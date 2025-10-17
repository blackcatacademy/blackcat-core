<?php

declare(strict_types=1);

namespace BlackCat\Core\Session;

use Psr\SimpleCache\CacheInterface;
use BlackCat\Core\Cache\LockingCacheInterface;
use BlackCat\Core\Database;
use BlackCat\Core\Security\Crypto;
use BlackCat\Core\Security\KeyManager;
use BlackCat\Core\Log\Logger;

/**
 * DbCachedSessionHandler
 *
 * A simple SessionHandlerInterface implementation that stores PHP session
 * payloads encrypted in a database table and uses a PSR-16 FileCache (or any
 * PSR-16 cache) as a local accelerator. The cache stores the encrypted blob
 * (not plaintext) so a leaked cache directory is not sufficient to read
 * session contents without crypto keys.
 *
 * IMPORTANT: this handler expects a small session table with the following
 * minimal schema. You can adjust $tableName when constructing if you prefer
 * another table.
 *
 * Rationale: we keep DB as source-of-truth and cache as temporary accelerator.
 * On read: try cache -> DB -> decrypt -> return raw session string.
 * On write: encrypt -> DB (upsert) -> update cache (write-through). Locking is
 * used when available to reduce cache stampede / races.
 */
final class DbCachedSessionHandler implements \SessionHandlerInterface
{
    private \PDO|Database $db;
    private ?CacheInterface $cache;
    private string $tableName;
    private int $cacheTtlSeconds;
    private int $lockTtlSeconds = 5; // when using LockingCacheInterface
    private const TOKEN_BYTES = 32; // raw cookie bytes used by SessionManager
    private const COOKIE_NAME = 'session_token';

    /** @param \PDO|Database $db PDO or your Database wrapper */
    public function __construct($db, ?CacheInterface $cache = null, string $tableName = 'sessions', int $cacheTtlSeconds = 120)
    {
        if (!($db instanceof \PDO) && !($db instanceof Database)) {
            throw new \InvalidArgumentException('DbCachedSessionHandler expects PDO or Database');
        }
        // Validate table name before assignment (only safe characters, reasonable length)
        if (!preg_match('/^[a-zA-Z0-9_]{1,64}$/', $tableName)) {
            throw new \InvalidArgumentException('Invalid table name provided');
        }

        $this->db = $db;
        $this->cache = $cache;
        $this->tableName = $tableName;
        $this->cacheTtlSeconds = max(0, (int)$cacheTtlSeconds);

        // crypto safety check: we won't require it at construct time but will
        // initialize when needed.
    }

    private function computeCacheTtlFromExpires(?string $expiresAt): ?int
    {
        if ($this->cacheTtlSeconds <= 0) return null;
        if (empty($expiresAt)) return $this->cacheTtlSeconds;
        try {
            $exp = new \DateTimeImmutable($expiresAt, new \DateTimeZone('UTC'));
            $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
            $secs = $exp->getTimestamp() - $now->getTimestamp();
            if ($secs <= 0) return 0;
            return min($this->cacheTtlSeconds, $secs);
        } catch (\Throwable $_) {
            return $this->cacheTtlSeconds;
        }
    }

    /** open() - nothing special to do */
    public function open(string $savePath, string $sessionName): bool
    {
        return true;
    }

    /** close() - nothing special */
    public function close(): bool
    {
        return true;
    }

    /**
     * Read session data for given session id.
     * Returns the serialized session string (may be empty string if not found).
     */
    public function read(string $sessionId): string
    {
        // resolve token_hash when possible (compatible with SessionManager)
        $tokenHash = $this->resolveTokenHashFromSessionId($sessionId);
        $cacheKey = $this->cacheKey($sessionId);

        // 1) Try cache first (contains encrypted blob) - safe checks for meta (revoked/expiry) and controlled decrypt
        if ($this->cache !== null) {
            try {
                $cached = $this->cache->get($cacheKey);
                if (is_array($cached) && array_key_exists('blob', $cached) && is_string($cached['blob'])) {
                    $blob = $cached['blob'];
                    $meta = is_array($cached['meta']) ? $cached['meta'] : [];
                    $kv = $meta['key_version'] ?? null;
                    $revoked = $meta['revoked'] ?? 0;
                    $expiresAt = $meta['expires_at'] ?? null;
                    
                    // ensure $dec always exists to avoid undefined variable notices
                    $dec = null;
                    // skip revoked
                    if (!empty($revoked)) {
                        // treat as cache miss — fallthrough to DB
                    } else {
                        // check expiry if provided
                        $shouldAttempt = true;
                        if ($expiresAt !== null) {
                            try {
                                $exp = new \DateTimeImmutable($expiresAt, new \DateTimeZone('UTC'));
                                if ($exp < new \DateTimeImmutable('now', new \DateTimeZone('UTC'))) {
                                    $shouldAttempt = false; // expired -> skip cache
                                }
                            } catch (\Throwable $_) {
                                // can't parse expiry -> still attempt decrypt (best-effort)
                                $shouldAttempt = true;
                            }
                        }

                        if ($shouldAttempt) {
                            $dec = $this->decryptBlobSafe($blob, $sessionId, $kv);
                            if (is_array($dec) && isset($dec['plain']) && is_string($dec['plain'])) {
                                // convert JSON->PHP session-serialized if needed
                                return $this->convertPlainToSessionPayload($dec['plain']);
                            }
                            // decrypt failed -> fallthrough to DB
                        }
                    }
                }
            } catch (\Throwable $e) {
                $this->log('warning', 'cache get failed in session read', $e, $this->makeLogCtx($sessionId, ['cacheKey' => $cacheKey]));
            }
        }

        // 2) Load from DB
        try {
            $keyVersion = null; // will be filled if DB row contains token_hash_key
            if ($tokenHash !== null) {
                // sessions table with token_hash (binary)
                $sql = "SELECT session_blob, expires_at, revoked, token_hash_key FROM {$this->tableName} WHERE token_hash = :token_hash LIMIT 1";
                if ($this->db instanceof Database) {
                    $row = $this->db->fetch($sql, [':token_hash' => $tokenHash]);
                    $keyVersion = $row['token_hash_key'] ?? null;
                } else {
                    $stmt = $this->pdoPrepare($sql);
                    // bind as binary if possible
                    $stmt->bindValue(':token_hash', $tokenHash, \PDO::PARAM_LOB);
                    $stmt->execute();
                    $row = $stmt->fetch(\PDO::FETCH_ASSOC) ?: null;
                    $keyVersion = $row['token_hash_key'] ?? null;
                }
            }

            if (empty($row)) return '';
            if (!empty($row['revoked'])) return '';
            if (!empty($row['expires_at'])) {
                try {
                    $exp = new \DateTimeImmutable($row['expires_at'], new \DateTimeZone('UTC'));
                    if ($exp < new \DateTimeImmutable('now', new \DateTimeZone('UTC'))) {
                        return '';
                    }
                } catch (\Throwable $_) {
                    // ignore parse error
                }
            }

            $blob = $row['session_blob'] ?? null;
            // normalize LOB that some PDO drivers return as stream
            if (is_resource($blob) && get_resource_type($blob) === 'stream') {
                $blob = stream_get_contents($blob);
            }
            if ($blob === '' || $blob === null) return '';

            // store to cache (best-effort) the encrypted blob so next read is faster
            if ($this->cache !== null) {
                try {
                    $cacheKey = $this->cacheKey($sessionId);
                    $meta = [
                        'expires_at' => $row['expires_at'] ?? null,
                        'revoked' => (int)($row['revoked'] ?? 0),
                        'key_version' => $keyVersion ?? null, // <- include DB key version if present
                    ];
                    if ($this->cache instanceof LockingCacheInterface) {
                        $lockName = 'session_blob_lock_' . hash('sha256', $sessionId);
                        $token = null;
                        try {
                            $token = $this->cache->acquireLock($lockName, $this->lockTtlSeconds);
                            $ttl = $this->computeCacheTtlFromExpires($row['expires_at'] ?? null);
                            if ($ttl !== 0) {
                                $this->cache->set($cacheKey, ['blob' => $blob, 'meta' => $meta], $ttl);
                            }
                        } finally {
                            if ($token !== null) {
                                try { $this->cache->releaseLock($lockName, $token); } catch (\Throwable $_) {}
                            }
                        }
                    } else {
                        $ttl = $this->computeCacheTtlFromExpires($row['expires_at'] ?? null);
                        if ($ttl !== 0) {
                            $this->cache->set($cacheKey, ['blob' => $blob, 'meta' => $meta], $ttl);
                        }
                    }
                } catch (\Throwable $e) {
                    $this->log('warning', 'cache set failed in session read', $e, $this->makeLogCtx($sessionId, ['cacheKey' => $cacheKey]));
                }
            }

            // pass DB key version to decrypt so we prefer correct key
            $dec = $this->decryptBlobSafe($blob, $sessionId, $keyVersion);
            if (!is_array($dec) || !isset($dec['plain']) || !is_string($dec['plain'])) {
                return '';
            }
            // convert JSON->PHP session-serialized if needed
            return $this->convertPlainToSessionPayload($dec['plain']);
        } catch (\Throwable $e) {
            $this->log('error', 'db error reading session', $e, $this->makeLogCtx($sessionId));
            return '';
        }
    }

    /**
     * Write session payload (serialized string) for given session id.
     * We encrypt payload before storing.
     */
    public function write(string $sessionId, string $data): bool
    {
        try {
            $this->ensureCryptoInitialized();

            // If $data already looks like JSON and decodes to array -> keep it
            $plaintext = null;
            if (is_string($data)) {
                $maybe = @json_decode($data, true);
                if (is_array($maybe)) {
                    // already JSON-format session (e.g. created by SessionManager)
                    $plaintext = $data;
                }
            }

            // If not JSON, try to parse PHP session-serialized string into array
            if ($plaintext === null) {
                $parsed = $this->parsePhpSessionStringToArray($data);
                if ($parsed === null) {
                    // fallback: treat raw $data as opaque string (keep as-is)
                    $plaintext = (string)$data;
                } else {
                    $clean = $this->sanitizeSessionForStorage($parsed);
                    $json = json_encode($clean, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
                    if ($json === false) {
                        throw new \RuntimeException('Failed to JSON encode session for storage');
                    }
                    $plaintext = $json;
                }
            }

            // Now encrypt the plaintext JSON (or raw fallback)
            $blob = Crypto::encrypt($plaintext, 'binary');
            if (!is_string($blob) || $blob === '') {
                throw new \RuntimeException('encrypt produced empty blob');
            }
        } catch (\Throwable $e) {
            $this->log('error', 'failed to encrypt session blob', $e, $this->makeLogCtx($sessionId));
            return false;
        }

        $lifetime = (int)ini_get('session.gc_maxlifetime');
        $expires = $lifetime > 0 ? (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))
            ->modify("+{$lifetime} seconds")->format('Y-m-d H:i:s.u') : null;
        $now = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s.u');

        try {
            $tokenHash = $this->resolveTokenHashFromSessionId($sessionId);

            // Determine token key version WITHOUT getCurrentKeyVersion() (doesn't exist).
            $tokenKeyVersion = null;
            try {
                $keysDir = self::getKeysDir();

                // 1) If sessionId is base64url raw token -> derive candidates and prefer matching token_hash
                $rawFromSessionId = $this->base64url_decode($sessionId);
                if (is_string($rawFromSessionId) && strlen($rawFromSessionId) === self::TOKEN_BYTES) {
                    $candidates = KeyManager::deriveHmacCandidates('SESSION_KEY', $keysDir, 'session_key', $rawFromSessionId);
                    if (!empty($candidates) && is_array($candidates)) {
                        // prefer candidate that matches resolved tokenHash (if we resolved it)
                        if ($tokenHash !== null) {
                            foreach ($candidates as $c) {
                                if (!empty($c['hash']) && $c['hash'] === $tokenHash && !empty($c['version'])) {
                                    $tokenKeyVersion = $c['version'];
                                    break;
                                }
                            }
                        }
                        // otherwise pick the first candidate's version (newest) as best-effort
                        if ($tokenKeyVersion === null && !empty($candidates[0]['version'])) {
                            $tokenKeyVersion = $candidates[0]['version'];
                        }
                    }
                } else {
                    // 2) Fallback: if cookie is present, try to derive latest from cookie raw token
                    $cookieVal = $_COOKIE[self::COOKIE_NAME] ?? null;
                    $rawFromCookie = is_string($cookieVal) ? $this->base64url_decode($cookieVal) : null;
                    if (is_string($rawFromCookie) && strlen($rawFromCookie) === self::TOKEN_BYTES) {
                        // deriveHmacWithLatest exists in your SessionManager usage path
                        $derived = KeyManager::deriveHmacWithLatest('SESSION_KEY', $keysDir, 'session_key', $rawFromCookie);
                        if (!empty($derived['version'])) {
                            $tokenKeyVersion = $derived['version'];
                        }
                    }
                }
            } catch (\Throwable $_) {
                // If KeyManager fails, leave $tokenKeyVersion as null (DB will accept NULL)
                $tokenKeyVersion = null;
            }

            if ($tokenHash !== null) {
                // write to sessions table with binary token_hash
                $sql = "INSERT INTO {$this->tableName} 
                    (token_hash, token_hash_key, token_fingerprint, token_issued_at, user_id, created_at, last_seen_at, expires_at, revoked, ip_hash, ip_hash_key, user_agent, session_blob)
                    VALUES (:token_hash, :token_hash_key, :token_fingerprint, :token_issued_at, :uid, :created, :last_seen_at, :expires_at, 0, :ip_hash, :ip_key, :user_agent, :blob)
                    ON DUPLICATE KEY UPDATE
                        session_blob = :blob_u,
                        last_seen_at = :last_seen_at_u,
                        expires_at = :expires_at_u,
                        token_hash_key = :token_hash_key_u,
                        revoked = 0";

                // před tím, než voláš DB zápis, připrav tokenFingerprint:
                $cookieVal = $_COOKIE[self::COOKIE_NAME] ?? null;
                $tokenFingerprintBin = is_string($cookieVal) ? hash('sha256', $cookieVal, true) : null;

                if ($this->db instanceof Database) {
                    $this->db->prepareAndRun($sql, [
                        ':token_hash' => $tokenHash,
                        ':token_hash_key' => $tokenKeyVersion,
                        ':token_fingerprint' => $tokenFingerprintBin,
                        ':token_issued_at' => $now,
                        ':uid' => null,
                        ':created' => $now,
                        ':last_seen_at' => $now,
                        ':expires_at' => $expires,
                        ':ip_hash' => null,
                        ':ip_key' => null,
                        ':user_agent' => $this->truncateUa($_SERVER['HTTP_USER_AGENT'] ?? null),
                        ':blob' => $blob,
                        ':blob_u' => $blob,
                        ':last_seen_at_u' => $now,
                        ':expires_at_u' => $expires,
                        ':token_hash_key_u' => $tokenKeyVersion,
                    ]);
                } else {
                    // PDO path
                    $stmt = $this->pdoPrepare($sql);
                    $stmt->bindValue(':token_hash', $tokenHash, \PDO::PARAM_LOB);
                    $stmt->bindValue(':token_hash_key', $tokenKeyVersion, \PDO::PARAM_STR);
                    if ($tokenFingerprintBin === null) {
                        $stmt->bindValue(':token_fingerprint', null, \PDO::PARAM_NULL);
                    } else {
                        $stmt->bindValue(':token_fingerprint', $tokenFingerprintBin, \PDO::PARAM_LOB);
                    }
                    $stmt->bindValue(':token_issued_at', $now, \PDO::PARAM_STR);
                    $stmt->bindValue(':uid', null, \PDO::PARAM_INT);
                    $stmt->bindValue(':created', $now, \PDO::PARAM_STR);
                    $stmt->bindValue(':last_seen_at', $now, \PDO::PARAM_STR);
                    $stmt->bindValue(':expires_at', $expires, \PDO::PARAM_STR);
                    $ipInfo = Logger::getHashedIp();
                    $stmt->bindValue(':ip_hash', $ipInfo['hash'], $ipInfo['hash'] === null ? \PDO::PARAM_NULL : \PDO::PARAM_LOB);
                    $stmt->bindValue(':ip_key', $ipInfo['key_id'], $ipInfo['key_id'] === null ? \PDO::PARAM_NULL : \PDO::PARAM_STR);
                    $ua = $this->truncateUa($_SERVER['HTTP_USER_AGENT'] ?? null);
                    $stmt->bindValue(':user_agent', $ua, \PDO::PARAM_STR);
                    $stmt->bindValue(':blob', $blob, \PDO::PARAM_LOB);
                    $stmt->bindValue(':blob_u', $blob, \PDO::PARAM_LOB);
                    $stmt->bindValue(':last_seen_at_u', $now, \PDO::PARAM_STR);
                    $stmt->bindValue(':expires_at_u', $expires, \PDO::PARAM_STR);
                    $stmt->bindValue(':token_hash_key_u', $tokenKeyVersion, \PDO::PARAM_STR);
                    $stmt->execute();
                }
            }

        } catch (\Throwable $e) {
            $this->log('error', 'db error writing session blob', $e, $this->makeLogCtx($sessionId));
            return false;
        }

        if ($this->cache !== null) {
            try {
                $cacheKey = $this->cacheKey($sessionId);
                $meta = ['expires_at' => $expires, 'revoked' => 0, 'key_version' => $tokenKeyVersion ?? null];
                $ttl = $this->computeCacheTtlFromExpires($expires);
                if ($ttl !== 0) {
                    $this->cache->set($cacheKey, ['blob' => $blob, 'meta' => $meta], $ttl);
                }
            } catch (\Throwable $e) {
                $this->log('warning', 'cache set failed in session write', $e, $this->makeLogCtx($sessionId));
            }
        }

        return true;
    }

    /** Destroy session row and remove cache entry */
    public function destroy(string $sessionId): bool
    {
        $tokenHash = $this->resolveTokenHashFromSessionId($sessionId);

        try {
            if ($tokenHash !== null) {
                // 1) try to read user_id and possibly token_fingerprint BEFORE deleting
                try {
                    $row = null;
                    $sqlSel = "SELECT user_id, token_fingerprint FROM {$this->tableName} WHERE token_hash = :token_hash LIMIT 1";
                    if ($this->db instanceof Database) {
                        $row = $this->db->fetch($sqlSel, [':token_hash' => $tokenHash]);
                    } else {
                        $stmtSel = $this->pdoPrepare($sqlSel);
                        $stmtSel->bindValue(':token_hash', $tokenHash, \PDO::PARAM_LOB);
                        $stmtSel->execute();
                        $row = $stmtSel->fetch(\PDO::FETCH_ASSOC) ?: null;
                    }
                    $foundUserId = !empty($row['user_id']) ? (int)$row['user_id'] : null;
                    $foundFpBin = $row['token_fingerprint'] ?? null;
                } catch (\Throwable $_) {
                    $foundUserId = null;
                    $foundFpBin = null;
                }
                // delete by token_hash in sessions table
                $sql = "DELETE FROM {$this->tableName} WHERE token_hash = :token_hash";
                if ($this->db instanceof Database) {
                    $this->db->prepareAndRun($sql, [':token_hash' => $tokenHash]);
                } else {
                    $stmt = $this->pdoPrepare($sql);
                    $stmt->bindValue(':token_hash', $tokenHash, \PDO::PARAM_LOB);
                    $stmt->execute();
                }
            }
        } catch (\Throwable $e) {
            $this->log('warning', 'db error destroying session', $e, $this->makeLogCtx($sessionId));
        }

        // delete cache entry (key resolves to session_blob_... when tokenHash present)
        if ($this->cache !== null) {
            try {
                $cacheKey = $this->cacheKey($sessionId);
                $this->cache->delete($cacheKey);
            } catch (\Throwable $e) {
                $this->log('warning', 'cache delete failed in session destroy', $e, $this->makeLogCtx($sessionId));
            }
        }

        // best-effort: delete CSRF cache store for user or guest
        try {
            if ($this->cache !== null) {
                // fingerprint: z cookie, jinak fallback na session_id()
                $cookieVal = $_COOKIE[self::COOKIE_NAME] ?? null;
                $fpBin = $foundFpBin ?? (is_string($cookieVal) ? hash('sha256', $cookieVal, true) : hash('sha256', session_id(), true));

                // user key: pokud přihlášený -> user_id, jinak 'anon'
                $userKey = (session_status() === PHP_SESSION_ACTIVE && isset($_SESSION['user_id'])) ? $_SESSION['user_id'] : 'anon';

                if ($fpBin !== null) {
                    $csrfKey = 'csrf_user_' . $userKey . '_' . bin2hex($fpBin);
                    try { $this->cache->delete($csrfKey); } catch (\Throwable $_) {}
                }
            }
        } catch (\Throwable $_) {
            // swallow
        }
        return true;
    }

    /** Garbage-collect expired sessions. */
    public function gc(int $maxlifetime): int
    {
        try {
            $cut = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->modify("-{$maxlifetime} seconds")->format('Y-m-d H:i:s.u');
            $sql = "DELETE FROM {$this->tableName} WHERE expires_at IS NOT NULL AND expires_at < :cut";
            if ($this->db instanceof Database) {
                $this->db->prepareAndRun($sql, [':cut' => $cut]);
            } else {
                $stmt = $this->pdoPrepare($sql);
                $stmt->bindValue(':cut', $cut, \PDO::PARAM_STR);
                $stmt->execute();
            }
            // we won't attempt to return exact number reliably; return 0 for compatibility
            return 0;
        } catch (\Throwable $e) {
            $this->log('warning', 'gc failed', $e, ['component'=>'DbCachedSessionHandler']);
            return 0;
        }
    }

    /* ------------------------- helpers ------------------------- */

    /**
     * Safe wrapper around unserialize() that converts PHP warnings/notices
     * into exceptions so they won't be emitted into logs. Returns the same
     * result as unserialize() or false on failure.
     */
    private function safeUnserialize(string $data)
    {
        // push a temporary error handler that throws ErrorException
        $prevHandler = set_error_handler(function ($severity, $message, $file = null, $line = null) {
            throw new \ErrorException($message, 0, $severity, $file, $line);
        });

        try {
            // allowed_classes => false for security
            $res = unserialize($data, ['allowed_classes' => false]);
        } catch (\Throwable $_) {
            $res = false;
        } finally {
            // restore previous handler (or default)
            if ($prevHandler !== null) {
                set_error_handler($prevHandler);
            } else {
                restore_error_handler();
            }
        }

        return $res;
    }
    
    /**
     * Convert an associative array (decoded JSON) to PHP session-serialized string.
     * Format: key1|<php-serialize(value1)>key2|<php-serialize(value2)>...
     *
     * Note: this implements the default "php" session.serialize_handler format.
     * Keys are sanitized to avoid accidental '|' characters which would break parsing.
     */
    private function arrayToPhpSessionString(array $arr): string
    {
        $out = '';
        foreach ($arr as $k => $v) {
            // Sanitize key: replace pipe (|) with underscore and ensure string
            $safeKey = str_replace('|', '_', (string)$k);

            // Optional: further sanitize to remove control chars (uncomment if needed)
            // $safeKey = preg_replace('/[\x00-\x1F\x7F]+/u', '_', $safeKey);

            // Use serialize() to preserve types (int/bool/array/null)
            $out .= $safeKey . '|' . serialize($v);
        }
        return $out;
    }

    /**
     * Convert plaintext decrypted blob into session payload expected by PHP session handler.
     * If $plain is JSON representing an array => convert to php serialized session string.
     * Otherwise return $plain unchanged (backwards compatible).
     */
    private function convertPlainToSessionPayload(string $plain): string
    {
        $handler = ini_get('session.serialize_handler') ?: 'php';
        if ($handler !== 'php' && $handler !== 'php_binary') {
            // loguj to pro debug, ale fallbackni na původní plain (bez konverze)
            $this->log('warning', 'unexpected session.serialize_handler: ' . $handler, null, ['component' => 'DbCachedSessionHandler']);
            return $plain;
        }

        $maybe = @json_decode($plain, true);
        if (is_array($maybe)) {
            return $this->arrayToPhpSessionString($maybe);
        }
        return $plain;
    }

    /**
     * Parse PHP session-serialized string (format "k1|<serialized>k2|<serialized>...") into array.
     * Returns array on success, or null if parsing failed.
     *
     * This is conservative: pokusí se rozpoznat jednotlivé páry jméno|serialized_value.
     * Implementace postupně zkouší malé kusy inputu pro unserialize() (robustní, i když ne ultra-performantní).
     */
    private function parsePhpSessionStringToArray(string $s): ?array
    {
        if ($s === '') return [];
        $len = strlen($s);

        // safety limits to avoid pathological inputs (1MB default)
        $maxBytes = 1 * 1024 * 1024; // 1MB
        if ($len > $maxBytes) {
            return null;
        }

        $offset = 0;
        $res = [];

        // iteration guard to avoid pathological CPU usage
        $maxIterations = 200000;
        $iters = 0;

        while ($offset < $len) {
            if (++$iters > $maxIterations) {
                return null;
            }

            $pipe = strpos($s, '|', $offset);
            if ($pipe === false) break;
            $name = substr($s, $offset, $pipe - $offset);
            $offset = $pipe + 1;
            if ($offset >= $len) {
                // nothing after pipe -> invalid
                return null;
            }

            $ok = false;
            // Try increasing substrings until unserialize works
            // (special-case for boolean false which unserialize returns false for 'b:0;')
            for ($i = 1; $offset + $i <= $len; $i++) {
                if (++$iters > $maxIterations) {
                    return null;
                }
                $chunk = substr($s, $offset, $i);
                $val = $this->safeUnserialize($chunk, ['allowed_classes' => false]);
                if ($val !== false || $chunk === 'b:0;') {
                    $res[$name] = $val;
                    $offset += $i;
                    $ok = true;
                    break;
                }
            }
            if (!$ok) {
                // couldn't parse value for this key
                return null;
            }
        }

        return $res;
    }

    /** sanitizeSessionForStorage - same behavior as SessionManager::sanitizeSessionForStorage */
    private function sanitizeSessionForStorage(array $sess): array
    {
        $clean = [];
        foreach ($sess as $k => $v) {
            // skip objects/resources
            if (is_object($v) || is_resource($v)) continue;
            if (is_array($v)) {
                $clean[$k] = $this->sanitizeSessionForStorage($v);
            } else {
                $clean[$k] = $v;
            }
        }
        return $clean;
    }

    private function truncateUa(?string $ua): ?string
    {
        if ($ua === null) {
            return null;
        }
        if (function_exists('mb_substr')) {
            return mb_substr($ua, 0, 512);
        }
        return substr($ua, 0, 512);
    }

    /** Create safe log context for session-related logs (no raw tokens) */
    private function makeLogCtx(string $sessionId, ?array $extra = null): array
    {
        $ctx = [
            'component' => 'DbCachedSessionHandler',
            // první 16 hex znaků SHA-256 = anonymní, korelovatelný identifikátor
            'session_id_hash' => substr(hash('sha256', (string)$sessionId), 0, 16),
        ];
        if (!empty($extra) && is_array($extra)) {
            $ctx = array_merge($ctx, $extra);
        }
        return $ctx;
    }

    /**
     * Try to convert given $sessionId (which may be PHP session id or our cookie)
     * into a binary token_hash (32 bytes) compatible with SessionManager.
     *
     * Returns binary token_hash string on success, or null if not resolvable.
     */
    private function resolveTokenHashFromSessionId(string $sessionId): ?string
    {
        static $memo = [];
        if (array_key_exists($sessionId, $memo)) {
            return $memo[$sessionId];
        }

        $result = null;

        // 1) if sessionId looks like base64url-encoded raw token (as SessionManager stores in cookie)
        $raw = $this->base64url_decode($sessionId);
        if (is_string($raw) && strlen($raw) === self::TOKEN_BYTES) {
            try {
                $keysDir = self::getKeysDir();
                $candidates = KeyManager::deriveHmacCandidates('SESSION_KEY', $keysDir, 'session_key', $raw);
                if (!empty($candidates) && is_array($candidates)) {
                    foreach ($candidates as $c) {
                        if (!empty($c['hash']) && is_string($c['hash']) && strlen($c['hash']) === 32) {
                            $result = $c['hash'];
                            break;
                        }
                    }
                }
            } catch (\Throwable $_) {
                // ignore — resolution failed
            }

            $memo[$sessionId] = $result;
            return $result;
        }

        // 2) maybe sessionId already is hex token hash (64 hex chars)
        if (ctype_xdigit($sessionId) && strlen($sessionId) === 64) {
            $bin = hex2bin($sessionId);
            if ($bin !== false && strlen($bin) === 32) {
                $memo[$sessionId] = $bin;
                return $bin;
            }
        }

        // not resolvable
        $memo[$sessionId] = null;
        return null;
    }

    /** same cache key format as SessionManager */
    private function cacheKeyForTokenHex(string $hex): string
    {
        return 'session_blob_' . $hex;
    }

    /* helpers used above */
    private static function getKeysDir(): ?string
    {
        return defined('KEYS_DIR') ? KEYS_DIR : ($_ENV['KEYS_DIR'] ?? null);
    }

    private function base64url_decode(string $b64u): ?string
    {
        $remainder = strlen($b64u) % 4;
        if ($remainder) {
            $b64u .= str_repeat('=', 4 - $remainder);
        }
        $decoded = base64_decode(strtr($b64u, '-_', '+/'), true);
        return $decoded === false ? null : $decoded;
    }

    private function cacheKey(string $sessionId): string
    {
        $tokenHash = $this->resolveTokenHashFromSessionId($sessionId);
        if ($tokenHash === null) {
            return 'session_blob_' . substr(hash('sha256', $sessionId), 0, 16);
        }
        return $this->cacheKeyForTokenHex(bin2hex($tokenHash));
    }

    private function ensureCryptoInitialized(): void
    {
        if (!class_exists(Crypto::class, true) || !class_exists(KeyManager::class, true)) {
            throw new \RuntimeException('Crypto/KeyManager required for session encryption');
        }
        try {
            Crypto::initFromKeyManager(self::getKeysDir());
        } catch (\Throwable $e) {
            throw new \RuntimeException('Crypto init failed: ' . $e->getMessage());
        }
    }

    /**
     * @return array{plain: string, key_version: ?string}|null
     */
    private function decryptBlobSafe($blob, string $rawTokenOrSessionId, ?string $keyVersion = null): ?array
    {
        try {
            $this->ensureCryptoInitialized();
            $keysDir = self::getKeysDir();

            // pokud máme raw token (cookie encoded) pokusíme se ho najít
            $raw = $this->base64url_decode($rawTokenOrSessionId);
            // pokud ne, necháme KeyManager pokusit se s tím, co má (někdy SessionManager volá s raw tokenem)
            $tokenForDerive = $raw !== null ? $raw : $rawTokenOrSessionId;

            $candidates = [];
            try {
                $candidates = KeyManager::deriveHmacCandidates('SESSION_KEY', $keysDir, 'session_key', $tokenForDerive);
                // safety: limit candidates tried
                if (!empty($candidates) && is_array($candidates)) {
                    $maxCandidates = 10;
                    if (count($candidates) > $maxCandidates) {
                        $candidates = array_slice($candidates, 0, $maxCandidates);
                    }
                }
            } catch (\Throwable $_) {
                $candidates = [];
            }

            if (!empty($candidates) && is_array($candidates)) {
                // pokud byla požadována konkrétní verze, zúžíme kandidáty pouze na tu verzi
                if ($keyVersion !== null) {
                    $candidates = array_filter($candidates, function($c) use ($keyVersion) {
                        return isset($c['version']) && $c['version'] === $keyVersion;
                    });
                    // pokud po filtrování nic nezbyde, povolíme fallback (zkusíme všechny kandidáty)
                    if (empty($candidates)) {
                        // necháme to prázdné -> následující smyčka nic neudělá a vrátí null
                    }
                }
            }

            foreach ($candidates as $c) {
                $candidateVersion = $c['version'] ?? null;
                $candidateHash = $c['hash'] ?? null;
                if ($candidateHash === null) continue;
                try {
                    $plain = Crypto::decrypt($blob, $candidateHash);
                    if ($plain !== null) {
                        return ['plain' => $plain, 'key_version' => $candidateVersion];
                    }
                } catch (\Throwable $_) {
                    continue;
                }
            }

            // Fallback: pokud nemáme kandidáty nebo nic nepadlo, zkusíme volat Crypto::decrypt bez explicitního candidate (některé implementace to podporují)
            try {
                $plain = Crypto::decrypt($blob);
                if ($plain !== null) {
                    // pokud jsme neměli konkrétní verzi, necháme key_version null
                    return ['plain' => $plain, 'key_version' => $keyVersion ?? null];
                }
            } catch (\Throwable $_) {
                // swallow
            }
            // pokud jsme sem došli, nepodařilo se dešifrovat — loguj pro debug rotace klíčů
            try {
                $this->log('info', 'decrypt candidates exhausted for session blob', null, [
                    'preferred_key_version' => $keyVersion ?? null,
                    'candidate_count' => is_array($candidates) ? count($candidates) : 0,
                    'component' => 'DbCachedSessionHandler'
                ]);
            } catch (\Throwable $_) {
                // swallow
            }
            return null;

        } catch (\Throwable $e) {
            $this->log('warning', 'decrypt failed for session blob', $e, ['component' => 'DbCachedSessionHandler']);
            return null;
        }
    }

    /**
     * Helper pro PDO prepare s chybovou kontrolou.
     * Vrací \PDOStatement nebo vyhodí \RuntimeException když prepare selže.
     * Používej $this->pdoPrepare(...) místo $this->db->prepare(...) v PDO větvích.
     */
    private function pdoPrepare(string $sql): \PDOStatement
    {
        try{if (!($this->db instanceof \PDO)) {
            throw new \RuntimeException('pdoPrepare called but $this->db is not a PDO instance');
        }

        $stmt = $this->db->prepare($sql);
        if ($stmt === false) {
            // Nebindujeme surový SQL do logu - pouze obecná chyba
            throw new \RuntimeException('PDO prepare failed');
        }
        return $stmt;
        } catch (\Throwable $e) {
    Logger::systemMessage('error', 'PDO prepare failed', null,  [
        'context' => 'pdoPrepare',
        'message' => $e->getMessage(),
        'file' => $e->getFile(),
        'line' => $e->getLine(),
        'trace' => $e->getTraceAsString()
    ]);
    throw $e;
}
    }

    private function log(string $level, string $msg, ?\Throwable $e = null, ?array $context = null): void
    {
        try {
            if ($e !== null && class_exists(Logger::class, true) && method_exists(Logger::class, 'systemError')) {
                try { Logger::systemError($e, null, null, $context ?? ['component' => 'DbCachedSessionHandler']); return; } catch (\Throwable $_) {}
            }
            if (class_exists(Logger::class, true) && method_exists(Logger::class, 'systemMessage')) {
                try { Logger::systemMessage($level, $msg, null, $context ?? ['component' => 'DbCachedSessionHandler']); return; } catch (\Throwable $_) {}
            }
            $ctxStr = '';
            if (!empty($context)) {
                $filtered = $context;
                if (isset($filtered['blob'])) $filtered['blob'] = '[redacted]';
                if (isset($filtered['session_blob'])) $filtered['session_blob'] = '[redacted]';
                $enc = @json_encode($filtered, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
                if ($enc !== false) {
                    $ctxStr = ' ' . $enc;
                }
            }
            $err = $e ? ' exception: ' . $e->getMessage() : '';
            error_log('[DbCachedSessionHandler]['.$level.'] '.$msg.$err.$ctxStr);
        } catch (\Throwable $_) {
            // swallow
        }
    }
}