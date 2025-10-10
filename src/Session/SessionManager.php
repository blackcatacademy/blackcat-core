<?php

declare(strict_types=1);

namespace BlackCat\Core\Session;

use BlackCat\Core\Database;
use BlackCat\Core\Security\KeyManager;
use BlackCat\Core\Security\Crypto;
use BlackCat\Core\Security\CSRF;
use BlackCat\Core\Log\Logger;

final class SessionManager
{
    private const TOKEN_BYTES = 32; // raw bytes
    private const COOKIE_NAME = 'session_token';
    private function __construct() {}

    /* -------------------------
     * Helpers
     * ------------------------- */

    private static function getKeysDir(): ?string
    {
        return defined('KEYS_DIR') ? KEYS_DIR : ($_ENV['KEYS_DIR'] ?? null);
    }

    private static function base64url_encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64url_decode(string $b64u): ?string
    {
        $remainder = strlen($b64u) % 4;
        if ($remainder) {
            $b64u .= str_repeat('=', 4 - $remainder);
        }
        $decoded = base64_decode(strtr($b64u, '-_', '+/'), true);
        return $decoded === false ? null : $decoded;
    }

    private static function truncateUserAgent(?string $ua): ?string
    {
        if ($ua === null) return null;

        // 1) odstraníme kontrolní znaky (včetně NUL, CR, LF, DEL)
        $ua = preg_replace('/[\x00-\x1F\x7F]+/u', '', $ua);

        // 2) nahradíme vícenásobné whitespace jednou mezerou a trim
        $ua = preg_replace('/\s+/u', ' ', $ua);
        $ua = trim($ua);

        // 3) ořežeme na max. 512 UTF-8 znaků (odpovídá VARCHAR(512))
        return mb_substr($ua, 0, 512, 'UTF-8');
    }

    private static function isHttps(): bool
    {
        $proto = strtolower($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '');
        return $proto === 'https' || (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off') || (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443);
    }

    /* -------------------------
     * DB helpers (reused)
     * ------------------------- */
    private static function executeDb($db, string $sql, array $params = []): void
    {
        if ($db instanceof Database) {
            $db->prepareAndRun($sql, $params);
            return;
        }
        if ($db instanceof \PDO) {
            $stmt = $db->prepare($sql);
            if ($stmt === false) throw new \RuntimeException('Failed to prepare statement');
            foreach ($params as $k => $v) {
                $name = (strpos((string)$k, ':') === 0) ? $k : ':' . $k;

                // NULL / INT / BOOL handling
                if ($v === null) {
                    $stmt->bindValue($name, null, \PDO::PARAM_NULL);
                    continue;
                }
                if (is_int($v)) {
                    $stmt->bindValue($name, $v, \PDO::PARAM_INT);
                    continue;
                }
                if (is_bool($v)) {
                    $stmt->bindValue($name, $v ? 1 : 0, \PDO::PARAM_INT);
                    continue;
                }

                // Strings and binary data
                if (is_string($v)) {
                    // explicit BLOB param names used in this class
                    if ($name === ':blob' || $name === ':session_blob') {
                        $stmt->bindValue($name, $v, \PDO::PARAM_LOB);
                        continue;
                    }

                    // binary token/hash fields (fixed 32 bytes) should be bound as LOB/BINARY
                    if (in_array($name, [':token_hash', ':ip_hash', ':token_fingerprint'], true) && strlen($v) === 32) {
                        $stmt->bindValue($name, $v, \PDO::PARAM_LOB);
                        continue;
                    }

                    // if contains a NUL, treat as binary
                    if (strpos($v, "\0") !== false) {
                        $stmt->bindValue($name, $v, \PDO::PARAM_LOB);
                        continue;
                    }

                    // default: regular string
                    $stmt->bindValue($name, $v, \PDO::PARAM_STR);
                    continue;
                }

                // fallback stringify
                $stmt->bindValue($name, (string)$v, \PDO::PARAM_STR);
            }
            $stmt->execute();
            return;
        }
        throw new \InvalidArgumentException('Unsupported $db provided to SessionManager (expected Database or PDO)');
    }

    private static function fetchOne($db, string $sql, array $params = []): ?array
    {
        if ($db instanceof Database) {
            return $db->fetch($sql, $params);
        }
        if ($db instanceof \PDO) {
            $stmt = $db->prepare($sql);
            if ($stmt === false) throw new \RuntimeException('Failed to prepare statement');
            foreach ($params as $k => $v) {
                $name = (strpos((string)$k, ':') === 0) ? $k : ':' . $k;
                if ($v === null) {
                    $stmt->bindValue($name, null, \PDO::PARAM_NULL);
                } elseif (is_int($v)) {
                    $stmt->bindValue($name, $v, \PDO::PARAM_INT);
                } elseif (is_bool($v)) {
                    $stmt->bindValue($name, $v ? 1 : 0, \PDO::PARAM_INT);
                } elseif (is_string($v)) {
                    if ($name === ':blob' || $name === ':session_blob') {
                        $stmt->bindValue($name, $v, \PDO::PARAM_LOB);
                    } elseif (in_array($name, [':token_hash', ':ip_hash', ':token_fingerprint'], true) && strlen($v) === 32) {
                        $stmt->bindValue($name, $v, \PDO::PARAM_LOB);
                    } elseif (strpos($v, "\0") !== false) {
                        $stmt->bindValue($name, $v, \PDO::PARAM_LOB);
                    } else {
                        $stmt->bindValue($name, $v, \PDO::PARAM_STR);
                    }
                } else {
                    $stmt->bindValue($name, (string)$v, \PDO::PARAM_STR);
                }
            }
            $stmt->execute();
            $row = $stmt->fetch(\PDO::FETCH_ASSOC);
            return $row === false ? null : $row;
        }
        throw new \InvalidArgumentException('Unsupported $db provided to SessionManager (expected Database or PDO)');
    }

    /* -------------------------
     * Crypto helpers (session payload encryption)
     * ------------------------- */

    private static function ensureCryptoInitialized(): void
    {
        if (!class_exists('Crypto') || !class_exists('KeyManager')) {
            throw new \RuntimeException('Crypto/KeyManager required for session encryption');
        }
        // idempotent: Crypto::initFromKeyManager will set internal key if not set
        try {
            Crypto::initFromKeyManager(self::getKeysDir());
        } catch (\Throwable $e) {
            throw new \RuntimeException('Crypto initialization failed: ' . $e->getMessage());
        }
    }

    /**
     * Persist current $_SESSION (except transient runtime-only things) encrypted into DB session_blob.
     * Uses Crypto::encrypt(..., 'binary') to create a versioned binary payload.
     */
    private static function persistSessionBlob($db, string $tokenHashBin): void
    {
        // gather session snapshot (exclude internal/ephemeral data if you want)
        $sess = $_SESSION ?? [];
        // ensure we don't accidentally store enormous resources or objects - keep scalars/arrays only
        $filtered = self::sanitizeSessionForStorage($sess);

        try {
            self::ensureCryptoInitialized();
            $plaintext = json_encode($filtered, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
            if ($plaintext === false) throw new \RuntimeException('Failed to JSON encode session');
            $blob = Crypto::encrypt($plaintext, 'binary');
            if (!is_string($blob) || $blob === '') {
                throw new \RuntimeException('Crypto produced empty blob');
            }

            $sql = 'UPDATE sessions SET session_blob = :blob WHERE token_hash = :token_hash';
            self::executeDb($db, $sql, [':blob' => $blob, ':token_hash' => $tokenHashBin]);
        } catch (\Throwable $e) {
            // log and fail silently (do not break app flow)
            if (class_exists('Logger')) {
                try { Logger::systemError($e, $_SESSION['user_id'] ?? null); } catch (\Throwable $_) {}
            }
        }
    }

    /**
     * Load encrypted session blob (binary) from $row (or DB if needed), decrypt, and populate $_SESSION.
     * Return true on success, false otherwise.
     */
    private static function loadSessionBlobAndPopulate($db, array $row, string $tokenHashBin): bool
    {
        // prefer blob from fetched $row when present
        $blob = $row['session_blob'] ?? null;

        // if not present in row, fetch it
        if ($blob === null) {
            try {
                $sql = 'SELECT session_blob FROM sessions WHERE token_hash = :token_hash LIMIT 1';
                $r = self::fetchOne($db, $sql, [':token_hash' => $tokenHashBin]);
                $blob = $r['session_blob'] ?? null;
            } catch (\Throwable $e) {
                if (class_exists('Logger')) { try { Logger::systemError($e, $_SESSION['user_id'] ?? null); } catch (\Throwable $_) {} }
                return false;
            }
        }

        if ($blob === null) {
            // nothing to restore -> leave $_SESSION as-is
            return true;
        }

        try {
            self::ensureCryptoInitialized();
            // Crypto::decrypt accepts both base64 compact and binary-versioned payloads
            $plain = Crypto::decrypt($blob);
            if ($plain === null) {
                // decryption failed -> treat session as invalid (security-first)
                return false;
            }

            $data = json_decode($plain, true);
            if (!is_array($data)) { return false; }

            // merge: ensure user_id from DB takes precedence
            $userIdFromDb = $row['user_id'] ?? null;
            $_SESSION = $data;
            if ($userIdFromDb !== null) $_SESSION['user_id'] = $userIdFromDb;
            return true;
        } catch (\Throwable $e) {
            if (class_exists('Logger')) { try { Logger::systemError($e, $_SESSION['user_id'] ?? null); } catch (\Throwable $_) {} }
            return false;
        }
    }

    /**
     * Basic sanitization of session array before storing:
     * - remove resources, objects (keep scalars and arrays)
     */
    private static function sanitizeSessionForStorage(array $sess): array
    {
        $clean = [];
        foreach ($sess as $k => $v) {
            // skip objects/resources
            if (is_object($v) || is_resource($v)) continue;
            if (is_array($v)) {
                $clean[$k] = self::sanitizeSessionForStorage($v);
            } else {
                $clean[$k] = $v;
            }
        }
        return $clean;
    }

    /* -------------------------
     * Session operations
     * ------------------------- */

    public static function createSession($db, int $userId, int $days = 30, bool $allowMultiple = true, string $samesite = 'Lax'): string
    {
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();
        session_regenerate_id(true);

        $rawToken = random_bytes(self::TOKEN_BYTES); // raw bytes
        $cookieToken = self::base64url_encode($rawToken); // safe for cookie
        $keysDir = self::getKeysDir();

        try {
            // derive HMAC using newest session key and obtain key version
            $derived = KeyManager::deriveHmacWithLatest('SESSION_KEY', $keysDir, 'session_key', $rawToken);
            $tokenHashBin = $derived['hash'];                // binary 32 bytes
            $tokenHashKeyVer = $derived['version'] ?? null;  // e.g. 'v2' or 'env'
            if (!is_string($tokenHashBin) || strlen($tokenHashBin) !== 32) {
                throw new \RuntimeException('Derived token hash invalid');
            }
        } catch (\Throwable $e) {
            if (class_exists('Logger')) { try { Logger::systemError($e, $userId); } catch (\Throwable $_) {} }
            throw new \RuntimeException('Unable to initialize session key.');
        }

        $nowUtc = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s.u');
        $expiresAt = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->modify("+{$days} days")->format('Y-m-d H:i:s.u');

        try {
            if (!$allowMultiple) {
                $sql = 'UPDATE sessions SET revoked = 1 WHERE user_id = :user_id';
                self::executeDb($db, $sql, [':user_id' => $userId]);
            }

            $ipRaw = $_SERVER['REMOTE_ADDR'] ?? null;
            $ua = $_SERVER['HTTP_USER_AGENT'] ?? null;

            $ipHashBin = null;
            $ipHashKey = null;
            if (class_exists('Logger')) {
                try {
                    $ipRes = Logger::getHashedIp($ipRaw);
                    $ipHashBin = $ipRes['hash'] ?? null;
                    $ipHashKey = $ipRes['key_id'] ?? null;
                } catch (\Throwable $_) {
                    $ipHashBin = null;
                }
            }

            // Insert - session_blob will be null initially; we'll persist after cookie + $_SESSION set
            $sql = 'INSERT INTO sessions (token_hash, token_hash_key, token_fingerprint, token_issued_at, user_id, created_at, last_seen_at, expires_at, ip_hash, ip_hash_key, user_agent, revoked, session_blob)
                    VALUES (:token_hash, :token_hash_key, :token_fingerprint, :token_issued_at, :user_id, :created_at, :last_seen_at, :expires_at, :ip_hash, :ip_hash_key, :user_agent, 0, NULL)';
            $params = [
                ':token_hash'   => $tokenHashBin,
                ':token_hash_key' => $tokenHashKeyVer,
                ':token_fingerprint' => hash('sha256', $cookieToken, true),
                ':token_issued_at'   => $nowUtc,
                ':user_id'      => $userId,
                ':created_at'   => $nowUtc,
                ':last_seen_at' => $nowUtc,
                ':expires_at'   => $expiresAt,
                ':ip_hash'      => $ipHashBin,
                ':ip_hash_key'  => $ipHashKey,
                ':user_agent'   => self::truncateUserAgent($ua),
            ];

            self::executeDb($db, $sql, $params);

            if (class_exists('Logger')) {
                try {
                    $meta = ['source' => 'SessionManager::createSession', '_token_hash_key' => $tokenHashKeyVer];
                    $meta['_token_hash_hex'] = bin2hex($tokenHashBin);
                    $meta['session_token_key_version'] = $tokenHashKeyVer;
                    $meta['csrf_key_version'] = CSRF::getKeyVersion() ?? null;
                    $storedUa = self::truncateUserAgent($ua);
                    Logger::session('session_created', $userId, $meta, $ipRaw, $storedUa, null, $tokenHashBin);
                } catch (\Throwable $_) {}
            }
        } catch (\Throwable $e) {
            if (class_exists('Logger')) { try { Logger::systemError($e, $userId); } catch (\Throwable $_) {} }
            throw new \RuntimeException('Unable to persist session.');
        }

        // set cookie AFTER DB write
        $cookieOpts = [
            'expires' => time() + $days * 86400,
            'path' => '/',
            'secure' => self::isHttps(),
            'httponly' => true,
            'samesite' => $samesite,
        ];
        $cookieDomain = $_ENV['SESSION_DOMAIN'] ?? ($_SERVER['HTTP_HOST'] ?? null);
        if (!empty($cookieDomain)) $cookieOpts['domain'] = $cookieDomain;

        if (PHP_VERSION_ID >= 70300) {
            setcookie(self::COOKIE_NAME, $cookieToken, $cookieOpts);
        } else {
            setcookie(
                self::COOKIE_NAME,
                $cookieToken,
                $cookieOpts['expires'],
                $cookieOpts['path'],
                $cookieDomain ?? '',
                $cookieOpts['secure'],
                $cookieOpts['httponly']
            );
        }

        // set user_id in session and persist encrypted session blob
        $_SESSION['user_id'] = $userId;
        try {
            self::persistSessionBlob($db, $tokenHashBin);
        } catch (\Throwable $_) {}

        return $cookieToken;
    }

    public static function validateSession($db): ?int
    {
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();

        $cookie = $_COOKIE[self::COOKIE_NAME] ?? null;
        if (!$cookie || !is_string($cookie)) return null;

        $rawToken = self::base64url_decode($cookie);
        if ($rawToken === null || strlen($rawToken) !== self::TOKEN_BYTES) return null;

        // per-request cache (vyřeší opakované volání v rámci jednoho requestu)
        static $validateCache = [];
        $cacheKey = bin2hex($rawToken);
        if (array_key_exists($cacheKey, $validateCache)) {
            return $validateCache[$cacheKey]; // může být int userId nebo null
        }

        $keysDir = self::getKeysDir();

        // nastavení: limit kandidátů (newest->oldest) — uprav dle potřeby
        $maxCandidates = 10;

        // 1) derive candidates (ordered newest -> oldest)
        try {
            $candidates = KeyManager::deriveHmacCandidates('SESSION_KEY', $keysDir, 'session_key', $rawToken);
            if (empty($candidates)) {
                $validateCache[$cacheKey] = null;
                return null;
            }
            // oříznout na maxCandidates (nejnovější první)
            if (count($candidates) > $maxCandidates) {
                $candidates = array_slice($candidates, 0, $maxCandidates);
            }
        } catch (\Throwable $e) {
            if (class_exists('Logger')) { try { Logger::systemError($e); } catch (\Throwable $_) {} }
            $validateCache[$cacheKey] = null;
            return null;
        }

        // připravíme seznam hashů pro jediný SELECT
        $hashes = [];
        foreach ($candidates as $c) {
            if (!empty($c['hash'])) $hashes[] = $c['hash'];
        }
        if (empty($hashes)) {
            $validateCache[$cacheKey] = null;
            return null;
        }

        // vytvoříme placeholdery a parametry (PDO)
        $placeholders = [];
        $params = [];
        foreach ($hashes as $i => $h) {
            $ph = ":h{$i}";
            $placeholders[] = $ph;
            $params[$ph] = $h;
        }

        // 2) Načteme všechny odpovídající řádky jedním dotazem
        try {
            $sql = 'SELECT id, token_hash, user_id, ip_hash, ip_hash_key, user_agent, expires_at, revoked, session_blob, failed_decrypt_count
                    FROM sessions
                    WHERE token_hash IN (' . implode(',', $placeholders) . ')';
            $stmt = $db->prepare($sql);
            foreach ($params as $ph => $val) {
                // binární data (PDO driver může vyžadovat PARAM_STR u některých driverů)
                $stmt->bindValue($ph, $val, \PDO::PARAM_LOB);
            }
            $stmt->execute();
            $rows = $stmt->fetchAll(\PDO::FETCH_ASSOC);
        } catch (\Throwable $e) {
            if (class_exists('Logger')) { try { Logger::systemError($e); } catch (\Throwable $_) {} }
            $validateCache[$cacheKey] = null;
            return null;
        }

        // mapujeme výsledky podle hex(token_hash) pro rychlé vyhledání
        $rowsMap = [];
        foreach ($rows as $r) {
            if (!isset($r['token_hash'])) continue;
            $rowsMap[bin2hex($r['token_hash'])] = $r;
        }

        $validRow = null;
        $usedCandidate = null;
        $usedCandidateVersion = null;

        // práh pro revokaci po opakovaných chybách
        $failThreshold = 3;

        foreach ($candidates as $c) {
            $candidate = $c['hash'];
            $candidateVersion = $c['version'] ?? null;
            $candidateHex = bin2hex($candidate);

            if (!isset($rowsMap[$candidateHex])) {
                // není v DB — pokračovat
                continue;
            }

            $row = $rowsMap[$candidateHex];

            if ((int)($row['revoked'] ?? 0) === 1) {
                continue;
            }

            // pokus o dešifrování / naplnění session
            $decryptedOk = false;
            try {
                $decryptedOk = self::loadSessionBlobAndPopulate($db, $row, $candidate, $candidateVersion);
            } catch (\Throwable $e) {
                if (class_exists('Logger')) { try { Logger::systemError($e); } catch (\Throwable $_) {} }
                $decryptedOk = false;
            }

            if ($decryptedOk === false) {
                // Bezpečná transakční inkrementace + audit + případná revokace
                try {
                    $db->beginTransaction();

                    // 1) zamknout řádek pro update
                    $sqlSel = 'SELECT id, failed_decrypt_count FROM sessions WHERE token_hash = :token_hash FOR UPDATE';
                    $stmtSel = $db->prepare($sqlSel);
                    $stmtSel->bindValue(':token_hash', $candidate, \PDO::PARAM_LOB);
                    $stmtSel->execute();
                    $sel = $stmtSel->fetch(\PDO::FETCH_ASSOC);

                    $sessionId = $sel['id'] ?? null;
                    $cnt = isset($sel['failed_decrypt_count']) ? (int)$sel['failed_decrypt_count'] : 0;
                    $cnt++;

                    // 2) aktualizovat counter + last_failed_decrypt_at
                    $nowUtc = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s.u');
                    $sqlUpd = 'UPDATE sessions
                            SET failed_decrypt_count = :cnt,
                                last_failed_decrypt_at = :now
                            WHERE token_hash = :token_hash';
                    $stmtUpd = $db->prepare($sqlUpd);
                    $stmtUpd->bindValue(':cnt', $cnt, \PDO::PARAM_INT);
                    $stmtUpd->bindValue(':now', $nowUtc);
                    $stmtUpd->bindValue(':token_hash', $candidate, \PDO::PARAM_LOB);
                    $stmtUpd->execute();

                    // připravíme hodnoty pro audit (dbIpHash definujeme z $row)
                    $dbIpHash = $row['ip_hash'] ?? null;
                    $ipHashKey = $row['ip_hash_key'] ?? null;
                    $uaForAudit = $row['user_agent'] ?? null;

                    // 3) audit záznam (použijeme stejné sloupce jako schema)
                    try {
                        $sqlAudit = 'INSERT INTO session_audit (
                                        session_token, session_token_key_version, csrf_key_version, session_id,
                                        event, user_id, ip_hash, ip_hash_key, ua, meta_json, outcome, created_at
                                    ) VALUES (
                                        :session_token, :session_token_key_version, :csrf_key_version, :session_id,
                                        :event, :user_id, :ip_hash, :ip_hash_key, :ua, :meta, :outcome, :created_at
                                    )';
                        $stmtAudit = $db->prepare($sqlAudit);
                        $stmtAudit->bindValue(':session_token', $candidate, \PDO::PARAM_LOB);
                        $stmtAudit->bindValue(':session_token_key_version', $candidateVersion);
                        $stmtAudit->bindValue(':csrf_key_version', null);
                        $stmtAudit->bindValue(':session_id', $sessionId, \PDO::PARAM_INT);
                        $stmtAudit->bindValue(':event', 'decrypt_failed', \PDO::PARAM_STR);
                        $stmtAudit->bindValue(':user_id', $row['user_id'] ?? null, \PDO::PARAM_INT);
                        $stmtAudit->bindValue(':ip_hash', $dbIpHash, \PDO::PARAM_LOB);
                        $stmtAudit->bindValue(':ip_hash_key', $ipHashKey, \PDO::PARAM_STR);
                        $stmtAudit->bindValue(':ua', $uaForAudit, \PDO::PARAM_STR);
                        $stmtAudit->bindValue(':meta', json_encode(['candidate_version' => $candidateVersion]), \PDO::PARAM_STR);
                        $stmtAudit->bindValue(':outcome', null, \PDO::PARAM_NULL);
                        $stmtAudit->bindValue(':created_at', $nowUtc);
                        $stmtAudit->execute();
                    } catch (\Throwable $_) {
                        // audit není kritický — ignorujeme chybu v auditu
                    }

                    // 4) pokud přesáhnut práh, revokuj a zapiš audit revokace (stejný sloupcový rozvrh)
                    if ($cnt >= $failThreshold) {
                        // 1) označit session jako revoked
                        $sqlRev = 'UPDATE sessions SET revoked = 1 WHERE token_hash = :token_hash';
                        $stmtRev = $db->prepare($sqlRev);
                        $stmtRev->bindValue(':token_hash', $candidate, \PDO::PARAM_STR); // oprava zde
                        $stmtRev->execute();

                        // 2) zapsat audit
                        $stmtAudit = $db->prepare($sqlAudit);
                        $stmtAudit->bindValue(':session_token', $candidate, \PDO::PARAM_STR);
                        $stmtAudit->bindValue(':session_token_key_version', $candidateVersion);
                        $stmtAudit->bindValue(':csrf_key_version', null);
                        $stmtAudit->bindValue(':session_id', $sessionId, \PDO::PARAM_INT);
                        $stmtAudit->bindValue(':event', 'revoked', \PDO::PARAM_STR);
                        $stmtAudit->bindValue(':user_id', $row['user_id'] ?? null, \PDO::PARAM_INT);
                        $stmtAudit->bindValue(':ip_hash', $dbIpHash, \PDO::PARAM_STR);
                        $stmtAudit->bindValue(':ip_hash_key', $ipHashKey, \PDO::PARAM_STR);
                        $stmtAudit->bindValue(':ua', $uaForAudit, \PDO::PARAM_STR);
                        $stmtAudit->bindValue(':meta', json_encode([
                            'reason' => 'failed_decrypt_threshold',
                            'fail_count' => $cnt
                        ]), \PDO::PARAM_STR);
                        $stmtAudit->bindValue(':outcome', null, \PDO::PARAM_NULL);
                        $stmtAudit->bindValue(':created_at', $nowUtc);
                        $stmtAudit->execute();

                        if (class_exists('Logger')) {
                            Logger::systemMessage(
                                'warning',
                                'Session revoked after repeated decrypt failures',
                                null,
                                ['candidate_version' => $candidateVersion, 'fail_count' => $cnt]
                            );
                        }
                    }

                    $db->commit(); // commit až po všem
                } catch (\Throwable $e) {
                    try { $db->rollBack(); } catch (\Throwable $_) {}
                    if (class_exists('Logger')) { try { Logger::systemError($e); } catch (\Throwable $_) {} }
                }
                // pokračuj na dalšího kandidáta
                continue;
            }

            // IP check (explicitní verze z DB -> fallback na derive candidates)
            $ipRaw = $_SERVER['REMOTE_ADDR'] ?? null;
            $ipMismatch = true;
            if ($ipRaw !== null && isset($row['ip_hash']) && $row['ip_hash'] !== null) {
                try {
                    $dbIpHash = $row['ip_hash'];
                    $ipHashKeyVersion = $row['ip_hash_key'] ?? null;

                    if (!empty($ipHashKeyVersion)) {
                        try {
                            $info = KeyManager::getRawKeyBytesByVersion('IP_HASH_KEY', $keysDir, 'ip_hash_key', $ipHashKeyVersion);
                            $key = $info['raw'];
                            $calc = hash_hmac('sha256', $ipRaw, $key, true);
                            if (is_string($dbIpHash) && is_string($calc) && hash_equals($dbIpHash, $calc)) {
                                $ipMismatch = false;
                            } else {
                                $ipMismatch = true;
                            }
                            try { KeyManager::memzero($key); } catch (\Throwable $_) {}
                        } catch (\Throwable $_) {
                            $ipHashKeyVersion = null;
                        }
                    }

                    if ($ipHashKeyVersion === null) {
                        try {
                            $ipCandidates = KeyManager::deriveHmacCandidates('IP_HASH_KEY', $keysDir, 'ip_hash_key', $ipRaw);
                            $matched = false;
                            foreach ($ipCandidates as $ipc) {
                                $iph = $ipc['hash'] ?? null;
                                if ($iph !== null && is_string($dbIpHash) && is_string($iph) && hash_equals($dbIpHash, $iph)) {
                                    $matched = true;
                                    break;
                                }
                            }
                            $ipMismatch = $matched ? false : true;
                        } catch (\Throwable $_) {
                            $ipMismatch = true;
                        }
                    }
                } catch (\Throwable $e) {
                    if (class_exists('Logger')) { try { Logger::systemError($e); } catch (\Throwable $_) {} }
                    $ipMismatch = true;
                }
            } else {
                // pokud v DB není uložen ip_hash, považujeme to za match (podle vaší politiky)
                $ipMismatch = false;
            }

            if ($ipMismatch) {
                self::destroySession($db); // tady se provede revoke+audit centralizovaně
                return null;
            }

            // User-agent check
            $ua = $_SERVER['HTTP_USER_AGENT'] ?? null;
            $normalizedUa = self::truncateUserAgent($ua);
            if (($row['user_agent'] ?? null) !== null && $row['user_agent'] !== $normalizedUa) {
                if (class_exists('Logger')) {
                    try { Logger::systemMessage('warning', 'Candidate rejected: UA mismatch', null, ['candidate_version' => $candidateVersion]); } catch (\Throwable $_) {}
                }
                continue;
            }

            // vše OK -> použijeme tento kandidát
            $validRow = $row;
            $usedCandidate = $candidate;
            $usedCandidateVersion = $candidateVersion;
            break;
        }

        if ($validRow === null) {
            $validateCache[$cacheKey] = null;
            return null;
        }

        // expiration
        try {
            $expiresAt = new \DateTimeImmutable($validRow['expires_at'], new \DateTimeZone('UTC'));
            if ($expiresAt < new \DateTimeImmutable('now', new \DateTimeZone('UTC'))) {
                $validateCache[$cacheKey] = null;
                return null;
            }
        } catch (\Throwable $_) {
            if (class_exists('Logger')) {
                try { Logger::Error('[validateSession] Invalid expires_at value'); } catch (\Throwable $_) {}
            }
            $validateCache[$cacheKey] = null;
            return null;
        }

        $userId = (int)$validRow['user_id'];
        $_SESSION['user_id'] = $userId;

        // update last_seen + reset failed_decrypt_count po úspěchu
        try {
            $nowUtc = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s.u');
            $sql = 'UPDATE sessions
                    SET last_seen_at = :last_seen_at,
                        failed_decrypt_count = 0,
                        last_failed_decrypt_at = NULL
                    WHERE token_hash = :token_hash';
            $stmt = $db->prepare($sql);
            $stmt->bindValue(':last_seen_at', $nowUtc);
            $stmt->bindValue(':token_hash', $usedCandidate, \PDO::PARAM_LOB);
            $stmt->execute();

        } catch (\Throwable $e) {
            if (class_exists('Logger')) { try { Logger::systemError($e); } catch (\Throwable $_) {} }
        }

        // uložit do per-request cache a vrátit
        $validateCache[$cacheKey] = $userId;
        return $userId;
    }

    public static function destroySession($db): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();

        $cookie = $_COOKIE[self::COOKIE_NAME] ?? null;
        $userId = $_SESSION['user_id'] ?? null;

        if ($cookie && is_string($cookie)) {
            $rawToken = self::base64url_decode($cookie);
            if (is_string($rawToken) && strlen($rawToken) === self::TOKEN_BYTES) {
                $keysDir = self::getKeysDir();
                    try {
                        $candidates = KeyManager::deriveHmacCandidates('SESSION_KEY', $keysDir, 'session_key', $rawToken);
                        foreach ($candidates as $c) {
                            $candidate = $c['hash'];
                            try {
                                $sql = 'UPDATE sessions SET revoked = 1 WHERE token_hash = :token_hash';
                                self::executeDb($db, $sql, [':token_hash' => $candidate]);
                            } catch (\Throwable $e) {
                                if (class_exists('Logger')) { try { Logger::systemError($e, $userId); } catch (\Throwable $_) {} }
                            }
                        }
                    } catch (\Throwable $_) {
                        // ignore
                    }
            }
        }

        // ensure candidate exists for later logging
        $candidate = $candidate ?? null;

        // clear cookie securely (use same attributes/domain as createSession, with PHP <7.3 fallback)
        $cookieOpts = [
            'expires' => time() - 3600,
            'path'    => '/',
            'secure'  => self::isHttps(),
            'httponly'=> true,
            'samesite'=> 'Lax',
        ];
        $cookieDomain = $_ENV['SESSION_DOMAIN'] ?? ($_SERVER['HTTP_HOST'] ?? null);
        if (!empty($cookieDomain)) $cookieOpts['domain'] = $cookieDomain;

        if (PHP_VERSION_ID >= 70300) {
            setcookie(self::COOKIE_NAME, '', $cookieOpts);
        } else {
            setcookie(
                self::COOKIE_NAME,
                '',
                $cookieOpts['expires'],
                $cookieOpts['path'],
                $cookieDomain ?? '',
                $cookieOpts['secure'],
                $cookieOpts['httponly']
            );
        }

        // destroy PHP session
        $userId = $_SESSION['user_id'] ?? null;
        $_SESSION = [];
        @session_destroy();

        // Audit session destruction (pass token hash bin if available)
        if (class_exists('Logger')) {
            try {
                if (isset($candidate)) {
                    Logger::session('session_destroyed', $userId ?? null, null, null, null, null, $candidate);
                } else {
                    Logger::session('session_destroyed', $userId ?? null, null, null, null, null, null);
                }
            } catch (\Throwable $_) {}
        }
    }
}