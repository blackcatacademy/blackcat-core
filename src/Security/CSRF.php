<?php
declare(strict_types=1);

namespace BlackCat\Core\Security;

use Psr\Log\LoggerInterface;
use BlackCat\Core\Cache\LockingCacheInterface;
use Psr\SimpleCache\CacheInterface;
use BlackCat\Core\Security\Crypto;

final class CSRF
{
    private static ?LoggerInterface $logger = null;
    private const DEFAULT_TTL = 3600; // 1 hour
    private const DEFAULT_MAX_TOKENS = 16;

    /** @var array|null Reference to session array (nullable until init) */
    private static ?array $session = null;
    private static int $ttl = self::DEFAULT_TTL;
    private static int $maxTokens = self::DEFAULT_MAX_TOKENS;

    /**
     * @var CacheInterface|LockingCacheInterface|null
     * Optional PSR-16 cache (FileCache). LockingCacheInterface signals that
     * acquireLock/releaseLock methods exist (silences static analysis).
     */
    private static ?CacheInterface $cache = null;

    /**
     * Per-request in-memory caches to avoid multiple cache I/O in same request.
     * Structure: [ cacheKey => ['store' => array(id=>meta), 'dirty' => bool] ]
     */
    private static array $requestStores = [];

    public static function setLogger(?LoggerInterface $logger): void
    {
        self::$logger = $logger;
    }

    /**
     * Optionally inject a PSR-16 cache instance (FileCache).
     */
    public static function setCache(?CacheInterface $cache): void
    {
        self::$cache = $cache;
    }

    /**
     * Inject reference to session array for testability / explicit init.
     * If $sessionRef is null, will attempt to use global $_SESSION (requires session_start()).
     *
     * Call this AFTER session_start() in production bootstrap.
     *
     * NOTE: added optional $cache param for convenience.
     *
     * @param array|null $sessionRef  Reference to the session array (usually $_SESSION)
     */
    public static function init(?array &$sessionRef = null, ?int $ttl = null, ?int $maxTokens = null, ?CacheInterface $cache = null): void
    {
        if ($sessionRef === null) {
            if (session_status() !== PHP_SESSION_ACTIVE) {
                throw new \LogicException('Session not active — call bootstrap (session_start) first.');
            }
            $sessionRef = &$_SESSION;
        }

        // assign property as a reference to provided session array
        self::$session = &$sessionRef;

        if ($ttl !== null) {
            self::$ttl = $ttl;
        }
        if ($maxTokens !== null) {
            self::$maxTokens = $maxTokens;
        }

        // only attach provided cache if CSRF has no cache yet; do not override an existing cache instance
        if ($cache !== null) {
            if (self::$cache === null) {
                self::setCache($cache);
            } else {
                // do not silently override an already attached cache instance - log the mismatch for debug
                if (self::$logger) {
                    try {
                        self::$logger->warning('CSRF::init() called with a cache but CSRF already has a cache attached — ignoring new cache instance.');
                    } catch (\Throwable $_) {}
                }
            }
        }

        if (!isset(self::$session['csrf_tokens']) || !is_array(self::$session['csrf_tokens'])) {
            self::$session['csrf_tokens'] = [];
        }
    }

    public static function getKeyVersion(): ?string
    {
        try {
            $candidates = Crypto::hmac('probe', 'CSRF_KEY', 'csrf_key', null, true);
            if (!empty($candidates) && is_array($candidates[0]) && isset($candidates[0]['version'])) {
                return $candidates[0]['version'];
            }
        } catch (\Throwable $e) {
            if (self::$logger) {
                self::$logger->error('CSRF getKeyVersion failed', ['exception' => $e]);
            }
        }
        return null;
    }

    private static function ensureInitialized(): void
    {
        if (self::$session === null) {
            // attempt auto-init from real session if started
            if (session_status() === PHP_SESSION_ACTIVE) {
                $ref = &$_SESSION;
                self::init($ref);
                return;
            }
            throw new \LogicException('CSRF not initialized. Call CSRF::init() after session_start().');
        }
    }

    /**
     * Return a session-specific fingerprint (binary 32 bytes) used to bind cached token store to session.
     * This matches SessionManager's token_fingerprint (sha256 of cookie token).
     */
    private static function getSessionFingerprint(): ?string
    {
        $cookie = $_COOKIE['session_token'] ?? null;
        if (!is_string($cookie) || $cookie === '') return null;
        // use raw cookie string as SessionManager does when creating token_fingerprint
        $fp = hash('sha256', $cookie, true);
        return $fp === false ? null : $fp;
    }

    /**
     * Build cache key for user's token store. Namespaced with session fingerprint hex if present.
     */
    private static function buildCacheKeyForUser(int $userId, ?string $sessionFingerprintBin): string
    {
        // fingerprint already hex-safe when created via bin2hex
        $fpHex = $sessionFingerprintBin !== null ? bin2hex($sessionFingerprintBin) : 'nofp';

        // nový bezpečný formát: csrf_user_<userId>_<fpHex>
        $raw = 'csrf_user_' . $userId . '_' . $fpHex;

        // dodatečná sanitizace (pro jistotu) - povolit jen A-Z a 0-9 a _ a -
        $safe = preg_replace('/[^A-Za-z0-9_\-]/', '_', $raw);

        return $safe;
    }

    /**
     * Load token store for a given user (from per-request cache or PSR-16 cache).
     * Returns associative array id => ['v'=>val,'exp'=>int]
     *
     * Behavior:
     *  - Try primary key (with session fingerprint if present).
     *  - If primary is empty and fingerprint present, try fallback key without fingerprint and merge.
     */
    private static function loadTokenStoreForUser(int $userId): array
    {
        if (self::$cache === null) {
            // ensure requestStores entry exists so other code can rely on userId
            $fallbackKey = self::buildCacheKeyForUser($userId, null);
            if (!isset(self::$requestStores[$fallbackKey])) {
                self::$requestStores[$fallbackKey] = ['store' => [], 'dirty' => false, 'userId' => $userId];
            }
            return [];
        }

        $fp = self::getSessionFingerprint();
        $primaryKey = self::buildCacheKeyForUser($userId, $fp);

        if (isset(self::$requestStores[$primaryKey])) {
            return self::$requestStores[$primaryKey]['store'];
        }

        $store = [];
        try {
            $store = self::$cache->get($primaryKey, []);
            if (!is_array($store)) $store = [];
        } catch (\Throwable $e) {
            if (self::$logger) self::$logger->warning('CSRF cache get failed (primary)', ['exception' => $e, 'key' => $primaryKey]);
            $store = [];
        }

        // If fingerprint present and primary is empty, try fallback (no fingerprint)
        if (empty($store) && $fp !== null) {
            $fallbackKey = self::buildCacheKeyForUser($userId, null);
            try {
                $fallbackStore = self::$cache->get($fallbackKey, []);
                if (is_array($fallbackStore) && !empty($fallbackStore)) {
                    // merge fallback entries into store (do not mark dirty here)
                    $store = $fallbackStore + $store;
                }
            } catch (\Throwable $e) {
                if (self::$logger) self::$logger->warning('CSRF cache get failed (fallback)', ['exception' => $e, 'key' => $fallbackKey]);
            }
        }

        // ensure requestStores entry includes userId for later cleanup/save
        self::$requestStores[$primaryKey] = ['store' => $store, 'dirty' => false, 'userId' => $userId];
        return $store;
    }

    /**
     * Save token store(s) for a given user if marked dirty.
     * Iterates over all requestStores entries for this user (handles primary + fallback keys).
     */
    private static function saveTokenStoreForUserIfNeeded(int $userId): void
    {
        if (self::$cache === null) return;

        $now = time();

        // find all requestStores entries for this user
        foreach (self::$requestStores as $cacheKey => $entry) {
            if (!isset($entry['userId']) || (int)$entry['userId'] !== $userId) {
                continue;
            }
            if (empty($entry['dirty'])) {
                continue;
            }

            $store = $entry['store'] ?? [];

            // compute conservative TTL for this store: minimum token expiry (if any)
            $minTtl = null;
            foreach ($store as $m) {
                if (isset($m['exp'])) {
                    $secs = (int)$m['exp'] - $now;
                    if ($secs <= 0) continue;
                    if ($minTtl === null || $secs < $minTtl) $minTtl = $secs;
                }
            }
            $cacheTtl = $minTtl !== null ? max(1, $minTtl) : (self::$ttl + 60);

            $locked = false;
            $token = null;
            $lockKey = 'csrf_lock_' . $cacheKey;

            try {
                if (self::$cache instanceof LockingCacheInterface) {
                    $token = self::$cache->acquireLock($lockKey, 5);
                    $locked = ($token !== null);
                }
            } catch (\Throwable $e) {
                if (self::$logger) self::$logger->warning('CSRF: lock acquire failed', ['exception' => $e, 'key' => $lockKey]);
                $locked = false;
            }

            try {
                try {
                    // If store is empty, prefer deleting cache key (remove stale file).
                    if (empty($store)) {
                        try {
                            self::$cache->delete($cacheKey);
                        } catch (\Throwable $e) {
                            if (self::$logger) self::$logger->warning('CSRF cache delete failed', ['exception' => $e, 'key' => $cacheKey]);
                        }
                    } else {
                        // write store with computed TTL (best-effort)
                        self::$cache->set($cacheKey, $store, $cacheTtl);
                    }
                    // mark persisted
                    self::$requestStores[$cacheKey]['dirty'] = false;
                } catch (\Throwable $e) {
                    if (self::$logger) self::$logger->error('CSRF cache set/delete failed', ['exception' => $e, 'key' => $cacheKey]);
                }
            } finally {
                if ($locked && $token !== null) {
                    try {
                        if (self::$cache instanceof LockingCacheInterface) {
                            self::$cache->releaseLock($lockKey, $token);
                        }
                    } catch (\Throwable $e) {
                        if (self::$logger) self::$logger->warning('CSRF: lock release failed', ['exception' => $e, 'key' => $lockKey]);
                    }
                }
            }
        }
    }

    /**
     * Remove expired tokens from a store and trim to maxTokens (oldest expire removed).
     */
    private static function cleanupStore(array $store): array
    {
        $now = time();
        foreach ($store as $k => $meta) {
            if (!isset($meta['exp']) || $meta['exp'] < $now) {
                unset($store[$k]);
            }
        }

        // trim by oldest exp while >= maxTokens
        while (count($store) >= self::$maxTokens) {
            $oldestKey = null;
            $oldestExp = PHP_INT_MAX;
            foreach ($store as $k => $meta) {
                $exp = $meta['exp'] ?? 0;
                if ($exp < $oldestExp) {
                    $oldestExp = $exp;
                    $oldestKey = $k;
                }
            }
            if ($oldestKey !== null) {
                unset($store[$oldestKey]);
            } else {
                break;
            }
        }
        return $store;
    }

    public static function countTokens(): int
    {
        self::ensureInitialized();

        // if logged-in and cache available, return cached store count
        $userId = isset(self::$session['user_id']) ? (int)self::$session['user_id'] : null;
        if ($userId !== null && self::$cache !== null) {
            $store = self::loadTokenStoreForUser($userId);
            return count($store);
        }

        return count(self::$session['csrf_tokens']);
    }

    public static function reset(): void
    {
        if (self::$session !== null) {
            unset(self::$session['csrf_tokens']);
        }
        self::$session = null;
        self::$ttl = self::DEFAULT_TTL;
        self::$maxTokens = self::DEFAULT_MAX_TOKENS;
        self::$cache = null;
        self::$requestStores = [];
    }

    public static function token(): string
    {
        self::ensureInitialized();

        $now = time();
        $userId = isset(self::$session['user_id']) ? (int)self::$session['user_id'] : null;

        // if user logged-in and cache provided -> cache-backed flow (but also persist to session)
        if ($userId !== null && self::$cache !== null) {
            $store = self::loadTokenStoreForUser($userId);
            $store = self::cleanupStore($store);

            $id = bin2hex(random_bytes(16)); // 32 hex chars
            $val = bin2hex(random_bytes(32)); // 64 hex chars
            $meta = ['v' => $val, 'exp' => $now + self::$ttl];

            $store[$id] = $meta;

            // write to requestStores and persist to cache
            $fp = self::getSessionFingerprint();
            $cacheKey = self::buildCacheKeyForUser($userId, $fp);
            self::$requestStores[$cacheKey] = ['store' => $store, 'dirty' => true, 'userId' => $userId];
            self::saveTokenStoreForUserIfNeeded($userId);

            // ALSO write authoritative copy into session (server-side persistence)
            if (is_array(self::$session)) {
                if (!isset(self::$session['csrf_tokens']) || !is_array(self::$session['csrf_tokens'])) {
                    self::$session['csrf_tokens'] = [];
                }
                self::$session['csrf_tokens'][$id] = $meta;
                // Note: session persistence to DB will be handled by SessionManager / session handler
            }

            $mac = bin2hex(Crypto::hmac($id . ':' . $val, 'CSRF_KEY', 'csrf_key'));
            return $id . ':' . $val . ':' . $mac;
        }

        // fallback: session-backed flow for anonymous users
        // cleanup expired tokens
        foreach (self::$session['csrf_tokens'] ?? [] as $k => $meta) {
            if (!isset($meta['exp']) || $meta['exp'] < $now) {
                unset(self::$session['csrf_tokens'][$k]);
            }
        }

        // ensure max tokens - remove oldest by smallest exp
        $tokens = &self::$session['csrf_tokens'];
        if (!is_array($tokens)) {
            $tokens = [];
        }

        while (count($tokens) >= self::$maxTokens) {
            $oldestKey = null;
            $oldestExp = PHP_INT_MAX;

            foreach ($tokens as $k => $meta) {
                $exp = $meta['exp'] ?? 0;
                if ($exp < $oldestExp) {
                    $oldestExp = $exp;
                    $oldestKey = $k;
                }
            }
            if ($oldestKey !== null) {
                unset($tokens[$oldestKey]);
            } else {
                break;
            }
        }

        $id = bin2hex(random_bytes(16)); // 32 hex chars
        $val = bin2hex(random_bytes(32)); // 64 hex chars
        $meta = ['v' => $val, 'exp' => $now + self::$ttl];
        self::$session['csrf_tokens'][$id] = $meta;

        $mac = bin2hex(Crypto::hmac($id . ':' . $val, 'CSRF_KEY', 'csrf_key'));
        return $id . ':' . $val . ':' . $mac;
    }

    public static function validate(?string $token): bool
    {
        self::ensureInitialized();

        if (!is_string($token)) {
            return false;
        }
        $parts = explode(':', $token, 3);
        if (count($parts) !== 3) {
            return false;
        }
        [$id, $val, $mac] = $parts;

        // validate ID/val format
        if (!ctype_xdigit($id) || strlen($id) !== 32) {
            return false;
        }
        if (!ctype_xdigit($val) || strlen($val) !== 64) {
            return false;
        }

        // KEY ROTATION AWARE CHECK
        $candidates = Crypto::hmac($id . ':' . $val, 'CSRF_KEY', 'csrf_key', null, true);

        $macBin = hex2bin($mac);
        // HMAC-SHA256 expected => 32 bytes
        if ($macBin === false || strlen($macBin) !== 32) {
            return false;
        }

        $ok = false;
        foreach ($candidates as $cand) {
            if (is_array($cand) && isset($cand['hash']) && is_string($cand['hash'])) {
                if (hash_equals($cand['hash'], $macBin)) {
                    $ok = true;
                    break;
                }
            } elseif (is_string($cand)) {
                if (hash_equals($cand, $macBin)) {
                    $ok = true;
                    break;
                }
            }
        }
        if (!$ok) {
            return false;
        }

        // determine path: cache-backed if user logged-in and cache present
        $userId = isset(self::$session['user_id']) ? (int)self::$session['user_id'] : null;
        $now = time();

        if ($userId !== null && self::$cache !== null) {
            $fp = self::getSessionFingerprint();
            $primaryKey = self::buildCacheKeyForUser($userId, $fp);
            $store = self::loadTokenStoreForUser($userId);

            // try primary
            if (isset($store[$id])) {
                $stored = $store[$id];
                unset($store[$id]);
                self::$requestStores[$primaryKey] = ['store' => $store, 'dirty' => true, 'userId' => $userId];
                self::saveTokenStoreForUserIfNeeded($userId);

                if (!isset($stored['v']) || !hash_equals($stored['v'], (string)$val)) return false;
                if (!isset($stored['exp']) || $stored['exp'] < $now) return false;

                // also remove from session authoritative copy if present
                if (isset(self::$session['csrf_tokens'][$id])) {
                    unset(self::$session['csrf_tokens'][$id]);
                }

                return true;
            }

            // try fallback (no fingerprint) if primary didn't have it
            if ($fp !== null) {
                $fallbackKey = self::buildCacheKeyForUser($userId, null);
                try {
                    $fallbackStore = self::$cache->get($fallbackKey, []);
                    if (is_array($fallbackStore) && isset($fallbackStore[$id])) {
                        $stored = $fallbackStore[$id];
                        // consume in fallback store: write back without this id
                        unset($fallbackStore[$id]);
                        // save fallback store back
                        self::$requestStores[$fallbackKey] = ['store' => $fallbackStore, 'dirty' => true, 'userId' => $userId];
                        self::saveTokenStoreForUserIfNeeded($userId);

                        if (!isset($stored['v']) || !hash_equals($stored['v'], (string)$val)) return false;
                        if (!isset($stored['exp']) || $stored['exp'] < $now) return false;

                        if (isset(self::$session['csrf_tokens'][$id])) {
                            unset(self::$session['csrf_tokens'][$id]);
                        }

                        return true;
                    }
                } catch (\Throwable $e) {
                    if (self::$logger) self::$logger->warning('CSRF validate fallback get failed', ['exception' => $e, 'key' => $fallbackKey]);
                }
            }

            // not found in cache-backed stores -> try authoritative session copy (DB)
            if (isset(self::$session['csrf_tokens'][$id])) {
                $stored = self::$session['csrf_tokens'][$id];
                unset(self::$session['csrf_tokens'][$id]);
                if (!isset($stored['v']) || !hash_equals($stored['v'], (string)$val)) return false;
                if (!isset($stored['exp']) || $stored['exp'] < $now) return false;
                return true;
            }

            return false;
        }

        // session-backed validation for anonymous
        if (!isset(self::$session['csrf_tokens'][$id])) {
            return false;
        }

        $stored = self::$session['csrf_tokens'][$id];
        // consume immediately
        unset(self::$session['csrf_tokens'][$id]);

        if (!isset($stored['v']) || !hash_equals($stored['v'], (string)$val)) {
            return false;
        }
        if (!isset($stored['exp']) || $stored['exp'] < $now) {
            return false;
        }
        return true;
    }

    /**
     * Returns a safe hidden input HTML string (escaped).
     */
    public static function hiddenInput(string $name = 'csrf'): string
    {
        $token = self::token();
        return '<input type="hidden" name="' .
            htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'utf-8') .
            '" value="' .
            htmlspecialchars($token, ENT_QUOTES | ENT_SUBSTITUTE, 'utf-8') .
            '">';
    }

    /**
     * Migrate tokens from anonymous session into user's cache-backed store.
     * Call this right after successful login (after $_SESSION['user_id'] is set).
     */
    public static function migrateGuestTokensToUser(int $userId): void
    {
        self::ensureInitialized();

        if (empty(self::$session['csrf_tokens']) || !is_array(self::$session['csrf_tokens'])) {
            return;
        }

        $guestTokens = self::$session['csrf_tokens'];
        if (empty($guestTokens)) return;

        // load primary user store and merge
        $fp = self::getSessionFingerprint();
        $primaryKey = self::buildCacheKeyForUser($userId, $fp);
        $store = self::loadTokenStoreForUser($userId);
        $store = self::cleanupStore($store);

        foreach ($guestTokens as $id => $meta) {
            // prefer keep existing user store entry if present
            if (!isset($store[$id])) {
                $store[$id] = $meta;
            }
        }

        // write back to requestStores so save will persist
        self::$requestStores[$primaryKey] = ['store' => $store, 'dirty' => true, 'userId' => $userId];
        self::saveTokenStoreForUserIfNeeded($userId);

        // keep authoritative session copy as well (optional: can clear guest tokens)
        // keep them in session to ensure DB persistence; optionally clear if you want
        unset(self::$session['csrf_tokens']);
    }

    /**
     * Cleanup expired tokens (call at bootstrap if needed).
     */
    public static function cleanup(): void
    {
        self::ensureInitialized();
        $now = time();

        // cleanup session tokens
        foreach (self::$session['csrf_tokens'] ?? [] as $k => $meta) {
            if (!isset($meta['exp']) || $meta['exp'] < $now) {
                unset(self::$session['csrf_tokens'][$k]);
            }
        }

        // persist any dirty per-request stores (also perform cleanup on them)
        foreach (self::$requestStores as $cacheKey => $entry) {
            $store = $entry['store'];
            $store = self::cleanupStore($store);

            self::$requestStores[$cacheKey]['store'] = $store;
            self::$requestStores[$cacheKey]['dirty'] = true;

            // Prefer stored userId if present
            $uid = $entry['userId'] ?? null;

            if ($uid !== null) {
                self::saveTokenStoreForUserIfNeeded((int)$uid);
            } else {
                if (self::$logger) self::$logger->warning('CSRF cleanup: cannot determine userId for requestStore', ['cacheKey' => $cacheKey]);
            }
        }
    }
}