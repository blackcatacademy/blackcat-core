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

        if ($cache !== null) {
            self::setCache($cache);
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
     */
    private static function loadTokenStoreForUser(int $userId): array
    {
        if (self::$cache === null) return [];

        $fp = self::getSessionFingerprint();
        $cacheKey = self::buildCacheKeyForUser($userId, $fp);

        if (isset(self::$requestStores[$cacheKey])) {
            return self::$requestStores[$cacheKey]['store'];
        }

        try {
            $store = self::$cache->get($cacheKey, []);
            if (!is_array($store)) $store = [];
        } catch (\Throwable $e) {
            if (self::$logger) self::$logger->warning('CSRF cache get failed', ['exception' => $e, 'key' => $cacheKey]);
            $store = [];
        }

        self::$requestStores[$cacheKey] = ['store' => $store, 'dirty' => false];
        return $store;
    }

    /**
     * Save token store for a given user if marked dirty.
     * Will attempt to acquire lock if cache supports it (FileCache provides acquireLock/releaseLock).
     */
    private static function saveTokenStoreForUserIfNeeded(int $userId): void
    {
        if (self::$cache === null) return;

        $fp = self::getSessionFingerprint();
        $cacheKey = self::buildCacheKeyForUser($userId, $fp);

        if (!isset(self::$requestStores[$cacheKey])) return;
        if (empty(self::$requestStores[$cacheKey]['dirty'])) return;

        $store = self::$requestStores[$cacheKey]['store'];
        $cacheTtl = self::$ttl + 60;

        $locked = false;
        $token = null;

        // try acquire lock if available
        try {
            if (method_exists(self::$cache, 'acquireLock')) {
                $token = self::$cache->acquireLock($cacheKey, 5); // 5s lock
                $locked = ($token !== null);
            }
        } catch (\Throwable $e) {
            if (self::$logger) self::$logger->warning('CSRF: lock acquire failed', ['exception' => $e, 'key' => $cacheKey]);
            $locked = false;
        }

        try {
            try {
                self::$cache->set($cacheKey, $store, $cacheTtl);
                self::$requestStores[$cacheKey]['dirty'] = false;
            } catch (\Throwable $e) {
                if (self::$logger) self::$logger->error('CSRF cache set failed', ['exception' => $e, 'key' => $cacheKey]);
            }
        } finally {
            if ($locked && $token !== null) {
                try {
                    if (method_exists(self::$cache, 'releaseLock')) {
                        self::$cache->releaseLock($cacheKey, $token);
                    }
                } catch (\Throwable $e) {
                    if (self::$logger) self::$logger->warning('CSRF: lock release failed', ['exception' => $e, 'key' => $cacheKey]);
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

        // if user logged-in and cache provided -> cache-backed flow
        if ($userId !== null && self::$cache !== null) {
            $store = self::loadTokenStoreForUser($userId);
            $store = self::cleanupStore($store);

            $id = bin2hex(random_bytes(16)); // 32 hex chars
            $val = bin2hex(random_bytes(32)); // 64 hex chars
            $store[$id] = ['v' => $val, 'exp' => $now + self::$ttl];

            // mark dirty and persist
            $fp = self::getSessionFingerprint();
            $cacheKey = self::buildCacheKeyForUser($userId, $fp);
            self::$requestStores[$cacheKey] = ['store' => $store, 'dirty' => true];
            self::saveTokenStoreForUserIfNeeded($userId);

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
        self::$session['csrf_tokens'][$id] = ['v' => $val, 'exp' => $now + self::$ttl];

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
        if ($macBin === false || strlen($macBin) < 16) {
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
            $cacheKey = self::buildCacheKeyForUser($userId, $fp);
            $store = self::loadTokenStoreForUser($userId);

            if (!isset($store[$id])) {
                return false;
            }

            $stored = $store[$id];
            // consume immediately
            unset($store[$id]);
            self::$requestStores[$cacheKey] = ['store' => $store, 'dirty' => true];
            self::saveTokenStoreForUserIfNeeded($userId);

            if (!isset($stored['v']) || !hash_equals($stored['v'], (string)$val)) {
                return false;
            }
            if (!isset($stored['exp']) || $stored['exp'] < $now) {
                return false;
            }
            return true;
        }

        // session-backed validation
        if (!isset(self::$session['csrf_tokens'][$id])) {
            return false;
        }

        $stored = self::$session['csrf_tokens'][$id];
        // consume immediately
        unset(self::$session['csrf_tokens'][$id]);

        if (!isset($stored['v']) || !hash_equals($stored['v'], (string)$val)) {
            return false;
        }
        if (!isset($stored['exp']) || $stored['exp'] < time()) {
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
            // mark dirty and save: derive userId from cacheKey (simple parse)
            self::$requestStores[$cacheKey]['store'] = $store;
            self::$requestStores[$cacheKey]['dirty'] = true;
            // try to extract userId (cache key format: csrf:user:{userId}:{fp})
            $parts = explode(':', $cacheKey);
            if (isset($parts[2]) && is_numeric($parts[2])) {
                $uid = (int)$parts[2];
                self::saveTokenStoreForUserIfNeeded($uid);
            } else {
                // fallback: try saving generically (best effort)
                // we can't reliably save without userId in this branch
            }
        }
    }
}