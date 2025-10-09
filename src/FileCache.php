<?php
declare(strict_types=1);

use Psr\SimpleCache\InvalidArgumentException as PsrInvalidArgumentException;

/**
 * Production-ready file-based PSR-16 cache (improved).
 *
 * NOTE: This variant uses your global static Logger (Logger::systemMessage / Logger::systemError).
 * If Logger class is not present, it falls back silently to error_log().
 */
class FileCache implements LockingCacheInterface
{
    private string $cacheDir;
    private string $cacheDirReal;

    // encryption options
    private bool $useEncryption = false;
    private ?string $cryptoKeysDir = null;
    private string $cryptoEnvName = 'CACHE_CRYPTO_KEY';
    private string $cryptoBasename = 'cache_crypto';

    // storage controls
    private int $gcProbability = 1; // numerator
    private int $gcProbabilityDivisor = 1000; // 1/1000 chance to run GC on set()

    // Sharding depth: number of hex chars from hash to use as subdirs (0 = no sharding)
    private int $shardDepth = 2;

    // Quota / eviction
    // maxTotalSizeBytes: 0 = unlimited; otherwise enforce total size in bytes
    private int $maxTotalSizeBytes = 0;
    // maxFiles: 0 = unlimited; otherwise enforce number of files
    private int $maxFiles = 0;

    // Max single entry payload (serialized) - prevents huge writes (0 = unlimited)
    private int $maxEntryBytes = 1024 * 1024; // default 1MB

    // Metrics / counters (in-memory, per-process - can be exposed to monitoring)
    private array $counters = [
        'sets' => 0,
        'gets' => 0,
        'hits' => 0,
        'misses' => 0,
        'evictions' => 0,
        'errors' => 0,
    ];

    private const SAFE_PREFIX_LEN = 32;

    public static function ensurePsrExceptionExists(): void
    {
        // helper; PSR exception class defined below
    }

    /**
     * @param string|null $cacheDir
     * @param bool $useEncryption
     * @param string|null $cryptoKeysDir
     * @param string $cryptoEnvName
     * @param string $cryptoBasename
     */
    public function __construct(
        ?string $cacheDir = null,
        bool $useEncryption = false,
        ?string $cryptoKeysDir = null,
        string $cryptoEnvName = 'CACHE_CRYPTO_KEY',
        string $cryptoBasename = 'cache_crypto',
        int $shardDepth = 2,
        int $maxTotalSizeBytes = 0,
        int $maxFiles = 0,
        int $maxEntryBytes = 1048576
    ) {
        $this->cacheDir = $cacheDir ?? __DIR__ . '/../cache';

        if (!is_dir($this->cacheDir)) {
            if (!@mkdir($this->cacheDir, 0700, true) && !is_dir($this->cacheDir)) {
                throw new RuntimeException("Cannot create cache directory: {$this->cacheDir}");
            }
            @chmod($this->cacheDir, 0700);
        }

        $real = realpath($this->cacheDir);
        if ($real === false) {
            throw new RuntimeException("Cannot resolve cacheDir realpath: {$this->cacheDir}");
        }
        $this->cacheDirReal = rtrim($real, DIRECTORY_SEPARATOR);

        $this->useEncryption = $useEncryption;
        $this->cryptoKeysDir = $cryptoKeysDir;
        $this->cryptoEnvName = $cryptoEnvName;
        $this->cryptoBasename = $cryptoBasename;
        $this->shardDepth = max(0, (int)$shardDepth);
        $this->maxTotalSizeBytes = max(0, (int)$maxTotalSizeBytes);
        $this->maxFiles = max(0, (int)$maxFiles);
        $this->maxEntryBytes = max(0, (int)$maxEntryBytes);

        // Ensure top-level cache dir perms and ownership (best-effort)
        @chmod($this->cacheDirReal, 0700);

        if ($this->useEncryption) {
            if (!class_exists('KeyManager') || !class_exists('Crypto')) {
                throw new RuntimeException('KeyManager or Crypto class not available; cannot enable encryption.');
            }

            try {
                KeyManager::requireSodium();
            } catch (Throwable $e) {
                throw new RuntimeException('libsodium extension required for FileCache encryption: ' . $e->getMessage());
            }

            try {
                $candidates = KeyManager::getAllRawKeys(
                    $this->cryptoEnvName,
                    $this->cryptoKeysDir,
                    $this->cryptoBasename,
                    KeyManager::keyByteLen()
                );
                if (!is_array($candidates) || empty($candidates)) {
                    throw new RuntimeException('No key material found for FileCache encryption (check ENV ' . $this->cryptoEnvName . ' or keysDir ' . ($this->cryptoKeysDir ?? 'null') . ').');
                }
                foreach ($candidates as &$c) {
                    try { KeyManager::memzero($c); } catch (Throwable $_) {}
                }
                unset($candidates);
            } catch (Throwable $e) {
                throw new RuntimeException('FileCache encryption initialization failed: ' . $e->getMessage());
            }
        }
    }

    /**
     * Logging wrapper that uses your static Logger.
     * - If Throwable $e is provided, calls Logger::systemError($e, ...)
     * - Otherwise calls Logger::systemMessage($level, $msg, null, $context)
     *
     * This wrapper never throws.
     *
     * @param string $level  'warning'|'error'|'info'|'critical'
     * @param string $msg
     * @param Throwable|null $e
     * @param array|null $context
     */
    private function log(string $level, string $msg, ?Throwable $e = null, ?array $context = null): void
    {
        try {
            if ($e !== null && class_exists('Logger') && method_exists('Logger', 'systemError')) {
                // call systemError for exceptions — keep it silent if it fails
                try {
                    Logger::systemError($e, null, null, $context ?? ['component' => 'FileCache']);
                    return;
                } catch (Throwable $_) {
                    // swallow and fallback
                }
            }

            if (class_exists('Logger') && method_exists('Logger', 'systemMessage')) {
                try {
                    $ctx = $context ?? ['component' => 'FileCache'];
                    Logger::systemMessage($level, $msg, null, $ctx);
                    return;
                } catch (Throwable $_) {
                    // swallow
                }
            }

            // final fallback
            error_log('[FileCache][' . $level . '] ' . $msg);
        } catch (Throwable $_) {
            // absolutely silent fallback
        }
    }

    private function validateKey(string $key): void
    {
        if ($key === '') {
            throw new CacheInvalidArgumentException('Cache key must not be empty.');
        }
        // PSR-16 reserved characters
        if (preg_match('/[\{\}\(\)\/\\\\\@\:]/', $key)) {
            throw new CacheInvalidArgumentException('Cache key contains reserved characters {}()/\\@:');
        }
        // control characters
        if (preg_match('/[\x00-\x1F\x7F]/', $key)) {
            throw new CacheInvalidArgumentException('Cache key contains control characters.');
        }
        if (strlen($key) > 1024) {
            throw new CacheInvalidArgumentException('Cache key too long.');
        }
    }

    private function getPath(string $key): string
    {
        $prefix = preg_replace('/[^a-zA-Z0-9_\-]/', '_', mb_substr($key, 0, self::SAFE_PREFIX_LEN));
        if ($prefix === '') $prefix = 'key';
        $hash = hash('sha256', $key);

        if ($this->shardDepth > 0) {
            // use first N hex chars -> create N/2 directories of two chars each for distribution
            $parts = [];
            for ($i = 0; $i < $this->shardDepth * 2; $i+=2) {
                $parts[] = $hash[$i].$hash[$i+1];
            }
            $sub = implode(DIRECTORY_SEPARATOR, $parts);
            $dir = $this->cacheDirReal . DIRECTORY_SEPARATOR . $sub;
            // ensure shard dir exists (best-effort, non-fatal)
            if (!is_dir($dir)) {
                @mkdir($dir, 0700, true);
                @chmod($dir, 0700);
            }
            return $dir . DIRECTORY_SEPARATOR . $prefix . '_' . $hash . '.cache';
        }

        return $this->cacheDirReal . DIRECTORY_SEPARATOR . $prefix . '_' . $hash . '.cache';
    }

    /**
     * Normalize TTL input into seconds.
     *
     * @param int|DateInterval|null $ttl
     * @return int|null seconds or null for unlimited
     */
    private function normalizeTtl($ttl): ?int
    {
        if ($ttl === null) return null;
        if ($ttl instanceof DateInterval) {
            $now = new DateTimeImmutable();
            $expiry = $now->add($ttl);
            return $expiry->getTimestamp() - $now->getTimestamp();
        }
        return (int)$ttl;
    }

    private function safeFileRead(string $file): string|false {
        $fp = @fopen($file, 'rb');
        if ($fp === false) return false;
        if (!flock($fp, LOCK_SH)) { fclose($fp); return false; }
        $contents = stream_get_contents($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
        return $contents;
    }

    private function safeAtomicWrite(string $file, string $data): bool {
        $tmp = @tempnam($this->cacheDirReal, 'fc_');
        if ($tmp === false) {
            $this->log('warning', 'tempnam failed for atomic write');
            return false;
        }
        $fp = @fopen($tmp, 'wb');
        if ($fp === false) { @unlink($tmp); $this->log('warning', 'fopen(tmp) failed'); return false; }
        if (!flock($fp, LOCK_EX)) { fclose($fp); @unlink($tmp); $this->log('warning', 'flock(tmp) failed'); return false; }
        $written = fwrite($fp, $data);
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
        if ($written === false) { @unlink($tmp); $this->log('warning', 'fwrite failed'); return false; }

        // Attempt to ensure destination dir exists
        $destDir = dirname($file);
        if (!is_dir($destDir)) {
            @mkdir($destDir, 0700, true);
            @chmod($destDir, 0700);
        }

        if (!@rename($tmp, $file)) { @unlink($tmp); $this->log('warning', 'rename tmp->file failed'); return false; }

        // Post-rename sanity: ensure final realpath is inside cacheDirReal
        $finalReal = realpath($file);
        if ($finalReal === false || !str_starts_with($finalReal, $this->cacheDirReal . DIRECTORY_SEPARATOR)) {
            // suspicious: remove file and log critical
            @unlink($file);
            $this->log('critical', 'Post-rename realpath outside cacheDir - possible symlink attack', null, ['file' => $file, 'final' => $finalReal]);
            return false;
        }

        // Enforce secure perms
        @chmod($file, 0600);
        clearstatcache(true, $file);
        return true;
    }

    private function isPathInCacheDir(string $path): bool {
        $real = realpath($path);
        if ($real === false) return false;
        return str_starts_with($real, $this->cacheDirReal . DIRECTORY_SEPARATOR);
    }

    /**
     * Attempt to acquire a file-based lock with expiry.
     *
     * Returns a lock token string on success (must be passed to releaseLock),
     * or null on failure.
     *
     * Uses O_EXCL-like fopen('x') to create lock file atomically. If a stale
     * lock exists (expired), it is removed and acquisition is retried once.
     */
    public function acquireLock(string $name, int $ttlSeconds = 10): ?string
    {
        $safe = preg_replace('/[^A-Za-z0-9_\-]/', '_', mb_substr($name, 0, 64));
        $locksDir = $this->cacheDirReal . DIRECTORY_SEPARATOR . 'locks';
        if (!is_dir($locksDir)) {
            @mkdir($locksDir, 0700, true);
            @chmod($locksDir, 0700);
        }
        $lockFile = $locksDir . DIRECTORY_SEPARATOR . $safe . '.lock';
        $token = bin2hex(random_bytes(16));
        $expireAt = time() + max(1, (int)$ttlSeconds);
        $payload = json_encode(['token' => $token, 'expires' => $expireAt], JSON_UNESCAPED_SLASHES);

        // Try atomic create via fopen('x')
        $fp = @fopen($lockFile, 'x'); // fails if file exists
        if ($fp !== false) {
            // write token + expires
            fwrite($fp, $payload);
            fflush($fp);
            fclose($fp);
            @chmod($lockFile, 0600);
            return $token;
        }

        // if file exists, check if stale
        if (is_file($lockFile) && is_readable($lockFile)) {
            $raw = @file_get_contents($lockFile);
            if ($raw !== false) {
                $dec = @json_decode($raw, true);
                if (is_array($dec) && isset($dec['expires']) && is_numeric($dec['expires'])) {
                    if ((int)$dec['expires'] < time()) {
                        // stale -> try to remove and acquire once more
                        @unlink($lockFile);
                        $fp2 = @fopen($lockFile, 'x');
                        if ($fp2 !== false) {
                            fwrite($fp2, $payload);
                            fflush($fp2);
                            fclose($fp2);
                            @chmod($lockFile, 0600);
                            return $token;
                        }
                    }
                }
            }
        }

        return null;
    }

    /**
     * Release lock previously acquired by acquireLock.
     * Returns true on success, false otherwise.
     */
    public function releaseLock(string $name, string $token): bool
    {
        $safe = preg_replace('/[^A-Za-z0-9_\-]/', '_', mb_substr($name, 0, 64));
        $lockFile = $this->cacheDirReal . DIRECTORY_SEPARATOR . 'locks' . DIRECTORY_SEPARATOR . $safe . '.lock';
        if (!is_file($lockFile) || !is_readable($lockFile)) return false;
        $raw = @file_get_contents($lockFile);
        if ($raw === false) return false;
        $dec = @json_decode($raw, true);
        if (!is_array($dec) || !isset($dec['token'])) return false;
        if (!hash_equals((string)$dec['token'], (string)$token)) {
            // token mismatch — do not remove other's lock
            return false;
        }
        return @unlink($lockFile);
    }

    /**
     * Returns detailed cache metrics for sharded caches with size breakdown.
     *
     * - totalFiles: all cache files including expired
     * - activeFiles: non-expired cache entries
     * - expiredFiles: expired cache entries
     * - totalSize: total size of all cache files in bytes
     * - activeSize: size of active cache files in bytes
     * - expiredSize: size of expired cache files in bytes
     * - evictions: total evictions counter
     */
    public function getMetrics(): array {
        $totalFiles = 0;
        $activeFiles = 0;
        $expiredFiles = 0;
        $totalSize = 0;
        $activeSize = 0;
        $expiredSize = 0;
        $processedExpired = 0;
        $maxGcPerRun = 1000;

        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator(
                $this->cacheDirReal,
                FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO
            ),
            RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($it as $f) {
            if (!$f->isFile() || substr($f->getFilename(), -6) !== '.cache') continue;

            $path = $f->getRealPath();
            if ($path === false || !$this->isPathInCacheDir($path)) continue;

            $size = $f->getSize();
            $totalFiles++;
            $totalSize += $size;

            $expired = false;
            $raw = $this->safeFileRead($path);
            if ($raw !== false) {
                $data = @unserialize($raw, ['allowed_classes' => false]);
                if (is_array($data) && isset($data['expires'])) {
                    if ($data['expires'] !== null && $data['expires'] < time()) {
                        $expired = true;
                    }
                }
            }

            if ($expired) {
                $expiredFiles++;
                $expiredSize += $size;
                // Light GC: remove max 1000 expired files per run
                if ($processedExpired < $maxGcPerRun) {
                    if ($this->isPathInCacheDir($path)) {
                        @unlink($path);
                    }
                    $processedExpired++;
                }
            } else {
                $activeFiles++;
                $activeSize += $size;
            }
        }

        return [
            'totalFiles' => $totalFiles,
            'activeFiles' => $activeFiles,
            'expiredFiles' => $expiredFiles,
            'totalSize' => $totalSize,
            'activeSize' => $activeSize,
            'expiredSize' => $expiredSize,
            'evictions' => $this->counters['evictions'] ?? 0,
        ];
    }

    /**
     * Fetches a value from the cache.
     *
     * @param string $key     Cache key
     * @param mixed $default  Default value to return if not found
     * @return mixed          Cached value or $default
     *
     * @throws CacheInvalidArgumentException If the key is invalid
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $this->counters['gets']++;
        $this->validateKey($key);
        $file = $this->getPath($key);
        if (!is_file($file)) return $default;

        $raw = $this->safeFileRead($file);
        if ($raw === false) return $default;

        $data = @unserialize($raw, ['allowed_classes' => false]);
        if (!is_array($data) || !array_key_exists('expires', $data) || !array_key_exists('value', $data)) {
            $this->counters['misses']++;
            return $default;
        }
        if ($data['expires'] !== null && $data['expires'] < time()) {
            if ($this->isPathInCacheDir($file)) @unlink($file);
            $this->counters['misses']++;
            return $default;
        }

        if (empty($data['enc'])) {
            $this->counters['hits']++;
            return $data['value'];
        }

        $payload = $data['value'];
        $version = $data['key_version'] ?? null;

        if ($version !== null) {
            try {
                $info = KeyManager::getRawKeyBytesByVersion(
                    $this->cryptoEnvName,
                    $this->cryptoKeysDir,
                    $this->cryptoBasename,
                    $version,
                    KeyManager::keyByteLen()
                );
                $rawKey = $info['raw'];
                $plain = Crypto::decryptWithKeyCandidates($payload, [$rawKey]);
                try { KeyManager::memzero($rawKey); } catch (Throwable $_) {}
                unset($rawKey, $info);

                if ($plain !== null) {
                    $val = @unserialize($plain, ['allowed_classes' => false]);
                    if ($val === false && $plain !== serialize(false)) return $default;
                    $this->counters['hits']++;
                    return $val;
                }
            } catch (Throwable $e) {
                $this->log('warning', 'decrypt_by_version failed', $e);
            }
        }

        try {
            $candidates = KeyManager::getAllRawKeys(
                $this->cryptoEnvName,
                $this->cryptoKeysDir,
                $this->cryptoBasename,
                KeyManager::keyByteLen()
            );

            if (!is_array($candidates) || empty($candidates)) {
                $this->log('warning', 'No key material found for cache basename/env');
                return $default;
            }

            $plain = Crypto::decryptWithKeyCandidates($payload, $candidates);

            foreach ($candidates as &$c) {
                try { KeyManager::memzero($c); } catch (Throwable $_) {}
            }
            unset($candidates);

            if ($plain === null) return $default;
            $val = @unserialize($plain, ['allowed_classes' => false]);
            if ($val === false && $plain !== serialize(false)) return $default;
            $this->counters['hits']++;
            return $val;
        } catch (Throwable $e) {
            $this->log('warning', 'decrypt_all_keys failed', $e);
            return $default;
        }
    }

    /**
     * Persists a value in the cache, optionally with TTL.
     *
     * @param string $key
     * @param mixed $value
     * @param int|DateInterval|null $ttl
     * @return bool True on success, false on failure
     *
     * @throws CacheInvalidArgumentException
     */
    public function set(string $key, mixed $value, DateInterval|int|null $ttl = null): bool
    {
        $this->validateKey($key);
        $file = $this->getPath($key);
        $ttlSec = $this->normalizeTtl($ttl);
        $expires = $ttlSec !== null ? time() + $ttlSec : null;

        if (!$this->useEncryption) {
            $data = ['expires' => $expires, 'value' => $value];
        } else {
            $plain = serialize($value);

            try {
                $info = KeyManager::getRawKeyBytes(
                    $this->cryptoEnvName,
                    $this->cryptoKeysDir,
                    $this->cryptoBasename,
                    false,
                    KeyManager::keyByteLen()
                );
            } catch (Throwable $e) {
                $this->log('error', 'failed to obtain raw key', $e);
                return false;
            }

            $raw = $info['raw'] ?? null;
            $version = $info['version'] ?? null;

            if (!is_string($raw) || strlen($raw) !== KeyManager::keyByteLen()) {
                try { KeyManager::memzero($raw); } catch (Throwable $_) {}
                $this->log('error', 'invalid raw key returned by KeyManager');
                return false;
            }

            try {
                $encrypted = Crypto::encryptWithKeyBytes($plain, $raw, 'compact_base64');
            } catch (Throwable $e) {
                $this->log('error', 'encryptWithKeyBytes failed', $e);
                try { KeyManager::memzero($raw); } catch (Throwable $_) {}
                return false;
            }

            try { KeyManager::memzero($raw); } catch (Throwable $_) {}
            unset($raw, $info);

            $data = [
                'expires' => $expires,
                'value' => $encrypted,
                'enc' => true,
                'key_version' => $version,
            ];
            $plain = '';
        }

        // probabilistic GC
        try {
            if (random_int(1, $this->gcProbabilityDivisor) <= $this->gcProbability) {
                $this->gc();
            }
        } catch (Throwable $_) {}

        try {
            $serialized = serialize($data);
            if ($this->maxEntryBytes > 0 && strlen($serialized) > $this->maxEntryBytes) {
                $this->log('warning', 'Entry too large for cache (rejected)', null, ['key' => $key, 'size' => strlen($serialized)]);
                $this->counters['errors']++;
                return false;
            }
            if (!$this->safeAtomicWrite($file, $serialized)) {
                $this->counters['errors']++;
                return false;
            }
            // successful write -> counters + quota enforcement
            $this->counters['sets']++;
            $this->enforceQuota();
            return true;
        } catch (Throwable $e) {
            $this->log('error', 'set() error', $e);
            return false;
        }
    }

    /**
     * Deletes an item from the cache.
     *
     * @param string $key
     * @return bool True if key was deleted, false if not found
     *
     * @throws CacheInvalidArgumentException
     */
    public function delete(string $key): bool
    {
        $this->validateKey($key);
        $file = $this->getPath($key);
        if (is_file($file)) {
            if (!$this->isPathInCacheDir($file)) {
                $this->log('warning', 'delete: path outside cacheDir');
                return false;
            }
            try { return unlink($file); } catch (Throwable $_) { return false; }
        }
        return true;
    }

    /**
     * Delete cache files whose key prefix (first SAFE_PREFIX_LEN chars) matches given prefix.
     *
     * @param string $prefix  The key prefix (e.g. 'gopay_status_...') — will be sanitized same way as getPath().
     * @return int Number of deleted entries.
     */
    public function deleteKeysByPrefix(string $prefix): int
    {
        $this->validateKey(mb_substr($prefix, 0, self::SAFE_PREFIX_LEN)); // quick sanity (may throw)
        $safePrefix = preg_replace('/[^a-zA-Z0-9_\-]/', '_', mb_substr($prefix, 0, self::SAFE_PREFIX_LEN));
        $deleted = 0;

        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->cacheDirReal, FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO),
            RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($it as $f) {
            if (!$f->isFile()) continue;
            $fname = $f->getFilename();
            if (!str_ends_with($fname, '.cache')) continue;

            // filenames are: <prefix>_<sha256>.cache
            if (str_starts_with($fname, $safePrefix . '_')) {
                $path = $f->getRealPath();
                if ($path === false) continue;
                if (!$this->isPathInCacheDir($path)) continue;
                try {
                    if (@unlink($path)) $deleted++;
                } catch (Throwable $_) {
                    // ignore individual failures but continue
                }
            }
        }

        if ($deleted > 0) $this->counters['evictions'] += $deleted;
        return $deleted;
    }

    /**
     * Wipes the entire cache directory.
     *
     * @return bool True on full clear success, false on error
     */
    public function clear(): bool
    {
        $success = true;
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->cacheDirReal, FilesystemIterator::SKIP_DOTS)
        );
        foreach ($it as $f) {
            if (!$f->isFile()) continue;
            $path = $f->getRealPath();
            if ($path === false) continue;
            if (!str_ends_with($path, '.cache')) continue;
            if (!$this->isPathInCacheDir($path)) { $success = false; continue; }
            if (!@unlink($path)) $success = false;
        }
        return $success;
    }

    /**
     * Obtains multiple values by their keys.
     *
     * @param iterable<string> $keys
     * @param mixed $default
     * @return array<string,mixed>
     *
     * @throws CacheInvalidArgumentException
     */
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $out = [];
        foreach ($keys as $k) {
            try {
                $this->validateKey($k);
                $out[$k] = $this->get($k, $default);
            } catch (PsrInvalidArgumentException $e) {
                throw $e;
            }
        }
        return $out;
    }

    /**
     * Stores multiple key/value pairs.
     *
     * @param iterable<string,mixed> $values
     * @param int|DateInterval|null $ttl
     * @return bool
     *
     * @throws CacheInvalidArgumentException
     */
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        $success = true;
        foreach ($values as $k => $v) {
            try {
                $this->validateKey($k);
                if (!$this->set($k, $v, $ttl)) $success = false;
            } catch (PsrInvalidArgumentException $e) {
                throw $e;
            }
        }
        return $success;
    }

    /**
     * Deletes multiple keys.
     *
     * @param iterable<string> $keys
     * @return bool
     *
     * @throws CacheInvalidArgumentException
     */
    public function deleteMultiple(iterable $keys): bool
    {
        $success = true;
        foreach ($keys as $k) {
            try {
                $this->validateKey($k);
                if (!$this->delete($k)) $success = false;
            } catch (PsrInvalidArgumentException $e) {
                throw $e;
            }
        }
        return $success;
    }

    
    /**
     * Checks if a cache entry exists and is not expired.
     *
     * @param string $key
     * @return bool
     *
     * @throws CacheInvalidArgumentException
     */
    public function has(string $key): bool
    {
        $this->validateKey($key);
        $file = $this->getPath($key);
        if (!is_file($file)) return false;

        $raw = $this->safeFileRead($file);
        if ($raw === false) return false;
        $data = @unserialize($raw, ['allowed_classes' => false]);
        if (!is_array($data) || !isset($data['expires'])) return false;
        if ($data['expires'] !== null && $data['expires'] < time()) {
            if ($this->isPathInCacheDir($file)) @unlink($file);
            return false;
        }
        return true;
    }

    /**
    * Remove expired cache files (max 1000 per run).
    */
    private function gc(): void {
        $maxPerRun = 1000; // process limit - adjust as needed
        $processed = 0;
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($this->cacheDirReal, FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO));
        foreach ($it as $f) {
            if ($processed++ >= $maxPerRun) break;
            if (!$f->isFile()) continue;
            $path = $f->getRealPath();
            if ($path === false) continue;
            if (!str_ends_with($path, '.cache')) continue;
            $fp = @fopen($path, 'rb');
            if ($fp === false) continue;
            if (!flock($fp, LOCK_SH)) { fclose($fp); continue; }
            $raw = stream_get_contents($fp, 8192, 0);
            flock($fp, LOCK_UN);
            fclose($fp);
            $data = @unserialize($raw, ['allowed_classes' => false]);
            if (is_array($data) && isset($data['expires']) && $data['expires'] !== null && $data['expires'] < time()) {
                if ($this->isPathInCacheDir($path)) @unlink($path);
            }
        }
    }

    /**
     * Enforce total size / file count limits by deleting oldest files.
     */
    private function enforceQuota(): void {
        // fast path
        if ($this->maxTotalSizeBytes <= 0 && $this->maxFiles <= 0) return;

        $pattern = $this->cacheDirReal . DIRECTORY_SEPARATOR . ($this->shardDepth > 0 ? '**/*.cache' : '*.cache'); // globstar pseudo - handled manually
        // collect files recursively (safe)
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($this->cacheDirReal, FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO));
        $files = [];
        $total = 0;
        $count = 0;
        foreach ($it as $f) {
            if (!$f->isFile()) continue;
            $path = $f->getRealPath();
            if ($path === false) continue;
            if (!str_starts_with($path, $this->cacheDirReal . DIRECTORY_SEPARATOR)) continue;
            if (substr($path, -6) !== '.cache') continue;
            $size = $f->getSize();
            $mtime = $f->getMTime();
            $files[] = ['path' => $path, 'size' => $size, 'mtime' => $mtime];
            $total += $size;
            $count++;
        }

        if ($this->maxTotalSizeBytes > 0 || $this->maxFiles > 0) {
            // sort by oldest mtime first (LRU-ish)
            usort($files, function($a, $b){ return $a['mtime'] <=> $b['mtime']; });

            $i = 0;
            while (($this->maxTotalSizeBytes > 0 && $total > $this->maxTotalSizeBytes)
                || ($this->maxFiles > 0 && $count > $this->maxFiles)) {
                if (!isset($files[$i])) break;
                $f = $files[$i];
                // double-check path is inside cache dir
                if ($this->isPathInCacheDir($f['path'])) {
                    @unlink($f['path']);
                    $this->counters['evictions']++;
                    $total -= $f['size'];
                    $count--;
                }
                $i++;
            }
        }
    }
} 
/**
 * PSR-16 compatible InvalidArgumentException for this file cache.
 */
class CacheInvalidArgumentException extends InvalidArgumentException implements PsrInvalidArgumentException {}