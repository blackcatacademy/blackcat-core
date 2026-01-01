<?php
declare(strict_types=1);

// 11/10 patch additions merged: PSR-16 friendly keys, TTL jitter, helpers, bulk API

namespace BlackCat\Core\Database;

use BlackCat\Core\Database;
use Psr\SimpleCache\CacheInterface;
use Psr\Log\LoggerInterface;
use BlackCat\Core\Cache\LockingCacheInterface;

/**
 * QueryCache
 * - compute-if-absent with optional locking
 * - shared prefix invalidation across processes via CacheInterface (best-effort)
 * - stale-while-revalidate helper
 *
 * Backwards compatible with previous version + merged patches.
 */
final class QueryCache
{
    public function __construct(
        private CacheInterface $cache,
        private ?LockingCacheInterface $locks = null,
        private ?LoggerInterface $logger = null,
        private string $namespace = 'dbq'
    ) {}

    // --- metrics & versioned prefixes ---
    private int $hits = 0;
    private int $miss = 0;

    // NEW metrics:
    private int $staleHits = 0;
    private int $lockAcquired = 0;
    private int $lockWaitTimeouts = 0;
    private int $producerRuns = 0;

    /** @var array<string,int> prefix => version (local in-process cache) */
    private array $prefixVersions = [];

    /** Shared prefix versioning config */
    private bool $useSharedPrefix = false;
    private int $sharedPrefixRefreshSec = 1;
    /** @var array<string,int> */
    private array $sharedPrefixLastFetch = [];

    // Lock/backoff settings
    private int $lockWaitSec = 10;      // total ceiling for waiting on a compute
    private int $lockRetryMinMs = 50;   // minimum backoff
    private int $lockRetryMaxMs = 250;  // maximum backoff

    // NEW: unified API for TTL jitter (percent 0..90)
    private int $ttlJitterPercent = 0;
    // NEW: optional key-length guard (0 = disabled)
    private int $maxKeyLength = 0;

    public function enableSharedPrefixVersions(bool $on = true, int $refreshSec = 1): void
    {
        $this->useSharedPrefix = $on;
        $this->sharedPrefixRefreshSec = max(1, $refreshSec);
    }

    // Fine tuning for anti-herd parameters (locking/backoff)
    public function configureLocking(int $waitSec = 10, int $minBackoffMs = 50, int $maxBackoffMs = 250): void
    {
        $this->lockWaitSec = max(1, $waitSec);
        $this->lockRetryMinMs = max(1, $minBackoffMs);
        $this->lockRetryMaxMs = max($this->lockRetryMinMs, $maxBackoffMs);
    }

    /** Alias 1: anti-herd TTL jitter (0..90). */
    public function configureJitter(int $percent): void
    {   // from patch variant "configureJitter"
        $this->setTtlJitterPercent($percent);
    }
    /** Alias 2: anti-herd TTL jitter (0..100). */
    public function configureTtlJitter(int $percent): void
    {   // from patch variant "configureTtlJitter"
        $this->setTtlJitterPercent($percent);
    }
    /** Alias 3: anti-herd TTL jitter (0..50 typical). */
    public function setTtlJitterPercent(int $pct): void
    {   // from patch variant "setTtlJitterPercent"
        $this->ttlJitterPercent = max(0, min(90, $pct));
    }

    /** Optional key-length guard (e.g. Memcached 250). 0 = disabled. */
    public function setMaxKeyLength(int $n = 250): void
    {
        $this->maxKeyLength = max(0, $n);
    }

    public function stats(): array
    {
        return [
            'hits' => $this->hits,
            'miss' => $this->miss,
            // NEW: extended metrics
            'staleHits' => $this->staleHits,
            'lockAcquired' => $this->lockAcquired,
            'lockWaitTimeouts' => $this->lockWaitTimeouts,
            'producerRuns' => $this->producerRuns,
            'prefixVersions' => $this->prefixVersions,
            'sharedPrefix' => $this->useSharedPrefix,
        ];
    }

    /** In-process version bump (legacy behavior) */
    public function invalidatePrefix(string $prefix): void
    {
        $this->prefixVersions[$prefix] = ($this->prefixVersions[$prefix] ?? 0) + 1;
        if ($this->useSharedPrefix) {
            $this->invalidatePrefixShared($prefix);
        }
    }

    /** Cross-process prefix invalidation (atomic via LockingCacheInterface, otherwise best-effort). */
    public function invalidatePrefixShared(string $prefix): void
    {
        $k = $this->sharedPrefixKey($prefix);
        $lk = 'pv:' . $k;
        try {
            if ($this->locks) {
                $tok = $this->locks->acquireLock($lk, 5);
                try {
                    $v = (int)$this->cache->get($k, 0);
                    $this->cache->set($k, $v + 1);
                    $this->prefixVersions[$prefix] = $v + 1;
                    $this->sharedPrefixLastFetch[$prefix] = time();
                } finally {
                    if ($tok !== null) { $this->locks->releaseLock($lk, $tok); }
                }
            } else {
                // fallback without locks (race-prone)
                $v = (int)$this->cache->get($k, 0);
                $this->cache->set($k, $v + 1);
                $this->prefixVersions[$prefix] = $v + 1;
                $this->sharedPrefixLastFetch[$prefix] = time();
            }
        } catch (\Throwable $e) {
            $this->logger?->warning('QueryCache invalidatePrefixShared failed', ['prefix'=>$prefix, 'e'=>$e]);
        }
    }

    private function sharedPrefixKey(string $prefix): string
    {
        return $this->namespace . ':pv|' . $prefix;
    }

    // Explicit key with prefix for easier invalidation.
    public function keyWithPrefix(string $prefix, string $dbId, string $sql, array $params = []): string
    {
        // Format: "<prefix>{$namespace}|{$dbId}|<hash>"
        return $prefix . $this->key($dbId, $sql, $params);
    }

    private function applyNamespace(string $key): string
    {
        foreach ($this->prefixVersions as $p => $ver) {
            if ($p !== '' && str_starts_with($key, $p)) {
                return $p . $ver . '|' . substr($key, strlen($p));
            }
        }
        if ($this->useSharedPrefix) {
            // Lazy resolve shared version (with small TTL) without a dedicated prefix list.
            foreach ($this->detectPrefixes($key) as $p) {
                $ver = $this->getSharedPrefixVersion($p);
                if ($ver !== null && $ver > 0) {
                    $this->prefixVersions[$p] = $ver;
                    if (str_starts_with($key, $p)) {
                        return $p . $ver . '|' . substr($key, strlen($p));
                    }
                }
            }
        }
        return $key;
    }

    /** Heuristic prefix discovery – without explicit hints returns known local prefixes. */
    private function detectPrefixes(string $fullKey): array
    {
        // If you use keyWithPrefix("users:"...), detection works immediately.
        // Otherwise it only returns prefixes seen via invalidatePrefix().
        return array_keys($this->prefixVersions);
    }

    private function getSharedPrefixVersion(string $prefix): ?int
    {
        $now = time();
        $last = $this->sharedPrefixLastFetch[$prefix] ?? 0;
        if (($now - $last) < $this->sharedPrefixRefreshSec) {
            return $this->prefixVersions[$prefix] ?? null;
        }
        try {
            $v = $this->cache->get($this->sharedPrefixKey($prefix), null);
            if (is_int($v)) {
                $this->prefixVersions[$prefix] = $v;
                $this->sharedPrefixLastFetch[$prefix] = $now;
                return $v;
            }
        } catch (\Throwable $e) {
            $this->logger?->warning('QueryCache getSharedPrefixVersion failed', ['prefix'=>$prefix, 'e'=>$e]);
        }
        $this->sharedPrefixLastFetch[$prefix] = $now;
        return $this->prefixVersions[$prefix] ?? null;
    }

    /** NEW: explicit prefix registration (eager sync of shared version if enabled). */
    public function registerPrefix(string $prefix): void
    {
        if ($prefix === '') return;
        if (!array_key_exists($prefix, $this->prefixVersions)) {
            $ver = $this->useSharedPrefix ? ($this->getSharedPrefixVersion($prefix) ?? 0) : 0;
            $this->prefixVersions[$prefix] = $ver;
            $this->sharedPrefixLastFetch[$prefix] = time();
        }
    }

    // More robust parameter serialization for key derivation + PSR-16 friendly key shape.
    public function key(string $dbId, string $sql, array $params = []): string
    {
        /**
         * PSR-16 safe key contract:
         * - namespace/dbId segments are normalized to [A-Za-z0-9._-] + a short hash suffix
         * - final form is "<ns>|<db>|<sha256>"
         */
        $blob = $dbId . '|' . $sql . '|' . $this->encodeParams($params);
        $h = hash('sha256', $blob);
        $ns = $this->normalizeSegment($this->namespace, 'ns');
        $db = $this->normalizeSegment($dbId, 'db');
        // Pipes used to avoid caches that treat ':' specially
        return "{$ns}|{$db}|{$h}";
    }

    // Safe parameter encoding for the key
    private function encodeParams(array $params): string
    {
        try {
            return json_encode($params, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
        } catch (\Throwable $e) {
            $this->logger?->notice('QueryCache json_encode failed, using serialize()', ['e'=>$e]);
            // serialize() is OK for keys (we hash it), even if it is not stable across PHP versions.
            return serialize($params);
        }
    }

    // TTL normalization (negative => 0 = no-store; null = unchanged)
    private function normalizeTtl(int|\DateInterval|null $ttl): int|\DateInterval|null
    {
        if (is_int($ttl)) {
            return $ttl <= 0 ? 0 : $ttl;
        }
        return $ttl;
    }

    // Jitter helper (aliases kept for merged patches compatibility)
    private function jitterTtl(int $ttl): int
    {
        if ($this->ttlJitterPercent <= 0 || $ttl <= 1) return $ttl;
        $amp = (int)floor($ttl * $this->ttlJitterPercent / 100);
        $j   = ($amp > 0) ? random_int(-$amp, $amp) : 0;
        return max(1, $ttl + $j);
    }

    // Internal helper with backoff (exponential-ish + jitter)
    private function backoffSleep(int $attempt): void
    {
        $min = $this->lockRetryMinMs;
        $max = $this->lockRetryMaxMs;
        $base = min($max, $min * (1 << max(0, $attempt - 1)));
        $jitter = random_int(0, (int)floor($base * 0.25));
        usleep(($base + $jitter) * 1000);
    }

    /** NEW: normalize a segment (namespace/dbId) to safe chars + hash suffix. */
    private function normalizeSegment(string $raw, string $fallback): string
    {
        $s = trim($raw);
        if ($s === '') $s = $fallback;
        $safe = preg_replace('~[^A-Za-z0-9._-]+~', '-', $s) ?? $s;
        $safe = trim($safe, '-_.');
        $h = substr(hash('sha1', $s), 0, 6);
        return ($safe === '' ? $fallback : $safe) . '.' . $h;
    }

    /** NEW: apply namespace/prefix version + length guard; returns the final cache key. */
    private function safeNsKey(string $key): string
    {
        $nsKey = $this->applyNamespace($key);
        if ($this->maxKeyLength > 0 && strlen($nsKey) > $this->maxKeyLength) {
            $ns = $this->normalizeSegment($this->namespace, 'ns');
            return $ns . '|H|' . hash('sha256', $nsKey);
        }
        return $nsKey;
    }

    /**
     * Compute-if-absent with (optional) locking.
     * $producer = fn(): mixed { ... }  // read-only.
     */
    public function remember(string $key, int|\DateInterval|null $ttl, callable $producer): mixed
    {
        $nsKey = $this->safeNsKey($key);

        // Fast path – simple read
        try {
            $hit = $this->cache->get($nsKey, '__MISS__');
            if ($hit !== '__MISS__') { $this->hits++; return $hit; }
        } catch (\Throwable $e) {
            $this->logger?->warning('QueryCache get failed', ['e'=>$e]);
        }

        $this->miss++;

        $ttl = $this->normalizeTtl($ttl);
        if (is_int($ttl) && $ttl > 0) { $ttl = $this->jitterTtl($ttl); }
        $lockName = 'q:' . $nsKey;
        $token = null;
        $locks = $this->locks;

        try {
            $deadline = microtime(true) + $this->lockWaitSec;

            if ($locks !== null) {
                $attempt = 0;
                // Try to acquire the lock non-blocking; if not, re-check cache with backoff.
                do {
                    $token = $locks->acquireLock($lockName, $this->lockWaitSec);
                    if ($token !== null) { $this->lockAcquired++; break; }

                    // Someone else is computing -> exponential backoff + re-check
                    $this->backoffSleep(++$attempt);
                    try {
                        $hit = $this->cache->get($nsKey, '__MISS__');
                        if ($hit !== '__MISS__') { $this->hits++; return $hit; }
                    } catch (\Throwable $e) {
                        $this->logger?->warning('QueryCache get during lock-wait failed', ['e'=>$e]);
                    }
                } while (microtime(true) < $deadline);

                // If lock is still not acquired: last attempt — re-read cache (else fallback to computing without lock).
                if ($token === null) {
                    $this->lockWaitTimeouts++;
                    try {
                        $hit = $this->cache->get($nsKey, '__MISS__');
                        if ($hit !== '__MISS__') { $this->hits++; return $hit; }
                    } catch (\Throwable $_) {}
                }
            }

            // Produce
            $this->producerRuns++;
            $val = $producer();

            try { $this->cache->set($nsKey, $val, $ttl); }
            catch (\Throwable $e) { $this->logger?->warning('QueryCache set failed', ['e'=>$e]); }

            return $val;
        } finally {
            if ($token !== null) {
                try { $locks?->releaseLock($lockName, $token); } catch (\Throwable $_) {}
            }
        }
    }

    /** Helper for common SELECTs. */
    public function rememberRows(Database $db, string $sql, array $params, int|\DateInterval|null $ttl): array
    {
        $key = $this->key($db->id(), $sql, $params);
        return $this->remember($key, $ttl, fn() => $db->fetchAll($sql, $params));
    }

    /** Same as rememberRows(), but with an app prefix for easier invalidation. */
    public function rememberRowsP(Database $db, string $prefix, string $sql, array $params, int|\DateInterval|null $ttl): array
    {
        $key = $this->keyWithPrefix($prefix, $db->id(), $sql, $params);
        return $this->remember($key, $ttl, fn() => $db->fetchAll($sql, $params));
    }

    /** Convenience – cache SELECT ... LIMIT 1 (row). */
    public function rememberRow(Database $db, string $sql, array $params, int|\DateInterval|null $ttl): ?array
    {
        $k = $this->key($db->id(), $sql, $params);
        return $this->remember($k, $ttl, fn()=> $db->fetch($sql, $params));
    }
    /** Convenience – cache a scalar value. */
    public function rememberValue(Database $db, string $sql, array $params, int|\DateInterval|null $ttl, mixed $default = null): mixed
    {
        $k = $this->key($db->id(), $sql, $params);
        return $this->remember($k, $ttl, fn()=> $db->fetchValue($sql, $params, $default));
    }
    /** Convenience – cache EXISTS(...) */
    public function rememberExists(Database $db, string $sql, array $params, int|\DateInterval|null $ttl): bool
    {
        $k = $this->key($db->id(), $sql, $params);
        return (bool)$this->remember($k, $ttl, fn()=> $db->exists($sql, $params));
    }

    /** Practical bulk API: load multiple keys at once; compute missing values.
     *  - Uses PSR-16 getMultiple() and (when no locks are configured) also setMultiple() for faster writes.
     *  - With locks enabled, preserves per-key remember() (correct synchronization).
     */
    public function rememberMultiple(array $keys, int|\DateInterval|null $ttl, callable $producer): array
    {
        if ($keys === []) return [];
        // Normalize input keys to strings (stable diff/compare).
        $origKeys = array_values(array_map('strval', $keys));

        // map original -> nsKey (prefix verze + guard)
        $map = [];
        foreach ($origKeys as $k) { $map[$k] = $this->safeNsKey($k); }

        $values = [];
        try {
            $fetched = $this->cache->getMultiple(array_values($map), '__MISS__');
            $arr = is_array($fetched)
                ? $fetched
                : (is_iterable($fetched) ? iterator_to_array($fetched) : []);
            foreach ($map as $orig => $nsKey) {
                $v = $arr[$nsKey] ?? '__MISS__';
                if ($v !== '__MISS__') { $values[$orig] = $v; }
            }
        } catch (\Throwable $e) {
            $this->logger?->warning('QueryCache getMultiple failed', ['e'=>$e]);
        }
        $this->hits += count($values);

        $missKeys = array_values(array_diff($origKeys, array_keys($values)));
        if ($missKeys === []) return $values;

        // Normalize/jitter TTL for batch writes (no-lock path).
        $ttlN = $this->normalizeTtl($ttl);
        if (is_int($ttlN) && $ttlN > 0) { $ttlN = $this->jitterTtl($ttlN); }

        if ($this->locks === null) {
            // FAST-PATH without locks: compute and setMultiple() in one go.
            $writes = [];
            foreach ($missKeys as $k) {
                $this->producerRuns++;
                $val = $producer($k);
                $writes[$map[$k]] = $val;
                $values[$k] = $val;
            }
            try { $this->cache->setMultiple($writes, $ttlN); }
            catch (\Throwable $e) { $this->logger?->warning('QueryCache setMultiple failed', ['e'=>$e]); }
            // Miss metrics are incremented only here (per-key path is handled by remember()).
            $this->miss += count($missKeys);
        } else {
            // LOCKED PATH: preserve per-key remember() (correct locking + metrics)
            foreach ($missKeys as $k) {
                $values[$k] = $this->remember($k, $ttl, fn()=> $producer($k));
            }
        }
        return $values;
    }

    /** Changes the logical namespace (e.g. to invalidate all previous keys). */
    public function newNamespace(string $ns): void
    {
        $this->namespace = $ns;
        // Clear local prefix versions so they don't leak into the new namespace.
        $this->prefixVersions = [];
        $this->sharedPrefixLastFetch = [];
    }

    public function cache(): CacheInterface { return $this->cache; }
    public function locks(): ?LockingCacheInterface { return $this->locks; }

    public function delete(string $key): void
    {
        try { $this->cache->delete($this->safeNsKey($key)); } catch (\Throwable $_) {}
    }

    /**
     * Stale-While-Revalidate:
     * - on a "stale hit" returns the stale value immediately
     * - refresh runs in only one process (when locks are available)
     */
    public function rememberSWR(string $key, int $ttl, int $staleTtl, callable $producer): mixed
    {
        $nsKey = $this->safeNsKey($key);
        $ttl = $this->normalizeTtl($ttl) ?? 0;
        if (is_int($ttl) && $ttl > 0) { $ttl = $this->jitterTtl($ttl); }
        $staleTtl = $this->jitterTtl($staleTtl);

        try {
            $val = $this->cache->get($nsKey, '__MISS__');
            if ($val !== '__MISS__') { return $val; }
        } catch (\Throwable $e) { $this->logger?->warning('SWR get failed',['e'=>$e]); }

        // attempt stale
        try {
            $stale = $this->cache->get($nsKey.':stale', '__MISS__');
            if ($stale !== '__MISS__') {
                $this->staleHits++;
                // Fire-and-forget refresh (when locks are not available it may run multiple times – acceptable).
                $refresh = function() use ($nsKey, $producer, $ttl, $staleTtl) {
                    try {
                        $this->producerRuns++;
                        $fresh = $producer();
                        $this->cache->set($nsKey, $fresh, $ttl);
                        $this->cache->set($nsKey.':stale', $fresh, $staleTtl);
                    } catch (\Throwable $e) {
                        $this->logger?->warning('SWR refresh failed',['e'=>$e]);
                    }
                };

                if ($this->locks) {
                    $tok = $this->locks->acquireLock('q:swr:' . $nsKey, 5);
                    if ($tok !== null) {
                        try { $refresh(); }
                        finally { $this->locks->releaseLock('q:swr:' . $nsKey, $tok); }
                    }
                } else {
                    // Without locks: just run it.
                    $refresh();
                }

                return $stale;
            }
        } catch (\Throwable $_) {}

        // Produce fresh synchronously.
        $this->producerRuns++;
        $fresh = $producer();
        try {
            $this->cache->set($nsKey, $fresh, $ttl);
            $this->cache->set($nsKey.':stale', $fresh, $staleTtl);
        } catch (\Throwable $e) {
            $this->logger?->warning('SWR set failed',['e'=>$e]);
        }
        return $fresh;
    }
}
