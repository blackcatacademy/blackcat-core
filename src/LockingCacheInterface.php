<?php
declare(strict_types=1);

use Psr\SimpleCache\CacheInterface;

/**
 * LockingCacheInterface
 *
 * Extension of the PSR-16 CacheInterface that provides a small lock API
 * suitable for file-based or simple distributed cache implementations which
 * want to offer basic lock acquisition/release semantics.
 *
 * Notes:
 * - These methods are optional — a standard PSR-16 implementation does not
 *   have to implement them.
 * - acquireLock should return an opaque "token" string when the lock was
 *   successfully obtained, or null when the lock could not be acquired.
 * - releaseLock must be called with the same token that acquireLock returned.
 * - TTL is a recommended expiry for the lock; implementations should treat
 *   expired locks as stale and allow a reclaim attempt.
 *
 * Rationale: this tiny extension is useful when you need a simple synchronization
 * primitive (for example: token refresh coordination) but don't want to depend
 * on external lock providers. For multi-host production usage consider robust
 * providers (Redis, Zookeeper, or Symfony Lock).
 *
 * @internal Keep this in your libs/ directory or a small shared package.
 */
interface LockingCacheInterface extends CacheInterface
{
    /**
     * Attempt to acquire a lock with a given name and TTL.
     *
     * Implementations should perform an atomic acquisition (e.g. fopen('x')
     * on a lock file, or SET NX in Redis). On success, return an opaque token
     * that the caller must supply to releaseLock().
     *
     * If the lock is not available (held by another process), return null.
     * If the lock file exists but is stale (expired), an implementation may
     * remove it and retry acquiring once.
     *
     * IMPORTANT: acquireLock should not throw on common concurrency situations —
     * prefer returning null. Exceptions may be used for fatal errors (I/O,
     * permission issues).
     *
     * @param string $name       Lock name (prefer short, filesystem-safe UTF-8)
     * @param int    $ttlSeconds Lock expiration in seconds (minimum 1)
     * @return string|null       Opaque lock token on success, or null on failure
     */
    public function acquireLock(string $name, int $ttlSeconds = 10): ?string;

    /**
     * Release a previously acquired lock.
     *
     * Implementations should verify the provided token matches the one that
     * was stored at acquisition (use hash_equals when comparing) and only
     * remove the lock if it matches.
     *
     * Return true when the lock was released, false otherwise (token mismatch,
     * file already removed, etc.).
     *
     * @param string $name  Lock name (same value as passed to acquireLock)
     * @param string $token Token returned by acquireLock
     * @return bool         True on success (lock released), false otherwise
     */
    public function releaseLock(string $name, string $token): bool;
}