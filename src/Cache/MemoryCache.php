<?php
declare(strict_types=1);

namespace BlackCat\Core\Cache;

use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException as PsrInvalidArgument;

/**
 * In-memory PSR-16 cache (per-process).
 * - Optional LRU eviction via maxItems (protects long-running workers).
 * - TTL in seconds or DateInterval; TTL<=0 => no-store (entry is not stored).
 * - Expiration happens "on-read" and also eagerly before LRU eviction (pruneExpired()).
 * - Test helper: setNowSkew(+/- seconds) to simulate time.
 *
 * Security:
 * - PSR-16 key guard: non-empty string without {}()/\@:
 * - getMultiple/setMultiple/deleteMultiple validate keys per PSR-16.
 */
final class MemoryCache implements CacheInterface
{
    /** @var array<string, array{v:mixed, t:?int, a:int}> key => ['v'=>value, 't'=>expirationUnixTs|null, 'a'=>lastAccessSeq] */
    private array $store = [];

    /** Max items (LRU); null = unlimited. */
    private ?int $maxItems;

    /** Internal time skew (tests only). */
    private int $nowSkew = 0;

    /** Monotonic access sequence (for LRU even with identical timestamps). */
    private int $accessSeq = 0;

    public function __construct(?int $maxItems = null)
    {
        $this->maxItems = ($maxItems !== null && $maxItems > 0) ? $maxItems : null;
    }

    /** Test helper – shifts internal time by +/- seconds. */
    public function setNowSkew(int $seconds): void
    {
        $this->nowSkew = $seconds;
    }

    /** Alias for older codebases (same as setNowSkew). */
    public function setNowSkewForTests(int $seconds): void
    {
        $this->setNowSkew($seconds);
    }

    /** Number of currently stored (non-expired) items – for tests/diagnostics. */
    public function debugCount(): int
    {
        $this->pruneExpired();
        return count($this->store);
    }

    private function now(): int
    {
        return time() + $this->nowSkew;
    }

    /** 
     * Materializes the key list (preserves order) — protects against double-iterating
     * generators in getMultiple()/deleteMultiple().
     * @param iterable<mixed> $keys
     * @return array<int,string>
     * @throws InvalidKeyException
     */
    private function toKeyList(iterable $keys): array
    {
        $list = [];
        foreach ($keys as $k) {
            $list[] = $k;
        }
        return $list;
    }

    // ---- PSR-16 compliance helpers ------------------------------------------------------------

    /** @throws InvalidKeyException */
    private function assertValidKey(mixed $key): void
    {
        if (!is_string($key) || $key === '') {
            throw new InvalidKeyException('Cache key must be a non-empty string.');
        }
        // PSR-16 reserved characters: {}()/\@:
        if (preg_match('/[{}()\/\\\\@:]/', $key)) {
            throw new InvalidKeyException('Cache key contains reserved characters: {}()/\\@:.');
        }
    }

    /**
     * @param iterable<mixed> $keys
     * @throws InvalidKeyException
     */
    private function assertValidKeys(iterable $keys): void
    {
        foreach ($keys as $k) {
            $this->assertValidKey($k);
        }
    }

    /** @return ?int unix timestamp, null = no expiration, 0 = "no-store" */
    private function ttlToExpiration(int|\DateInterval|null $ttl): ?int
    {
        if ($ttl === null) return null;
        if (is_int($ttl)) {
            if ($ttl <= 0) return 0;                // no-store
            return $this->now() + $ttl;
        }
        // DateInterval: compute relative to "now"
        $base = (new \DateTimeImmutable('@'.$this->now()))->setTimezone(new \DateTimeZone('UTC'));
        return $base->add($ttl)->getTimestamp();
    }

    /** Remove expired items (eager) — called before LRU eviction and in debugCount(). */
    private function pruneExpired(): void
    {
        $now = $this->now();
        foreach ($this->store as $k => $e) {
            $t = $e['t'];
            if ($t !== null && $t < $now) {
                unset($this->store[$k]);
            }
        }
    }

    private function evictOneLru(): void
    {
        $lruKey = null;
        $lruTs  = PHP_INT_MAX;
        foreach ($this->store as $k => $meta) {
            if (isset($meta['a']) && $meta['a'] < $lruTs) {
                $lruTs  = $meta['a'];
                $lruKey = $k;
            }
        }
        // Fallback to the first key — but only after trying to account for "hit" keys.
        $victim = $lruKey ?? array_key_first($this->store);
        if ($victim !== null) {
            unset($this->store[$victim]);
        }
    }

    private function evictIfNeeded(): void
    {
        if ($this->maxItems === null) return;

        // First remove expired entries so LRU doesn't evict valid data unnecessarily.
        $this->pruneExpired();

        while (count($this->store) > $this->maxItems && !empty($this->store)) {
            $this->evictOneLru();
        }
    }

    // ---- PSR-16 interface ---------------------------------------------------------------------

    /** @inheritdoc */
    public function get(string $key, mixed $default = null): mixed
    {
        $this->assertValidKey($key);
        $e = $this->store[$key] ?? null;
        if ($e === null) return $default;

        $now = $this->now();
        if ($e['t'] !== null && $e['t'] < $now) {
            unset($this->store[$key]);
            return $default;
        }

        // Hit – touch last-access (monotonic order)
        $this->store[$key]['a'] = ++$this->accessSeq;
        return $e['v'];
    }

    /** @inheritdoc */
    public function set(string $key, mixed $value, int|\DateInterval|null $ttl = null): bool
    {
        $this->assertValidKey($key);
        $this->pruneExpired();
        $exp = $this->ttlToExpiration($ttl);

        // TTL<=0 => no-store (PSR allows a "successful drop"; we return true)
        if ($exp === 0) {
            unset($this->store[$key]);
            return true;
        }

        if ($this->maxItems !== null && count($this->store) >= $this->maxItems) {
            $this->evictOneLru();
        }

        $this->store[$key] = ['v' => $value, 't' => $exp, 'a' => ++$this->accessSeq];
        $this->evictIfNeeded();
        return true;
    }

    /** @inheritdoc */
    public function delete(string $key): bool
    {
        $this->assertValidKey($key);
        unset($this->store[$key]);
        return true;
    }

    /** @inheritdoc */
    public function clear(): bool
    {
        $this->store = [];
        return true;
    }

    /** @inheritdoc */
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        if (!is_iterable($keys)) {
            throw new InvalidKeyException('getMultiple() expects iterable of keys.');
        }
        $list = $this->toKeyList($keys);
        $this->assertValidKeys($list);

        $out = [];
        foreach ($list as $k) {
            $out[$k] = $this->get($k, $default);
        }
        return $out;
    }

    /** @inheritdoc */
    public function setMultiple(iterable $values, int|\DateInterval|null $ttl = null): bool
    {
        if (!is_iterable($values)) {
            throw new InvalidKeyException('setMultiple() expects iterable of key => value.');
        }

        // Materialize once (generators) and validate all keys before writing.
        $items = is_array($values) ? $values : iterator_to_array($values, true);
        foreach (array_keys($items) as $k) {
            $this->assertValidKey($k);
        }

        $ok = true;
        foreach ($items as $k => $v) {
            $ok = $this->set($k, $v, $ttl) && $ok;
        }
        return $ok;
    }

    /** @inheritdoc */
    public function deleteMultiple(iterable $keys): bool
    {
        if (!is_iterable($keys)) {
            throw new InvalidKeyException('deleteMultiple() expects iterable of keys.');
        }
        $list = $this->toKeyList($keys);
        $this->assertValidKeys($list);

        foreach ($list as $k) {
            unset($this->store[$k]);
        }
        return true;
    }

    /** @inheritdoc */
    public function has(string $key): bool
    {
        $this->assertValidKey($key);
        $e = $this->store[$key] ?? null;
        if ($e === null) return false;

        $now = $this->now();
        if ($e['t'] !== null && $e['t'] < $now) {
            unset($this->store[$key]);
            return false;
        }
        return true;
    }
}

/**
 * Local InvalidArgumentException that implements the PSR-16 interface.
 */
final class InvalidKeyException extends \InvalidArgumentException implements PsrInvalidArgument {}
