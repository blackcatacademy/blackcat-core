<?php
declare(strict_types=1);

namespace BlackCat\Core\Cache;

use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException as PsrInvalidArgument;

/**
 * In-memory PSR-16 cache (per-process).
 * - Volitelná LRU evikce přes maxItems (chrání dlouho běžící workery).
 * - TTL v sekundách nebo DateInterval; TTL<=0 => no-store (záznam se neuloží).
 * - Expirace se provádí „on-read“ a také eager před LRU evikcí (pruneExpired()).
 * - Test helper: setNowSkew(+/- sekundy) pro simulaci času.
 *
 * Bezpečnost:
 * - PSR-16 key guard: string, neprázdné, bez {}()/\@:
 * - getMultiple/setMultiple/deleteMultiple validují klíče dle PSR-16.
 */
final class MemoryCache implements CacheInterface
{
    /** @var array<string, array{v:mixed, t:?int, a:int}> key => ['v'=>value, 't'=>expirationUnixTs|null, 'a'=>lastAccessSeq] */
    private array $store = [];

    /** Max. počet položek (LRU); null = neomezené. */
    private ?int $maxItems;

    /** Posun interního „času“ (jen pro testy). */
    private int $nowSkew = 0;

    /** Monotónní pořadí přístupů (pro LRU i při stejném timestampu). */
    private int $accessSeq = 0;

    public function __construct(?int $maxItems = null)
    {
        $this->maxItems = ($maxItems !== null && $maxItems > 0) ? $maxItems : null;
    }

    /** Test helper – posune interní čas o +/- sekundy. */
    public function setNowSkew(int $seconds): void
    {
        $this->nowSkew = $seconds;
    }

    /** @deprecated Použij setNowSkew(); alias kvůli zpětné kompatibilitě. */
    public function setNowSkewForTests(int $seconds): void
    {
        $this->setNowSkew($seconds);
    }

    /** Počet aktuálně uložených (neexpirovaných) položek – pro testy/diagnostiku. */
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
     * Materializuje seznam klíčů (zachová pořadí) – chrání před dvojnásobnou
     * iterací nad generátorem v getMultiple()/deleteMultiple().
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

    /** @return ?int unix timestamp, null = bez expirace, 0 = „no-store“ */
    private function ttlToExpiration(int|\DateInterval|null $ttl): ?int
    {
        if ($ttl === null) return null;
        if (is_int($ttl)) {
            if ($ttl <= 0) return 0;                // no-store
            return $this->now() + $ttl;
        }
        // DateInterval: přepočet vůči "teď"
        $base = (new \DateTimeImmutable('@'.$this->now()))->setTimezone(new \DateTimeZone('UTC'));
        return $base->add($ttl)->getTimestamp();
    }

    /** Odstraní expirované položky (eager) – volá se před LRU evikcí a u debugCount(). */
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
        // fallback na první klíč – ale až po tom, co zkusíme zohlednit „hitnuté“ klíče
        $victim = $lruKey ?? array_key_first($this->store);
        if ($victim !== null) {
            unset($this->store[$victim]);
        }
    }

    private function evictIfNeeded(): void
    {
        if ($this->maxItems === null) return;

        // Nejdřív smaž zjevně expirované, ať LRU zbytečně nekope platná data.
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

        // Hit – touch last-access (monotónní pořadí)
        $this->store[$key]['a'] = ++$this->accessSeq;
        return $e['v'];
    }

    /** @inheritdoc */
    public function set(string $key, mixed $value, int|\DateInterval|null $ttl = null): bool
    {
        $this->assertValidKey($key);
        $this->pruneExpired();
        $exp = $this->ttlToExpiration($ttl);

        // TTL<=0 => no-store (PSR povoluje „úspěšné zahození“; vracíme true)
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

        // Materializuj jednou (generátory) a validuj všechny klíče před zápisem
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
