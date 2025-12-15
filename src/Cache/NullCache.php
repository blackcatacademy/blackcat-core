<?php
declare(strict_types=1);

namespace BlackCat\Core\Cache;

use Psr\SimpleCache\CacheInterface;

/**
 * No-op PSR-16 cache (useful for tests/feature flags).
 */
final class NullCache implements CacheInterface
{
    public function get($key, $default = null): mixed
    {
        return $default;
    }

    public function set($key, $value, $ttl = null): bool
    {
        return true;
    }

    public function delete($key): bool
    {
        return true;
    }

    public function clear(): bool
    {
        return true;
    }

    public function getMultiple($keys, $default = null): iterable
    {
        $out = [];
        foreach ($keys as $k) {
            $out[$k] = $default;
        }
        return $out;
    }

    public function setMultiple($values, $ttl = null): bool
    {
        return true;
    }

    public function deleteMultiple($keys): bool
    {
        return true;
    }

    public function has($key): bool
    {
        return false;
    }
}
