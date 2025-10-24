<?php
declare(strict_types=1);

namespace BlackCat\Core\Database;

use BlackCat\Core\Database;
use Psr\SimpleCache\CacheInterface;
use Psr\Log\LoggerInterface;
use BlackCat\Core\Cache\LockingCacheInterface;

final class QueryCache
{
    public function __construct(
        private CacheInterface $cache,
        private ?LockingCacheInterface $locks = null,   // může být stejné jako $cache, když implementuje locking
        private ?LoggerInterface $logger = null,
        private string $namespace = 'dbq'
    ) {}

    public function key(string $dbId, string $sql, array $params = []): string
    {
        // stabilní serializace parametrů
        $blob = $dbId . '|' . $sql . '|' . json_encode($params, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
        $h = hash('sha256', $blob);
        return "{$this->namespace}:{$dbId}:" . $h;
    }

    /**
     * Compute-if-absent s (volitelným) zámkem proti thundering herd.
     * $producer = fn(): mixed { ... }  // měl by být read-only.
     */
    public function remember(string $key, int|\DateInterval|null $ttl, callable $producer): mixed
    {
        try {
            $hit = $this->cache->get($key, '__MISS__');
            if ($hit !== '__MISS__') return $hit;
        } catch (\Throwable $e) {
            $this->logger?->warning('QueryCache get failed', ['e'=>$e]);
        }

        $token = null;
        try {
            if ($this->locks) {
                $token = $this->locks->acquireLock('q:' . $key, 10);
                if ($token === null) {
                    // někdo jiný počítá → krátce počkej a zkus znovu
                    usleep(100 * 1000);
                    $hit = $this->cache->get($key, '__MISS__');
                    if ($hit !== '__MISS__') return $hit;
                }
            }

            $val = $producer();

            try { $this->cache->set($key, $val, $ttl); }
            catch (\Throwable $e) { $this->logger?->warning('QueryCache set failed', ['e'=>$e]); }

            return $val;
        } finally {
            if ($token !== null) {
                try { $this->locks?->releaseLock('q:' . $key, $token); } catch (\Throwable $_) {}
            }
        }
    }

    /** Pomocník pro běžné SELECTy */
    public function rememberRows(Database $db, string $sql, array $params, int|\DateInterval|null $ttl): array
    {
        $key = $this->key($db->id(), $sql, $params);
        return $this->remember($key, $ttl, fn() => $db->fetchAll($sql, $params));
    }

    /** Invalidace “namespaced” klíčů bez ne-standardních metod: otočíme namespace. */
    public function newNamespace(string $ns): void { $this->namespace = $ns; }
}
