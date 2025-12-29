<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\Cache;

use BlackCat\Core\Cache\FileCache;
use PHPUnit\Framework\TestCase;

final class FileCacheSymlinkAttackTest extends TestCase
{
    public function testGetDoesNotFollowSymlinkOutsideCacheDir(): void
    {
        if (!function_exists('symlink')) {
            self::markTestSkipped('symlink() is not available.');
        }

        $cacheDir = sys_get_temp_dir() . '/blackcat-core-cache-' . bin2hex(random_bytes(6));
        mkdir($cacheDir, 0700, true);

        $outside = tempnam(sys_get_temp_dir(), 'blackcat-outside-');
        if (!is_string($outside)) {
            self::markTestSkipped('tempnam failed.');
        }
        file_put_contents($outside, 'SECRET');

        try {
            $cache = new FileCache($cacheDir, false, null, 'CACHE_CRYPTO_KEY', 'cache_crypto', 0);
            $key = 'example_key';

            $m = new \ReflectionMethod(FileCache::class, 'getPath');
            $m->setAccessible(true);
            /** @var string $cacheFile */
            $cacheFile = $m->invoke($cache, $key);

            @unlink($cacheFile);
            if (!@symlink($outside, $cacheFile)) {
                self::markTestSkipped('symlink creation failed (filesystem may not support it).');
            }

            $v = $cache->get($key, 'DEFAULT');
            self::assertSame('DEFAULT', $v);
        } finally {
            @unlink($outside);
            foreach (glob($cacheDir . DIRECTORY_SEPARATOR . '*') ?: [] as $f) {
                @unlink($f);
            }
            @rmdir($cacheDir);
        }
    }
}

