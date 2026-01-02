<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel;

use BlackCat\Core\TrustKernel\TrustKernel;
use BlackCat\Core\TrustKernel\TrustKernelConfig;
use PHPUnit\Framework\TestCase;

final class TrustKernelFileCacheHardeningTest extends TestCase
{
    private static function waitForNextSecond(): void
    {
        $start = time();
        while (time() === $start) {
            usleep(50_000);
        }
    }

    public function testComposerLockCacheInvalidatesWhenContentChangesEvenIfMtimeAndSizeArePreserved(): void
    {
        $tmp = rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'blackcat-core-' . bin2hex(random_bytes(8));
        self::assertTrue(@mkdir($tmp, 0700, true) || is_dir($tmp), 'Failed to create tmp dir.');

        $composerLockPath = $tmp . DIRECTORY_SEPARATOR . 'composer.lock';
        $manifestPath = $tmp . DIRECTORY_SEPARATOR . 'manifest.json';

        try {
            file_put_contents($composerLockPath, '{"a":1}');
            file_put_contents($manifestPath, '{}');

            $cfg = new TrustKernelConfig(
                chainId: 4207,
                rpcEndpoints: ['https://a', 'https://b'],
                rpcQuorum: 1,
                maxStaleSec: 60,
                mode: 'root_uri',
                instanceController: '0x1111111111111111111111111111111111111111',
                releaseRegistry: null,
                integrityRootDir: $tmp,
                integrityManifestPath: $manifestPath,
                rpcTimeoutSec: 1,
                imageDigestFilePath: $tmp . DIRECTORY_SEPARATOR . 'image.digest',
            );

            $kernel = new TrustKernel($cfg);
            $method = new \ReflectionMethod(TrustKernel::class, 'computeComposerLockSha256Bytes32OrThrow');
            $method->setAccessible(true);

            /** @var string $sha1 */
            $sha1 = $method->invoke($kernel);

            clearstatcache(true, $composerLockPath);
            $mtime1 = @filemtime($composerLockPath);
            $size1 = @filesize($composerLockPath);
            $ctime1 = @filectime($composerLockPath);
            self::assertIsInt($mtime1, 'Expected filemtime to be available.');
            self::assertIsInt($size1, 'Expected filesize to be available.');
            self::assertIsInt($ctime1, 'Expected filectime to be available.');

            // Tamper: keep the same size and restore the original mtime to simulate an attacker
            // trying to bypass mtime/size-only invalidation.
            self::waitForNextSecond();
            file_put_contents($composerLockPath, '{"a":2}');
            touch($composerLockPath, $mtime1);

            clearstatcache(true, $composerLockPath);
            $mtime2 = @filemtime($composerLockPath);
            $size2 = @filesize($composerLockPath);
            $ctime2 = @filectime($composerLockPath);
            self::assertIsInt($mtime2, 'Expected filemtime to be available (after tamper).');
            self::assertIsInt($size2, 'Expected filesize to be available (after tamper).');
            self::assertIsInt($ctime2, 'Expected filectime to be available (after tamper).');

            self::assertSame($mtime1, $mtime2, 'Test setup failed: mtime was not preserved.');
            self::assertSame($size1, $size2, 'Test setup failed: size was not preserved.');
            if ($ctime1 === $ctime2) {
                self::markTestSkipped('filectime did not change on content modification; cannot assert tamper invalidation on this platform.');
            }

            /** @var string $sha2 */
            $sha2 = $method->invoke($kernel);

            self::assertNotSame($sha1, $sha2, 'Expected cache invalidation when composer.lock content changes (even if mtime/size are preserved).');
        } finally {
            @unlink($composerLockPath);
            @unlink($manifestPath);
            @rmdir($tmp);
        }
    }

    public function testImageDigestCacheInvalidatesWhenContentChangesEvenIfMtimeAndSizeArePreserved(): void
    {
        $tmp = rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'blackcat-core-' . bin2hex(random_bytes(8));
        self::assertTrue(@mkdir($tmp, 0700, true) || is_dir($tmp), 'Failed to create tmp dir.');

        $composerLockPath = $tmp . DIRECTORY_SEPARATOR . 'composer.lock';
        $manifestPath = $tmp . DIRECTORY_SEPARATOR . 'manifest.json';
        $imageDigestPath = $tmp . DIRECTORY_SEPARATOR . 'image.digest';

        try {
            file_put_contents($composerLockPath, '{"a":1}');
            file_put_contents($manifestPath, '{}');
            file_put_contents($imageDigestPath, str_repeat('a', 64));

            $cfg = new TrustKernelConfig(
                chainId: 4207,
                rpcEndpoints: ['https://a', 'https://b'],
                rpcQuorum: 1,
                maxStaleSec: 60,
                mode: 'root_uri',
                instanceController: '0x1111111111111111111111111111111111111111',
                releaseRegistry: null,
                integrityRootDir: $tmp,
                integrityManifestPath: $manifestPath,
                rpcTimeoutSec: 1,
                imageDigestFilePath: $imageDigestPath,
            );

            $kernel = new TrustKernel($cfg);
            $method = new \ReflectionMethod(TrustKernel::class, 'readImageDigestSha256Bytes32OrThrow');
            $method->setAccessible(true);

            /** @var string $d1 */
            $d1 = $method->invoke($kernel);

            clearstatcache(true, $imageDigestPath);
            $mtime1 = @filemtime($imageDigestPath);
            $size1 = @filesize($imageDigestPath);
            $ctime1 = @filectime($imageDigestPath);
            self::assertIsInt($mtime1, 'Expected filemtime to be available.');
            self::assertIsInt($size1, 'Expected filesize to be available.');
            self::assertIsInt($ctime1, 'Expected filectime to be available.');

            self::waitForNextSecond();
            file_put_contents($imageDigestPath, str_repeat('a', 63) . 'b');
            touch($imageDigestPath, $mtime1);

            clearstatcache(true, $imageDigestPath);
            $mtime2 = @filemtime($imageDigestPath);
            $size2 = @filesize($imageDigestPath);
            $ctime2 = @filectime($imageDigestPath);
            self::assertIsInt($mtime2, 'Expected filemtime to be available (after tamper).');
            self::assertIsInt($size2, 'Expected filesize to be available (after tamper).');
            self::assertIsInt($ctime2, 'Expected filectime to be available (after tamper).');

            self::assertSame($mtime1, $mtime2, 'Test setup failed: mtime was not preserved.');
            self::assertSame($size1, $size2, 'Test setup failed: size was not preserved.');
            if ($ctime1 === $ctime2) {
                self::markTestSkipped('filectime did not change on content modification; cannot assert tamper invalidation on this platform.');
            }

            /** @var string $d2 */
            $d2 = $method->invoke($kernel);

            self::assertNotSame($d1, $d2, 'Expected cache invalidation when image.digest content changes (even if mtime/size are preserved).');
        } finally {
            @unlink($composerLockPath);
            @unlink($manifestPath);
            @unlink($imageDigestPath);
            @rmdir($tmp);
        }
    }
}
