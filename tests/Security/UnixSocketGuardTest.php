<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\Security;

use BlackCat\Core\Security\UnixSocketGuard;
use PHPUnit\Framework\TestCase;

final class UnixSocketGuardTest extends TestCase
{
    public function testRejectsRelativePaths(): void
    {
        $this->expectException(\RuntimeException::class);
        UnixSocketGuard::assertSafeUnixSocketPath('secrets-agent.sock', UnixSocketGuard::defaultAllowedPrefixes());
    }

    public function testAcceptsPathUnderCustomAllowedPrefix(): void
    {
        $dir = sys_get_temp_dir() . '/blackcat-core-sock-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700, true);

        try {
            $prefix = rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
            $path = $dir . DIRECTORY_SEPARATOR . 'agent.sock';

            UnixSocketGuard::assertSafeUnixSocketPath($path, [$prefix]);
            self::assertTrue(true);
        } finally {
            @rmdir($dir);
        }
    }

    public function testRejectsSymlinkSocketPath(): void
    {
        if (!function_exists('symlink')) {
            self::markTestSkipped('symlink() is not available.');
        }

        $dir = sys_get_temp_dir() . '/blackcat-core-sock-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700, true);

        try {
            $prefix = rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
            $target = $dir . DIRECTORY_SEPARATOR . 'target.sock';
            file_put_contents($target, 'x');

            $link = $dir . DIRECTORY_SEPARATOR . 'agent.sock';
            if (!@symlink($target, $link)) {
                self::markTestSkipped('symlink creation failed (filesystem may not support it).');
            }

            $this->expectException(\RuntimeException::class);
            UnixSocketGuard::assertSafeUnixSocketPath($link, [$prefix]);
        } finally {
            foreach (glob($dir . DIRECTORY_SEPARATOR . '*') ?: [] as $f) {
                @unlink($f);
            }
            @rmdir($dir);
        }
    }
}

