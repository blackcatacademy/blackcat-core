<?php
declare(strict_types=1);

namespace BlackCat\Core\Tests\Security;

use BlackCat\Core\Security\KeyManager;
use PHPUnit\Framework\TestCase;

final class KeyManagerTest extends TestCase
{
    public function testListKeyVersionsSortsNumerically(): void
    {
        $dir = sys_get_temp_dir() . '/blackcat-core-tests-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700, true);

        try {
            file_put_contents($dir . '/app_salt_v10.key', 'x');
            file_put_contents($dir . '/app_salt_v2.key', 'x');
            file_put_contents($dir . '/app_salt_v1.key', 'x');

            $list = KeyManager::listKeyVersions($dir, 'app_salt');

            self::assertSame(['v1', 'v2', 'v10'], array_keys($list));
        } finally {
            foreach (glob($dir . '/*') ?: [] as $f) {
                @unlink($f);
            }
            @rmdir($dir);
        }
    }

    public function testListKeyVersionsSkipsSymlinks(): void
    {
        if (!function_exists('symlink')) {
            self::markTestSkipped('symlink() is not available.');
        }

        $dir = sys_get_temp_dir() . '/blackcat-core-tests-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700, true);

        try {
            file_put_contents($dir . '/app_salt_v1.key', str_repeat('x', 32));

            $target = $dir . '/app_salt_v1.key';
            $link = $dir . '/app_salt_v2.key';
            if (!@symlink($target, $link)) {
                self::markTestSkipped('symlink creation failed (filesystem may not support it).');
            }

            $list = KeyManager::listKeyVersions($dir, 'app_salt');

            self::assertSame(['v1'], array_keys($list));
        } finally {
            foreach (glob($dir . '/*') ?: [] as $f) {
                @unlink($f);
            }
            @rmdir($dir);
        }
    }

    public function testRotateKeyRefusesSymlinkTargetFile(): void
    {
        if (!function_exists('symlink')) {
            self::markTestSkipped('symlink() is not available.');
        }

        $dir = sys_get_temp_dir() . '/blackcat-core-keymgr-rotate-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700, true);

        $outside = tempnam(sys_get_temp_dir(), 'blackcat-keymgr-outside-');
        if (!is_string($outside)) {
            self::markTestSkipped('tempnam failed.');
        }
        file_put_contents($outside, 'X');

        $target = $dir . '/app_salt_v1.key';
        if (!@symlink($outside, $target)) {
            self::markTestSkipped('symlink creation failed (filesystem may not support it).');
        }

        try {
            $this->expectException(\RuntimeException::class);
            KeyManager::rotateKey('app_salt', $dir);
        } finally {
            @unlink($target);
            @unlink($dir . '/.keymgr.lock');
            @unlink($outside);
            @rmdir($dir);
        }
    }
}
