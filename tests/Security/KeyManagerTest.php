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
}

