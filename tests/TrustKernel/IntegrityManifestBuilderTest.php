<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel;

use BlackCat\Core\TrustKernel\IntegrityManifestBuilder;
use PHPUnit\Framework\TestCase;

final class IntegrityManifestBuilderTest extends TestCase
{
    public function testBuildFailsOnSymlinkDirectory(): void
    {
        $dir = sys_get_temp_dir() . '/blackcat-core-manifest-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700, true);

        $target = $dir . '/target';
        mkdir($target, 0700, true);

        try {
            file_put_contents($dir . '/a.txt', "hello\n");

            $link = $dir . '/linked-dir';
            if (!symlink($target, $link)) {
                self::fail('Unable to create symlink directory for test.');
            }

            $this->expectException(\RuntimeException::class);
            $this->expectExceptionMessage('symlink is not allowed');
            IntegrityManifestBuilder::build($dir, null);
        } finally {
            @unlink($dir . '/a.txt');
            @unlink($dir . '/linked-dir');
            @rmdir($target);
            @rmdir($dir);
        }
    }
}

