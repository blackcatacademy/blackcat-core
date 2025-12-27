<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel;

use BlackCat\Core\TrustKernel\IntegrityManifestV1;
use BlackCat\Core\TrustKernel\IntegrityViolationException;
use BlackCat\Core\TrustKernel\LocalIntegrityVerifier;
use BlackCat\Core\TrustKernel\Sha256Merkle;
use PHPUnit\Framework\TestCase;

final class LocalIntegrityVerifierTest extends TestCase
{
    public function testComputeAndVerifyRootPassesOnMatchingFiles(): void
    {
        $dir = sys_get_temp_dir() . '/blackcat-core-integrity-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700, true);

        try {
            file_put_contents($dir . '/a.txt', "hello\n");
            file_put_contents($dir . '/b.txt', "world\n");

            $aHash = '0x' . hash_file('sha256', $dir . '/a.txt');
            $bHash = '0x' . hash_file('sha256', $dir . '/b.txt');

            $manifestPath = $dir . '/integrity.json';
            file_put_contents($manifestPath, json_encode([
                'schema_version' => 1,
                'type' => 'blackcat.integrity.manifest',
                'uri' => 'https://example.test/manifest.json',
                'files' => [
                    'a.txt' => $aHash,
                    'b.txt' => $bHash,
                ],
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");

            $manifest = IntegrityManifestV1::fromJsonFile($manifestPath);
            $verifier = new LocalIntegrityVerifier($dir);
            $root = $verifier->computeAndVerifyRoot($manifest);

            self::assertSame(Sha256Merkle::root($manifest->files), $root);
        } finally {
            @unlink($dir . '/a.txt');
            @unlink($dir . '/b.txt');
            @unlink($dir . '/integrity.json');
            @rmdir($dir);
        }
    }

    public function testComputeAndVerifyRootFailsOnMismatch(): void
    {
        $dir = sys_get_temp_dir() . '/blackcat-core-integrity-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700, true);

        try {
            file_put_contents($dir . '/a.txt', "hello\n");

            $aHash = '0x' . hash_file('sha256', $dir . '/a.txt');

            $manifestPath = sys_get_temp_dir() . '/blackcat-core-integrity-manifest-' . bin2hex(random_bytes(6)) . '.json';
            file_put_contents($manifestPath, json_encode([
                'schema_version' => 1,
                'type' => 'blackcat.integrity.manifest',
                'files' => [
                    'a.txt' => $aHash,
                ],
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");

            // Tamper.
            file_put_contents($dir . '/a.txt', "tampered\n");

            $manifest = IntegrityManifestV1::fromJsonFile($manifestPath);
            $verifier = new LocalIntegrityVerifier($dir);

            $this->expectException(\RuntimeException::class);
            $this->expectExceptionMessage('hash mismatch');
            $verifier->computeAndVerifyRoot($manifest);
        } finally {
            @unlink($dir . '/a.txt');
            @unlink($dir . '/integrity.json');
            @rmdir($dir);
        }
    }

    public function testComputeAndVerifyRootStrictFailsOnSymlinkDirectory(): void
    {
        $dir = sys_get_temp_dir() . '/blackcat-core-integrity-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700, true);

        $target = $dir . '/target';
        mkdir($target, 0700, true);

        try {
            file_put_contents($dir . '/a.txt', "hello\n");

            $aHash = '0x' . hash_file('sha256', $dir . '/a.txt');

            $manifestPath = sys_get_temp_dir() . '/blackcat-core-integrity-manifest-' . bin2hex(random_bytes(6)) . '.json';
            file_put_contents($manifestPath, json_encode([
                'schema_version' => 1,
                'type' => 'blackcat.integrity.manifest',
                'files' => [
                    'a.txt' => $aHash,
                ],
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");

            $link = $dir . '/linked-dir';
            if (!symlink($target, $link)) {
                self::fail('Unable to create symlink directory for test.');
            }

            $manifest = IntegrityManifestV1::fromJsonFile($manifestPath);
            $verifier = new LocalIntegrityVerifier($dir);

            $this->expectException(IntegrityViolationException::class);
            $this->expectExceptionMessage('symlink is not allowed');
            $verifier->computeAndVerifyRootStrict($manifest);
        } finally {
            @unlink($dir . '/a.txt');
            @unlink($manifestPath ?? '');
            @unlink($dir . '/linked-dir');
            @rmdir($target);
            @rmdir($dir);
        }
    }
}
