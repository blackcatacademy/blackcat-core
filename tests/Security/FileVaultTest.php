<?php
declare(strict_types=1);

namespace BlackCat\Core\Tests\Security;

use BlackCat\Core\Security\FileVault;
use PHPUnit\Framework\TestCase;

final class FileVaultTest extends TestCase
{
    public function testEncryptThenDecryptToFile(): void
    {
        $base = sys_get_temp_dir() . '/blackcat-core-filevault-' . bin2hex(random_bytes(6));
        $keysDir = $base . '/keys';
        $outDir = $base . '/out';
        mkdir($keysDir, 0700, true);
        mkdir($outDir, 0700, true);

        $keyPath = $keysDir . '/filevault_key_v1.key';
        file_put_contents($keyPath, random_bytes(32));
        chmod($keyPath, 0400);

        FileVault::setKeysDir($keysDir);

        $plainPath = $base . '/plain.txt';
        $plain = "hello\nworld\n" . bin2hex(random_bytes(16));
        file_put_contents($plainPath, $plain);

        $encPath = $outDir . '/test.enc';
        $okEnc = FileVault::uploadAndEncrypt($plainPath, $encPath);
        self::assertSame($encPath, $okEnc);
        self::assertFileExists($encPath);
        self::assertFileExists($encPath . '.meta');

        $decPath = $outDir . '/test.dec.txt';
        $okDec = FileVault::decryptToFile($encPath, $decPath);
        self::assertTrue($okDec);
        self::assertSame($plain, file_get_contents($decPath));

        $this->rmrf($base);
    }

    public function testDecryptWorksWithoutMetaUsingKeyIdFromHeader(): void
    {
        $base = sys_get_temp_dir() . '/blackcat-core-filevault-nometa-' . bin2hex(random_bytes(6));
        $keysDir = $base . '/keys';
        $outDir = $base . '/out';
        mkdir($keysDir, 0700, true);
        mkdir($outDir, 0700, true);

        $keyPath = $keysDir . '/filevault_key_v1.key';
        file_put_contents($keyPath, random_bytes(32));
        chmod($keyPath, 0400);

        FileVault::setKeysDir($keysDir);

        $plainPath = $base . '/plain.txt';
        $plain = 'payload-' . bin2hex(random_bytes(16));
        file_put_contents($plainPath, $plain);

        $encPath = $outDir . '/test.enc';
        $okEnc = FileVault::uploadAndEncrypt($plainPath, $encPath);
        self::assertSame($encPath, $okEnc);

        // Remove .meta to force header-based key selection.
        unlink($encPath . '.meta');
        self::assertFileDoesNotExist($encPath . '.meta');

        $decPath = $outDir . '/test.dec.txt';
        $okDec = FileVault::decryptToFile($encPath, $decPath);
        self::assertTrue($okDec);
        self::assertSame($plain, file_get_contents($decPath));

        $this->rmrf($base);
    }

    public function testDecryptFailsWhenCiphertextIsTampered(): void
    {
        $base = sys_get_temp_dir() . '/blackcat-core-filevault-tamper-' . bin2hex(random_bytes(6));
        $keysDir = $base . '/keys';
        $outDir = $base . '/out';
        mkdir($keysDir, 0700, true);
        mkdir($outDir, 0700, true);

        $keyPath = $keysDir . '/filevault_key_v1.key';
        file_put_contents($keyPath, random_bytes(32));
        chmod($keyPath, 0400);

        FileVault::setKeysDir($keysDir);

        $plainPath = $base . '/plain.txt';
        file_put_contents($plainPath, 'hello');

        $encPath = $outDir . '/test.enc';
        self::assertSame($encPath, FileVault::uploadAndEncrypt($plainPath, $encPath));

        $raw = file_get_contents($encPath);
        self::assertIsString($raw);
        // Flip a bit somewhere after the header (best-effort).
        $pos = min(strlen($raw) - 1, 40);
        $raw[$pos] = chr(ord($raw[$pos]) ^ 0x01);
        file_put_contents($encPath, $raw);

        $decPath = $outDir . '/test.dec.txt';
        self::assertFalse(FileVault::decryptToFile($encPath, $decPath));

        $this->rmrf($base);
    }

    private function rmrf(string $path): void
    {
        if (!file_exists($path)) {
            return;
        }
        if (is_file($path) || is_link($path)) {
            @unlink($path);
            return;
        }
        $items = scandir($path);
        if (!is_array($items)) {
            return;
        }
        foreach ($items as $it) {
            if ($it === '.' || $it === '..') {
                continue;
            }
            $this->rmrf($path . DIRECTORY_SEPARATOR . $it);
        }
        @rmdir($path);
    }
}

