<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel;

use BlackCat\Core\TrustKernel\TxOutbox;
use BlackCat\Core\TrustKernel\TxOutboxException;
use PHPUnit\Framework\TestCase;

final class TxOutboxTest extends TestCase
{
    public function testEnqueueWritesJsonFile(): void
    {
        $dir = sys_get_temp_dir() . '/blackcat-core-tx-outbox-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700, true);

        try {
            $outbox = new TxOutbox($dir);
            $path = $outbox->enqueue([
                'schema_version' => 1,
                'type' => 'blackcat.tx_request',
                'to' => '0x1111111111111111111111111111111111111111',
                'method' => 'reportIncident(bytes32)',
                'args' => ['0x' . str_repeat('00', 32)],
            ]);

            self::assertFileExists($path);
            self::assertStringContainsString('.json', $path);

            $raw = file_get_contents($path);
            self::assertIsString($raw);
            self::assertNotSame('', trim($raw));

            /** @var mixed $decoded */
            $decoded = json_decode($raw, true);
            self::assertIsArray($decoded);
            self::assertSame('blackcat.tx_request', $decoded['type'] ?? null);
        } finally {
            foreach (glob($dir . '/*') ?: [] as $file) {
                @unlink((string) $file);
            }
            @rmdir($dir);
        }
    }

    public function testConstructorRejectsSymlinkDirectory(): void
    {
        if (!function_exists('symlink')) {
            self::markTestSkipped('symlink not available');
        }

        $dir = sys_get_temp_dir() . '/blackcat-core-tx-outbox-real-' . bin2hex(random_bytes(6));
        $link = sys_get_temp_dir() . '/blackcat-core-tx-outbox-link-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700, true);

        try {
            if (!symlink($dir, $link)) {
                self::markTestSkipped('Unable to create symlink');
            }

            try {
                new TxOutbox($link);
                self::fail('Expected TxOutboxException for symlink directory.');
            } catch (TxOutboxException $e) {
                self::assertStringContainsString('Tx outbox directory', $e->getMessage());
            }

            // Trailing slashes must not bypass symlink detection.
            try {
                new TxOutbox($link . '/');
                self::fail('Expected TxOutboxException for symlink directory with trailing slash.');
            } catch (TxOutboxException $e) {
                self::assertStringContainsString('Tx outbox directory', $e->getMessage());
            }
        } finally {
            @unlink($link);
            @rmdir($dir);
        }
    }

    public function testConstructorRejectsWorldWritableDir(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX perms not available');
        }

        $dir = sys_get_temp_dir() . '/blackcat-core-tx-outbox-world-writable-' . bin2hex(random_bytes(6));
        mkdir($dir, 0777, true);
        @chmod($dir, 0777);

        try {
            $this->expectException(TxOutboxException::class);
            new TxOutbox($dir);
        } finally {
            @rmdir($dir);
        }
    }
}
