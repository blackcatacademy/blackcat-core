<?php
declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel;

use BlackCat\Core\TrustKernel\AuditChain;
use PHPUnit\Framework\TestCase;

final class AuditChainTest extends TestCase
{
    public function testAppendAndHeadAdvances(): void
    {
        $dir = sys_get_temp_dir() . '/blackcat-core-audit-chain-' . bin2hex(random_bytes(6));
        mkdir($dir, 0750, true);

        $ac = new AuditChain($dir);

        $head0 = $ac->head();
        self::assertSame(0, $head0['seq']);
        self::assertSame('0x' . str_repeat('00', 32), $head0['head_hash']);

        $h1 = $ac->append('test.event', ['ok' => true], ['uid' => 33]);
        self::assertSame(1, $h1['seq']);
        self::assertStringStartsWith('0x', $h1['head_hash']);
        self::assertSame(66, strlen($h1['head_hash']));

        $h2 = $ac->append('test.event2', ['n' => 2], null);
        self::assertSame(2, $h2['seq']);
        self::assertNotSame($h1['head_hash'], $h2['head_hash']);

        $headNow = $ac->head();
        self::assertSame(2, $headNow['seq']);
        self::assertSame($h2['head_hash'], $headNow['head_hash']);

        $logPath = rtrim($dir, '/\\') . '/audit.log.ndjson';
        self::assertFileExists($logPath);

        $lines = file($logPath, FILE_IGNORE_NEW_LINES);
        self::assertIsArray($lines);
        self::assertCount(2, $lines);

        $e1 = json_decode((string) $lines[0], true);
        $e2 = json_decode((string) $lines[1], true);
        self::assertIsArray($e1);
        self::assertIsArray($e2);

        self::assertSame($h1['head_hash'], $e1['hash'] ?? null);
        self::assertSame($h2['head_hash'], $e2['hash'] ?? null);
        self::assertSame($e1['hash'] ?? null, $e2['prev'] ?? null);
    }

    public function testRefusesSymlinkLogFile(): void
    {
        $dir = sys_get_temp_dir() . '/blackcat-core-audit-chain-symlink-' . bin2hex(random_bytes(6));
        mkdir($dir, 0750, true);

        $target = $dir . '/target.txt';
        file_put_contents($target, 'x');
        $link = $dir . '/audit.log.ndjson';
        if (!@symlink($target, $link)) {
            self::markTestSkipped('symlink() not supported in this environment');
        }

        $ac = new AuditChain($dir);

        $this->expectException(\RuntimeException::class);
        $ac->append('test.event');
    }

    public function testRefusesOversizedHeadFile(): void
    {
        $dir = sys_get_temp_dir() . '/blackcat-core-audit-chain-headsize-' . bin2hex(random_bytes(6));
        mkdir($dir, 0750, true);

        $headPath = rtrim($dir, '/\\') . '/audit.head.json';
        file_put_contents($headPath, str_repeat('x', 64 * 1024 + 10));

        $ac = new AuditChain($dir);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('too large');
        $ac->head();
    }
}
