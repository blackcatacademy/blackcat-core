<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel;

use BlackCat\Core\TrustKernel\Sha256Merkle;
use PHPUnit\Framework\TestCase;

final class Sha256MerkleTest extends TestCase
{
    public function testRootIsStableAndOrderIndependent(): void
    {
        $entriesA = [
            'b.txt' => '0x' . str_repeat('11', 32),
            'a.txt' => '0x' . str_repeat('22', 32),
        ];

        $entriesB = [
            'a.txt' => '0x' . str_repeat('22', 32),
            'b.txt' => '0x' . str_repeat('11', 32),
        ];

        $expected = '0xf92742ec920dcc955d96633e56df2ea657a3f5521fe309045e900eee39ef14b0';

        self::assertSame($expected, Sha256Merkle::root($entriesA));
        self::assertSame($expected, Sha256Merkle::root($entriesB));
    }

    public function testNormalizeRejectsDotDot(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Sha256Merkle::normalizePath('../secrets.key');
    }
}

