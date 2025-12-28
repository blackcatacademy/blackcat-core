<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel;

use BlackCat\Core\TrustKernel\DefaultWeb3Transport;
use PHPUnit\Framework\TestCase;

final class DefaultWeb3TransportTest extends TestCase
{
    public function testRejectsNonHttpSchemes(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        self::invokeAssertAllowedRpcUrl('file:///etc/passwd');
    }

    public function testRejectsPhpStreamWrapper(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        self::invokeAssertAllowedRpcUrl('php://filter/resource=/etc/passwd');
    }

    public function testRejectsMissingScheme(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        self::invokeAssertAllowedRpcUrl('rpc.layeredge.io');
    }

    public function testRejectsUrlWithBasicAuth(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        self::invokeAssertAllowedRpcUrl('https://user:pass@example.invalid');
    }

    public function testRejectsPlainHttpForNonLoopback(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        self::invokeAssertAllowedRpcUrl('http://rpc.layeredge.io');
    }

    public function testAllowsHttpForLoopback(): void
    {
        try {
            self::invokeAssertAllowedRpcUrl('http://127.0.0.1:8545');
            self::assertTrue(true);
        } catch (\Throwable $e) {
            self::fail('Expected loopback http to be allowed: ' . $e->getMessage());
        }
    }

    private static function invokeAssertAllowedRpcUrl(string $url): void
    {
        $ref = new \ReflectionMethod(DefaultWeb3Transport::class, 'assertAllowedRpcUrl');
        $ref->setAccessible(true);
        $ref->invoke(null, $url);
    }
}
