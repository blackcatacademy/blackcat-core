<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\Security;

use BlackCat\Core\Security\TrustedProxyGuard;
use PHPUnit\Framework\TestCase;

final class TrustedProxyGuardTest extends TestCase
{
    public function testRejectsForwardedHeadersFromUntrustedPeer(): void
    {
        $this->expectException(\RuntimeException::class);

        TrustedProxyGuard::assertNoUntrustedForwardedHeaders(
            [
                'REMOTE_ADDR' => '203.0.113.10',
                'HTTP_X_FORWARDED_PROTO' => 'https',
            ],
            ['127.0.0.1', '::1'],
        );
    }

    public function testAllowsForwardedHeadersFromTrustedPeer(): void
    {
        TrustedProxyGuard::assertNoUntrustedForwardedHeaders(
            [
                'REMOTE_ADDR' => '127.0.0.1',
                'HTTP_X_FORWARDED_PROTO' => 'https',
                'HTTP_X_FORWARDED_FOR' => '198.51.100.1',
            ],
            ['127.0.0.1', '::1'],
        );

        self::assertTrue(true);
    }

    public function testHonorsForwardedProtoHttpsOnlyFromTrustedPeer(): void
    {
        $trusted = ['10.0.0.0/8', '::1', '2001:db8::/32'];

        self::assertTrue(TrustedProxyGuard::isForwardedHttpsFromTrustedProxy(
            [
                'REMOTE_ADDR' => '10.1.2.3',
                'HTTP_X_FORWARDED_PROTO' => 'https',
            ],
            $trusted,
        ));

        self::assertTrue(TrustedProxyGuard::isForwardedHttpsFromTrustedProxy(
            [
                'REMOTE_ADDR' => '2001:db8::1234',
                'HTTP_X_FORWARDED_PROTO' => 'https,http',
            ],
            $trusted,
        ));

        self::assertFalse(TrustedProxyGuard::isForwardedHttpsFromTrustedProxy(
            [
                'REMOTE_ADDR' => '203.0.113.10',
                'HTTP_X_FORWARDED_PROTO' => 'https',
            ],
            $trusted,
        ));
    }
}

