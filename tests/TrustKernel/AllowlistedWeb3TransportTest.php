<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel;

use BlackCat\Core\TrustKernel\AllowlistedWeb3Transport;
use BlackCat\Core\TrustKernel\Web3TransportInterface;
use PHPUnit\Framework\TestCase;

final class AllowlistedWeb3TransportTest extends TestCase
{
    public function testRejectsNonAllowlistedHost(): void
    {
        $inner = new class implements Web3TransportInterface {
            public function postJson(string $url, string $jsonBody, int $timeoutSec): string
            {
                return '{"ok":true}';
            }
        };

        $t = AllowlistedWeb3Transport::fromRpcEndpoints($inner, ['https://rpc.example.invalid']);

        $this->expectException(\InvalidArgumentException::class);
        $t->postJson('https://evil.example.invalid', '{}', 1);
    }

    public function testAllowsAllowlistedHost(): void
    {
        $inner = new class implements Web3TransportInterface {
            public function postJson(string $url, string $jsonBody, int $timeoutSec): string
            {
                return '{"ok":true}';
            }
        };

        $t = AllowlistedWeb3Transport::fromRpcEndpoints($inner, ['https://rpc.example.invalid']);
        $res = $t->postJson('https://rpc.example.invalid', '{}', 1);
        self::assertSame('{"ok":true}', $res);
    }
}

