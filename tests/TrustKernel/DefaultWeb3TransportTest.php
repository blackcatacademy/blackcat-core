<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel;

use BlackCat\Core\TrustKernel\DefaultWeb3Transport;
use PHPUnit\Framework\TestCase;

final class DefaultWeb3TransportTest extends TestCase
{
    public function testRejectsNonHttpSchemes(): void
    {
        $t = new DefaultWeb3Transport();

        $this->expectException(\InvalidArgumentException::class);
        $t->postJson('file:///etc/passwd', '{}', 1);
    }

    public function testRejectsPhpStreamWrapper(): void
    {
        $t = new DefaultWeb3Transport();

        $this->expectException(\InvalidArgumentException::class);
        $t->postJson('php://filter/resource=/etc/passwd', '{}', 1);
    }

    public function testRejectsMissingScheme(): void
    {
        $t = new DefaultWeb3Transport();

        $this->expectException(\InvalidArgumentException::class);
        $t->postJson('rpc.layeredge.io', '{}', 1);
    }

    public function testRejectsUrlWithBasicAuth(): void
    {
        $t = new DefaultWeb3Transport();

        $this->expectException(\InvalidArgumentException::class);
        $t->postJson('https://user:pass@example.invalid', '{}', 1);
    }
}

