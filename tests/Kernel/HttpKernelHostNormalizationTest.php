<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\Kernel;

use BlackCat\Core\Kernel\HttpKernel;
use PHPUnit\Framework\TestCase;

final class HttpKernelHostNormalizationTest extends TestCase
{
    public function testNormalizeHostHeaderAcceptsHostAndHostPortForms(): void
    {
        $m = new \ReflectionMethod(HttpKernel::class, 'normalizeHostHeader');
        $m->setAccessible(true);

        self::assertSame('example.com', $m->invoke(null, 'Example.COM'));
        self::assertSame('example.com', $m->invoke(null, 'example.com:443'));
        self::assertSame('127.0.0.1', $m->invoke(null, '127.0.0.1:80'));
        self::assertSame('::1', $m->invoke(null, '[::1]:443'));
        self::assertSame('::1', $m->invoke(null, '[::1]'));
    }

    public function testNormalizeHostHeaderRejectsUrlsAndWeirdPorts(): void
    {
        $m = new \ReflectionMethod(HttpKernel::class, 'normalizeHostHeader');
        $m->setAccessible(true);

        self::assertNull($m->invoke(null, 'https://example.com'));
        self::assertNull($m->invoke(null, 'http://localhost'));
        self::assertNull($m->invoke(null, 'example.com:abc'));
        self::assertNull($m->invoke(null, 'example.com:80:90'));
        self::assertNull($m->invoke(null, '[::1]:abc'));
        self::assertNull($m->invoke(null, '[::1]/path'));
    }
}

