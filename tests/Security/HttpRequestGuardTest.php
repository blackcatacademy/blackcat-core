<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\Security;

use BlackCat\Core\Security\HttpRequestGuard;
use PHPUnit\Framework\TestCase;

final class HttpRequestGuardTest extends TestCase
{
    public function test_allows_basic_get_request(): void
    {
        HttpRequestGuard::assertSafeRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/health?ok=1',
        ]);

        $this->assertTrue(true);
    }

    public function test_rejects_path_traversal(): void
    {
        $this->expectException(\RuntimeException::class);
        HttpRequestGuard::assertSafeRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/../../etc/passwd',
        ]);
    }

    public function test_rejects_encoded_path_traversal(): void
    {
        $this->expectException(\RuntimeException::class);
        HttpRequestGuard::assertSafeRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/%2e%2e/%2e%2e/etc/passwd',
        ]);
    }

    public function test_rejects_php_stream_wrapper_in_uri(): void
    {
        $this->expectException(\RuntimeException::class);
        HttpRequestGuard::assertSafeRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/?file=php://filter',
        ]);
    }

    public function test_rejects_disallowed_method_by_default(): void
    {
        $this->expectException(\RuntimeException::class);
        HttpRequestGuard::assertSafeRequest([
            'REQUEST_METHOD' => 'PUT',
            'REQUEST_URI' => '/api/resource',
        ]);
    }
}

