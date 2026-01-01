<?php
declare(strict_types=1);

namespace BlackCat\Core\Tests\Security;

use BlackCat\Core\Security\Recaptcha;
use PHPUnit\Framework\TestCase;

final class RecaptchaTest extends TestCase
{
    public function testVerifyOkOnSuccess(): void
    {
        $recaptcha = new Recaptcha('secret', 0.4, [
            'endpoint' => 'https://www.google.com/recaptcha/api/siteverify',
            'httpClient' => static function (string $url, array $postFields, int $timeout): array {
                return [
                    'code' => 200,
                    'body' => json_encode([
                        'success' => true,
                        'score' => 0.9,
                        'action' => 'login',
                    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
                    'error' => null,
                ];
            },
        ]);

        $res = $recaptcha->verify('token', '203.0.113.1');
        self::assertTrue($res['ok']);
        self::assertSame('login', $res['action']);
        self::assertSame(null, $res['error']);
    }

    public function testVerifyRejectsHttpEndpoint(): void
    {
        $recaptcha = new Recaptcha('secret', 0.4, [
            'endpoint' => 'http://www.google.com/recaptcha/api/siteverify',
            'httpClient' => static function (string $url, array $postFields, int $timeout): array {
                return ['code' => 200, 'body' => '{}', 'error' => null];
            },
        ]);

        $res = $recaptcha->verify('token');
        self::assertFalse($res['ok']);
        self::assertSame('bad_endpoint_scheme', $res['error']);
    }

    public function testVerifyRejectsIpLiteralEndpoint(): void
    {
        $recaptcha = new Recaptcha('secret', 0.4, [
            'endpoint' => 'https://127.0.0.1/recaptcha/api/siteverify',
            'httpClient' => static function (string $url, array $postFields, int $timeout): array {
                return ['code' => 200, 'body' => '{}', 'error' => null];
            },
        ]);

        $res = $recaptcha->verify('token');
        self::assertFalse($res['ok']);
        self::assertSame('bad_endpoint_ip', $res['error']);
    }

    public function testVerifyRejectsHostNotInAllowlist(): void
    {
        $recaptcha = new Recaptcha('secret', 0.4, [
            'endpoint' => 'https://example.com/recaptcha/api/siteverify',
            'allowed_hosts' => ['www.google.com'],
            'httpClient' => static function (string $url, array $postFields, int $timeout): array {
                return ['code' => 200, 'body' => '{}', 'error' => null];
            },
        ]);

        $res = $recaptcha->verify('token');
        self::assertFalse($res['ok']);
        self::assertSame('bad_endpoint_host_not_allowed', $res['error']);
    }

    public function testVerifyRejectsTooLargeResponse(): void
    {
        $tooLarge = str_repeat('a', 70 * 1024);

        $recaptcha = new Recaptcha('secret', 0.4, [
            'endpoint' => 'https://www.google.com/recaptcha/api/siteverify',
            'httpClient' => static function (string $url, array $postFields, int $timeout) use ($tooLarge): array {
                return ['code' => 200, 'body' => $tooLarge, 'error' => null];
            },
        ]);

        $res = $recaptcha->verify('token');
        self::assertFalse($res['ok']);
        self::assertSame('response_too_large', $res['error']);
    }
}

