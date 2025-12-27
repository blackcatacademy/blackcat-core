<?php

declare(strict_types=1);

namespace BlackCat\Core\Kernel;

use BlackCat\Core\Security\HttpRequestGuard;
use BlackCat\Core\Security\PhpRuntimeInspector;
use BlackCat\Core\TrustKernel\Web3TransportInterface;
use Psr\Log\LoggerInterface;

/**
 * Kernel-only HTTP entrypoint (recommended).
 *
 * Centralizes the “front controller” duties:
 * - reduce HTTP entrypoints to a single index.php (with web server deny rules),
 * - basic request hardening,
 * - boot TrustKernel early (fail-closed),
 * - optionally gate requests on `readAllowed` (strict default),
 * - best-effort PHP runtime hardening checks.
 */
final class HttpKernel
{
    /**
     * Run kernel-only HTTP flow and then execute `$app` with a booted context.
     *
     * @param callable(HttpKernelContext):void $app
     */
    public static function run(
        callable $app,
        ?array $server = null,
        ?HttpKernelOptions $options = null,
        ?LoggerInterface $logger = null,
        ?Web3TransportInterface $transport = null,
    ): void {
        if (PHP_SAPI === 'cli') {
            return;
        }

        $server ??= $_SERVER;
        $options ??= new HttpKernelOptions();

        $bootstrap = self::bootstrapOrReject($server, $options, $logger, $transport);
        if ($bootstrap instanceof HttpKernelResponse) {
            $bootstrap->send();
            return;
        }

        $ctx = $bootstrap;

        if (!$options->catchAppExceptions) {
            $app($ctx);
            return;
        }

        try {
            $app($ctx);
        } catch (\Throwable $e) {
            $logger?->error('[http-kernel] unhandled exception: ' . $e->getMessage());
            self::genericErrorResponse(500)->send();
        }
    }

    /**
     * Perform request hardening and early gating.
     *
     * Returns a response when the request should be rejected, otherwise a booted context.
     *
     * This does not execute the user app.
     */
    public static function bootstrapOrReject(
        array $server,
        HttpKernelOptions $options,
        ?LoggerInterface $logger = null,
        ?Web3TransportInterface $transport = null,
    ): HttpKernelContext|HttpKernelResponse {
        if ($options->applyIniHardening) {
            self::applyIniHardening();
        }

        if ($options->sendSecurityHeaders) {
            self::sendSecurityHeaders();
        }

        try {
            HttpRequestGuard::assertSafeRequest($server, $options->allowedMethods);
        } catch (\Throwable $e) {
            $logger?->warning('[http-kernel] request rejected: ' . $e->getMessage());
            return self::genericErrorResponse(400);
        }

        // Boot TrustKernel early to install guards before any app logic.
        try {
            $kernel = KernelBootstrap::bootOrFail($logger, $transport);
        } catch (\Throwable $e) {
            $logger?->error('[http-kernel] kernel bootstrap failed: ' . $e->getMessage());
            return self::genericErrorResponse(503);
        }

        $status = $kernel->check();
        if ($options->checkTrustOnRequest && !$status->readAllowed) {
            $logger?->error('[http-kernel] trust kernel denied read on request entry.');
            return self::genericErrorResponse(503);
        }

        $phpRuntime = null;
        if ($options->requireRuntimeHardeningInStrict && $status->enforcement === 'strict') {
            try {
                $phpRuntime = PhpRuntimeInspector::inspect();
                foreach (($phpRuntime['findings'] ?? []) as $finding) {
                    if (!is_array($finding)) {
                        continue;
                    }
                    if (($finding['severity'] ?? null) === 'error') {
                        $logger?->error('[http-kernel] php runtime hardening violation: ' . ($finding['code'] ?? 'unknown'));
                        return self::genericErrorResponse(503);
                    }
                }
            } catch (\Throwable $e) {
                $logger?->warning('[http-kernel] php runtime inspect failed: ' . $e->getMessage());
            }
        }

        return new HttpKernelContext($kernel, $status, $phpRuntime);
    }

    private static function applyIniHardening(): void
    {
        @ini_set('display_errors', '0');
        @ini_set('display_startup_errors', '0');
        @ini_set('log_errors', '1');
        @ini_set('expose_php', '0');
        @ini_set('zend.exception_ignore_args', '1');
        @ini_set('session.use_strict_mode', '1');
        @ini_set('session.use_only_cookies', '1');
        @ini_set('session.use_trans_sid', '0');
        @ini_set('session.cookie_httponly', '1');
    }

    private static function sendSecurityHeaders(): void
    {
        if (headers_sent()) {
            return;
        }

        if (function_exists('header_remove')) {
            @header_remove('X-Powered-By');
        }

        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    }

    private static function genericErrorResponse(int $status): HttpKernelResponse
    {
        $status = in_array($status, [400, 503, 500], true) ? $status : 500;

        $body = match ($status) {
            400 => "Bad Request\n",
            503 => "Service Unavailable\n",
            default => "Internal Server Error\n",
        };

        return new HttpKernelResponse(
            $status,
            ['Content-Type' => 'text/plain; charset=utf-8'],
            $body,
        );
    }
}
