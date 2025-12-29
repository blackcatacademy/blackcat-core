<?php

declare(strict_types=1);

namespace BlackCat\Core\Kernel;

use BlackCat\Core\Security\HttpRequestGuard;
use BlackCat\Core\Security\PhpRuntimeInspector;
use BlackCat\Core\Security\ThreatScanner;
use BlackCat\Core\Security\TrustedProxyGuard;
use BlackCat\Core\TrustKernel\CanonicalJson;
use BlackCat\Core\TrustKernel\TxOutbox;
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
    private static ?string $lastThreatIncidentHash = null;
    private static int $lastThreatIncidentAt = 0;

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
            self::applyIniHardening($server);
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

        if ($options->rejectUntrustedForwardedHeaders || $options->honorTrustedForwardedProto) {
            $trustedProxies = self::mergeTrustedProxyList(
                $options->trustedProxies,
                self::trustedProxiesFromRuntimeConfig(),
            );

            try {
                if ($options->rejectUntrustedForwardedHeaders) {
                    TrustedProxyGuard::assertNoUntrustedForwardedHeaders($server, $trustedProxies);
                }

                if ($options->honorTrustedForwardedProto && TrustedProxyGuard::isForwardedHttpsFromTrustedProxy($server, $trustedProxies)) {
                    // Best-effort: make downstream code treat the request as HTTPS when behind a trusted proxy.
                    // Never downgrade HTTPS to HTTP based on forwarded headers.
                    $server['HTTPS'] = 'on';
                    $server['SERVER_PORT'] = '443';
                    $_SERVER['HTTPS'] = 'on';
                    $_SERVER['SERVER_PORT'] = '443';
                }
            } catch (\Throwable $e) {
                $logger?->warning('[http-kernel] forwarded headers rejected: ' . $e->getMessage());
                return self::genericErrorResponse(400);
            }
        }

        if ($options->applyIniHardening) {
            // Re-apply cookie hardening after proxy HTTPS normalization.
            self::applyIniHardening($server);
        }

        if ($options->sendHstsHeader) {
            self::sendHstsHeaderIfHttps($server, $options);
        }

        $status = $kernel->check();
        if ($status->paused) {
            $logger?->error('[http-kernel] instance controller is paused.');
            return self::genericErrorResponse(503);
        }

        $allowedHosts = self::allowedHostsFromRuntimeConfig();
        if ($allowedHosts !== []) {
            $hostHeader = $server['HTTP_HOST'] ?? ($server['SERVER_NAME'] ?? null);
            $host = is_string($hostHeader) ? self::normalizeHostHeader($hostHeader) : null;
            $ok = $host !== null && self::isHostAllowed($host, $allowedHosts);
            if (!$ok) {
                $logger?->warning('[http-kernel] host rejected by allowlist.');
                if ($status->enforcement === 'strict') {
                    return self::genericErrorResponse(400);
                }
            }
        }

        if ($options->checkTrustOnRequest && $status->enforcement === 'strict' && !$status->readAllowed) {
            $logger?->error('[http-kernel] trust kernel denied read on request entry.');
            return self::genericErrorResponse(503);
        }

        if ($options->scanRequestThreats) {
            try {
                $get = is_array($_GET) ? $_GET : [];
                $post = is_array($_POST) ? $_POST : [];
                $cookie = is_array($_COOKIE) ? $_COOKIE : [];
                $files = is_array($_FILES) ? $_FILES : [];

                $report = ThreatScanner::scanRequest(
                    $server,
                    $get,
                    $post,
                    $cookie,
                    $files,
                    [
                        'max_fields' => $options->threatScanMaxFields,
                        'max_value_len' => $options->threatScanMaxValueLen,
                        'max_files' => $options->threatScanMaxFiles,
                        'max_file_bytes' => $options->threatScanMaxFileBytes,
                        'disallowed_upload_extensions' => $options->threatScanDisallowedUploadExtensions,
                    ],
                );

                $findings = $report['findings'] ?? null;
                if (is_array($findings) && $findings !== []) {
                    $codes = [];
                    foreach ($findings as $f) {
                        if (!is_array($f)) {
                            continue;
                        }
                        $code = $f['code'] ?? null;
                        if (is_string($code) && $code !== '' && !str_contains($code, "\0")) {
                            $codes[$code] = true;
                        }
                    }
                    $codeList = array_keys($codes);
                    sort($codeList, SORT_STRING);

                    if ($status->enforcement === 'strict') {
                        $logger?->warning('[http-kernel] threat scanner rejected request: ' . implode(',', $codeList));
                        if ($options->enqueueThreatIncidents) {
                            self::enqueueThreatIncident($kernel->instanceControllerAddress(), $server, $codeList, $options, $logger);
                        }
                        return self::genericErrorResponse(400);
                    }

                    $logger?->warning('[http-kernel] threat scanner findings (warn mode): ' . implode(',', $codeList));
                }
            } catch (\Throwable $e) {
                // Scanner must never block the app by crashing; rely on TrustKernel for fail-closed integrity.
                $logger?->warning('[http-kernel] threat scanner failed: ' . $e->getMessage());
            }
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

    /**
     * @param list<string> $codes
     */
    private static function enqueueThreatIncident(
        string $controller,
        array $server,
        array $codes,
        HttpKernelOptions $options,
        ?LoggerInterface $logger = null,
    ): void {
        $outbox = TxOutbox::fromRuntimeConfigBestEffort();
        if ($outbox === null) {
            return;
        }

        $method = $server['REQUEST_METHOD'] ?? null;
        $method = is_string($method) ? strtoupper(trim($method)) : 'UNKNOWN';

        $requestUri = $server['REQUEST_URI'] ?? null;
        $path = is_string($requestUri) ? parse_url($requestUri, PHP_URL_PATH) : null;
        $path = is_string($path) && $path !== '' ? $path : '/';

        $preimage = [
            'schema_version' => 1,
            'type' => 'blackcat.security.threat_detected',
            'controller' => $controller,
            'method' => $method,
            'path_sha256' => '0x' . hash('sha256', $path),
            'codes' => $codes,
        ];

        $incidentHash = CanonicalJson::sha256Bytes32($preimage);

        $now = time();
        if (
            self::$lastThreatIncidentHash !== null
            && hash_equals(self::$lastThreatIncidentHash, $incidentHash)
            && $options->threatIncidentDebounceSec > 0
            && ($now - self::$lastThreatIncidentAt) < $options->threatIncidentDebounceSec
        ) {
            return;
        }

        try {
            $payload = [
                'schema_version' => 1,
                'type' => 'blackcat.tx_request',
                'created_at' => gmdate('c'),
                'to' => $controller,
                'method' => 'reportIncident(bytes32)',
                'args' => [$incidentHash],
                'meta' => [
                    'source' => 'http-kernel',
                    'codes' => $codes,
                ],
            ];

            $outbox->enqueue($payload);
            self::$lastThreatIncidentHash = $incidentHash;
            self::$lastThreatIncidentAt = $now;
        } catch (\Throwable $e) {
            $logger?->warning('[http-kernel] threat incident outbox enqueue failed: ' . $e->getMessage());
        }
    }

    /**
     * @return list<string>
     */
    private static function mergeTrustedProxyList(array $a, array $b): array
    {
        $out = [];
        $add = static function (array $items) use (&$out): void {
            foreach ($items as $v) {
                if (!is_string($v)) {
                    continue;
                }
                $v = trim($v);
                if ($v === '' || str_contains($v, "\0")) {
                    continue;
                }
                $out[$v] = true;
            }
        };

        $add($a);
        $add($b);

        return array_keys($out);
    }

    /**
     * Read allowed hosts list from runtime config (`http.allowed_hosts`).
     *
     * @return list<string>
     */
    private static function allowedHostsFromRuntimeConfig(): array
    {
        $configClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'Config']);
        if (!class_exists($configClass)) {
            return [];
        }

        $isInitialized = false;
        if (is_callable([$configClass, 'isInitialized'])) {
            $method = 'isInitialized';
            $isInitialized = (bool) $configClass::$method();
        }
        if (!$isInitialized || !is_callable([$configClass, 'get'])) {
            return [];
        }

        $get = 'get';
        /** @var mixed $raw */
        $raw = $configClass::$get('http.allowed_hosts');
        if (!is_array($raw)) {
            return [];
        }

        $out = [];
        foreach ($raw as $v) {
            if (!is_string($v)) {
                continue;
            }
            $v = trim($v);
            if ($v === '' || str_contains($v, "\0") || str_contains($v, "\r") || str_contains($v, "\n")) {
                continue;
            }

            if (str_starts_with($v, '*.')) {
                $suffix = strtolower(trim(substr($v, 2)));
                if ($suffix === '' || str_contains($suffix, "\0")) {
                    continue;
                }
                if (!preg_match('/^[a-z0-9.-]+$/', $suffix)) {
                    continue;
                }
                if (str_contains($suffix, '..') || str_starts_with($suffix, '.') || str_ends_with($suffix, '.')) {
                    continue;
                }
                $out['*.' . $suffix] = true;
                continue;
            }

            $host = self::normalizeHostHeader($v);
            if ($host === null) {
                continue;
            }
            $out[$host] = true;
        }

        $list = array_keys($out);
        sort($list, SORT_STRING);
        return $list;
    }

    private static function normalizeHostHeader(string $hostHeader): ?string
    {
        $hostHeader = trim($hostHeader);
        if ($hostHeader === '' || str_contains($hostHeader, "\0")) {
            return null;
        }

        if (str_contains($hostHeader, '://') || str_contains($hostHeader, '/') || str_contains($hostHeader, '\\')) {
            return null;
        }

        // Bracketed IPv6: [::1]:443
        if (str_starts_with($hostHeader, '[')) {
            $end = strpos($hostHeader, ']');
            if ($end === false) {
                return null;
            }
            $ipv6 = substr($hostHeader, 1, $end - 1);
            if ($ipv6 === '') {
                return null;
            }
            if (@filter_var($ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
                return null;
            }

            $rest = trim(substr($hostHeader, $end + 1));
            if ($rest !== '') {
                if (!str_starts_with($rest, ':')) {
                    return null;
                }
                $port = trim(substr($rest, 1));
                if ($port === '' || !ctype_digit($port)) {
                    return null;
                }
                $portNum = (int) $port;
                if ($portNum < 1 || $portNum > 65535) {
                    return null;
                }
            }

            return strtolower($ipv6);
        }

        // Normalize "host:port" form (ignore port).
        if (str_contains($hostHeader, ':')) {
            [$h, $p] = explode(':', $hostHeader, 2) + [null, null];
            if (!is_string($h) || !is_string($p)) {
                return null;
            }
            $p = trim($p);
            if ($p === '' || !ctype_digit($p)) {
                return null;
            }
            $portNum = (int) $p;
            if ($portNum < 1 || $portNum > 65535) {
                return null;
            }
            $hostHeader = $h;
        }

        $host = strtolower(trim($hostHeader));
        if ($host === '' || str_contains($host, "\0")) {
            return null;
        }

        if (@filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6) !== false) {
            return $host;
        }

        if (!preg_match('/^[a-z0-9.-]+$/', $host)) {
            return null;
        }
        if (str_contains($host, '..') || str_starts_with($host, '.') || str_ends_with($host, '.')) {
            return null;
        }

        return $host;
    }

    /**
     * @param list<string> $allowedHosts Normalized host patterns.
     */
    private static function isHostAllowed(string $host, array $allowedHosts): bool
    {
        foreach ($allowedHosts as $pattern) {
            if (!is_string($pattern)) {
                continue;
            }
            if ($pattern === $host) {
                return true;
            }
            if (str_starts_with($pattern, '*.')) {
                $suffix = substr($pattern, 1); // ".example.com"
                if ($suffix !== '' && str_ends_with($host, $suffix) && strlen($host) > strlen($suffix)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Read trusted proxy peers from runtime config (`http.trusted_proxies`).
     *
     * @return list<string>
     */
    private static function trustedProxiesFromRuntimeConfig(): array
    {
        $configClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'Config']);
        if (!class_exists($configClass)) {
            return [];
        }

        $isInitialized = false;
        if (is_callable([$configClass, 'isInitialized'])) {
            $method = 'isInitialized';
            $isInitialized = (bool) $configClass::$method();
        }
        if (!$isInitialized || !is_callable([$configClass, 'get'])) {
            return [];
        }

        // If this process runs as root, it should be treated as privileged (installer/agent context).
        // In such contexts, proxy spoofing is not meaningful to guard at the HTTP boundary.
        if (function_exists('posix_geteuid')) {
            $euid = @posix_geteuid();
            if (is_int($euid) && $euid === 0) {
                return [];
            }
        }

        $get = 'get';
        /** @var mixed $raw */
        $raw = $configClass::$get('http.trusted_proxies');
        if (!is_array($raw)) {
            return [];
        }

        $out = [];
        foreach ($raw as $v) {
            if (!is_string($v)) {
                continue;
            }
            $v = trim($v);
            if ($v === '' || str_contains($v, "\0")) {
                continue;
            }
            $out[] = $v;
        }

        return $out;
    }

    /**
     * Apply best-effort php.ini hardening for HTTP runtimes.
     *
     * Note: this does not attempt to override security-critical php.ini settings (those are enforced
     * by RuntimeDoctor + TrustKernel gates). This is only "defense-in-depth" for common defaults.
     *
     * @param array<string,mixed> $server
     */
    private static function applyIniHardening(array $server): void
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
        @ini_set('session.cookie_samesite', 'Lax');

        // Only set cookie_secure when the request is HTTPS (or trusted-proxy normalized to HTTPS).
        if (self::isHttpsRequest($server)) {
            @ini_set('session.cookie_secure', '1');
        }
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

    private static function sendHstsHeaderIfHttps(array $server, HttpKernelOptions $options): void
    {
        if (headers_sent()) {
            return;
        }
        if (!self::isHttpsRequest($server)) {
            return;
        }

        $maxAge = (int) $options->hstsMaxAgeSec;
        if ($maxAge < 0) {
            $maxAge = 0;
        }
        if ($maxAge > 31536000 * 10) {
            $maxAge = 31536000 * 10;
        }

        $value = 'max-age=' . $maxAge;
        if ($options->hstsIncludeSubDomains) {
            $value .= '; includeSubDomains';
        }
        if ($options->hstsPreload) {
            $value .= '; preload';
        }

        header('Strict-Transport-Security: ' . $value);
    }

    /**
     * @param array<string,mixed> $server
     */
    private static function isHttpsRequest(array $server): bool
    {
        $https = $server['HTTPS'] ?? null;
        if ($https === true) {
            return true;
        }
        if (is_string($https)) {
            $v = strtolower(trim($https));
            if ($v === 'on' || $v === '1' || $v === 'true') {
                return true;
            }
        }
        if (is_int($https) && $https === 1) {
            return true;
        }

        $port = $server['SERVER_PORT'] ?? null;
        if (is_int($port) && $port === 443) {
            return true;
        }
        if (is_string($port) && trim($port) === '443') {
            return true;
        }

        return false;
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
