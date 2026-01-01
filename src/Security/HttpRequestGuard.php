<?php

declare(strict_types=1);

namespace BlackCat\Core\Security;

/**
 * Basic HTTP request guard for "single front controller" deployments.
 *
 * This is intentionally conservative and lightweight:
 * - deny obviously malicious request URIs (path traversal, stream wrappers),
 * - enforce a reasonable URI length limit,
 * - validate Host header shape (anti header injection),
 * - restrict HTTP methods unless explicitly allowed.
 *
 * This is not a substitute for:
 * - web server config (deny direct access to *.php except index.php),
 * - OS isolation,
 * - proper app-level input validation.
 */
final class HttpRequestGuard
{
    /**
     * @param array<string,mixed> $server Typically $_SERVER
     * @param list<string>|null $allowedMethods
     * @throws \RuntimeException when request is rejected
     */
    public static function assertSafeRequest(array $server, ?array $allowedMethods = null): void
    {
        $method = $server['REQUEST_METHOD'] ?? null;
        if (!is_string($method) || $method === '') {
            throw new \RuntimeException('Invalid HTTP request method.');
        }

        $allowedMethods ??= ['GET', 'POST', 'HEAD', 'OPTIONS'];
        $allowed = array_map(static fn (string $m): string => strtoupper(trim($m)), $allowedMethods);
        if (!in_array(strtoupper($method), $allowed, true)) {
            throw new \RuntimeException('HTTP method not allowed: ' . $method);
        }

        // Host header sanity (anti header-injection / request smuggling primitives).
        $host = $server['HTTP_HOST'] ?? ($server['SERVER_NAME'] ?? null);
        if (is_string($host) && trim($host) !== '') {
            self::assertSafeHost($host);
        }

        $uri = $server['REQUEST_URI'] ?? null;
        if (!is_string($uri) || $uri === '') {
            throw new \RuntimeException('Missing REQUEST_URI.');
        }

        if (str_contains($uri, "\0")) {
            throw new \RuntimeException('Invalid REQUEST_URI (null byte).');
        }

        // Reject CRLF in URI (header injection / request smuggling primitive).
        if (str_contains($uri, "\r") || str_contains($uri, "\n")) {
            throw new \RuntimeException('Invalid REQUEST_URI (CRLF).');
        }

        // Basic DoS guard: extremely long URIs are suspicious.
        if (strlen($uri) > 4096) {
            throw new \RuntimeException('REQUEST_URI too long.');
        }

        $lower = strtolower($uri);

        // Common exploit primitives / stream wrappers in URL.
        foreach (['php://', 'data:', 'expect://', 'zip://', 'phar://'] as $needle) {
            if (str_contains($lower, $needle)) {
                throw new \RuntimeException('Blocked URI scheme: ' . $needle);
            }
        }

        // Path traversal (raw and percent-encoded).
        $decoded = self::safeRawUrlDecode($uri);
        $hay = strtolower($decoded);
        if (str_contains($hay, '../') || str_contains($hay, '..\\') || str_contains($hay, '/..') || str_contains($hay, '\\..')) {
            throw new \RuntimeException('Path traversal detected in URI.');
        }
    }

    private static function assertSafeHost(string $host): void
    {
        $host = trim($host);
        if ($host === '' || str_contains($host, "\0")) {
            throw new \RuntimeException('Invalid Host header.');
        }

        // Reject header injection primitives.
        if (str_contains($host, "\r") || str_contains($host, "\n")) {
            throw new \RuntimeException('Invalid Host header (CRLF).');
        }

        // Basic DoS guard.
        if (strlen($host) > 255) {
            throw new \RuntimeException('Host header too long.');
        }

        // Normalize the common "host:port" form.
        $hostPart = $host;
        $portPart = null;

        // IPv6 in brackets: [::1]:443
        if (str_starts_with($hostPart, '[')) {
            $end = strpos($hostPart, ']');
            if ($end === false) {
                throw new \RuntimeException('Invalid Host header (bad IPv6 bracket).');
            }
            $ipv6 = substr($hostPart, 1, $end - 1);
            if ($ipv6 === '' || @filter_var($ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
                throw new \RuntimeException('Invalid Host header (bad IPv6 address).');
            }
            $rest = substr($hostPart, $end + 1);
            if ($rest === '') {
                return;
            }
            if (!str_starts_with($rest, ':')) {
                throw new \RuntimeException('Invalid Host header (unexpected IPv6 suffix).');
            }
            $portPart = substr($rest, 1);
            self::assertSafePort($portPart);
            return;
        }

        // Split host:port for non-bracketed hosts.
        if (str_contains($hostPart, ':')) {
            [$h, $p] = explode(':', $hostPart, 2) + [null, null];
            if (!is_string($h) || !is_string($p)) {
                throw new \RuntimeException('Invalid Host header.');
            }
            $hostPart = $h;
            $portPart = $p;
        }

        $hostPart = trim($hostPart);
        if ($hostPart === '') {
            throw new \RuntimeException('Invalid Host header (empty host).');
        }

        // Allow IPv4 literal.
        if (@filter_var($hostPart, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            if ($portPart !== null) {
                self::assertSafePort($portPart);
            }
            return;
        }

        // Domain label sanity (intentionally strict; punycode is allowed).
        $lower = strtolower($hostPart);
        if (!preg_match('/^[a-z0-9.-]+$/', $lower)) {
            throw new \RuntimeException('Invalid Host header (bad characters).');
        }
        if (str_contains($lower, '..') || str_starts_with($lower, '.') || str_ends_with($lower, '.')) {
            throw new \RuntimeException('Invalid Host header (bad dots).');
        }

        if ($portPart !== null) {
            self::assertSafePort($portPart);
        }
    }

    private static function assertSafePort(string $port): void
    {
        $port = trim($port);
        if ($port === '' || !ctype_digit($port)) {
            throw new \RuntimeException('Invalid Host header (bad port).');
        }

        $n = (int) $port;
        if ($n < 1 || $n > 65535) {
            throw new \RuntimeException('Invalid Host header (port out of range).');
        }
    }

    private static function safeRawUrlDecode(string $s): string
    {
        // rawurldecode may throw warnings on malformed sequences; treat failures as-is.
        try {
            $d = rawurldecode($s);
            if (!is_string($d) || $d === '' || str_contains($d, "\0")) {
                return $s;
            }
            return $d;
        } catch (\Throwable) {
            return $s;
        }
    }
}
