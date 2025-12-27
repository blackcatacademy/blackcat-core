<?php

declare(strict_types=1);

namespace BlackCat\Core\Security;

/**
 * Basic HTTP request guard for "single front controller" deployments.
 *
 * This is intentionally conservative and lightweight:
 * - deny obviously malicious request URIs (path traversal, stream wrappers),
 * - enforce a reasonable URI length limit,
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

        $uri = $server['REQUEST_URI'] ?? null;
        if (!is_string($uri) || $uri === '') {
            throw new \RuntimeException('Missing REQUEST_URI.');
        }

        if (str_contains($uri, "\0")) {
            throw new \RuntimeException('Invalid REQUEST_URI (null byte).');
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

