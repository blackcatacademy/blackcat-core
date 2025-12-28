<?php

declare(strict_types=1);

namespace BlackCat\Core\Security;

/**
 * Trusted-proxy + forwarded-header guard.
 *
 * Goals:
 * - Prevent clients from spoofing forwarding headers (proto/host/for) unless they come from a trusted proxy.
 * - Optionally "honor" X-Forwarded-Proto=https when the immediate peer is trusted.
 *
 * This is not a WAF. It is a conservative safety belt for kernel-only deployments.
 */
final class TrustedProxyGuard
{
    /**
     * @param array<string,mixed> $server Typically $_SERVER
     * @param list<string> $trustedProxies IPs/CIDRs (e.g. "127.0.0.1", "::1", "10.0.0.0/8")
     * @throws \RuntimeException when forwarded headers are present from an untrusted peer
     */
    public static function assertNoUntrustedForwardedHeaders(array $server, array $trustedProxies): void
    {
        if (!self::hasForwardedHeaders($server)) {
            return;
        }

        $remoteAddr = $server['REMOTE_ADDR'] ?? null;
        if (!is_string($remoteAddr) || trim($remoteAddr) === '') {
            throw new \RuntimeException('Forwarded headers present but REMOTE_ADDR is missing.');
        }

        if (!self::isTrustedPeer($remoteAddr, $trustedProxies)) {
            throw new \RuntimeException('Untrusted forwarded headers from remote peer: ' . $remoteAddr);
        }
    }

    /**
     * @param array<string,mixed> $server Typically $_SERVER
     * @param list<string> $trustedProxies
     */
    public static function isForwardedHttpsFromTrustedProxy(array $server, array $trustedProxies): bool
    {
        $remoteAddr = $server['REMOTE_ADDR'] ?? null;
        if (!is_string($remoteAddr) || trim($remoteAddr) === '') {
            return false;
        }
        if (!self::isTrustedPeer($remoteAddr, $trustedProxies)) {
            return false;
        }

        $proto = self::forwardedProto($server);
        return $proto === 'https';
    }

    /**
     * Return the normalized forwarded proto ("https"|"http") if present.
     *
     * @param array<string,mixed> $server
     */
    public static function forwardedProto(array $server): ?string
    {
        $raw = $server['HTTP_X_FORWARDED_PROTO'] ?? null;
        if (!is_string($raw)) {
            return null;
        }

        // Common proxy format: "https" or "https,http"
        $first = trim(explode(',', $raw, 2)[0] ?? '');
        $first = strtolower($first);

        if ($first === 'https') {
            return 'https';
        }
        if ($first === 'http') {
            return 'http';
        }

        return null;
    }

    /**
     * @param array<string,mixed> $server
     */
    private static function hasForwardedHeaders(array $server): bool
    {
        foreach ([
            'HTTP_X_FORWARDED_PROTO',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED_HOST',
            'HTTP_X_FORWARDED_PORT',
            'HTTP_FORWARDED',
        ] as $key) {
            if (array_key_exists($key, $server)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<string> $trustedProxies
     */
    private static function isTrustedPeer(string $remoteAddr, array $trustedProxies): bool
    {
        $remoteAddr = trim($remoteAddr);
        if ($remoteAddr === '' || str_contains($remoteAddr, "\0")) {
            return false;
        }

        if (@filter_var($remoteAddr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            foreach ($trustedProxies as $rule) {
                if (self::matchIpv4($remoteAddr, $rule)) {
                    return true;
                }
            }
            return false;
        }

        if (@filter_var($remoteAddr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            foreach ($trustedProxies as $rule) {
                if (self::matchIpv6($remoteAddr, $rule)) {
                    return true;
                }
            }
            return false;
        }

        return false;
    }

    private static function matchIpv4(string $ip, string $rule): bool
    {
        $rule = trim($rule);
        if ($rule === '') {
            return false;
        }

        if (str_contains($rule, '/')) {
            [$net, $bitsRaw] = explode('/', $rule, 2) + [null, null];
            if (!is_string($net) || !is_string($bitsRaw)) {
                return false;
            }
            if (@filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
                return false;
            }
            $bitsRaw = trim($bitsRaw);
            if ($bitsRaw === '' || !ctype_digit($bitsRaw)) {
                return false;
            }
            $bits = (int) $bitsRaw;
            if ($bits < 0 || $bits > 32) {
                return false;
            }
            $mask = $bits === 0 ? 0 : (-1 << (32 - $bits)) & 0xFFFFFFFF;
            $ipLong = ip2long($ip);
            $netLong = ip2long($net);
            if ($ipLong === false || $netLong === false) {
                return false;
            }
            return (($ipLong & $mask) === ($netLong & $mask));
        }

        return $ip === $rule;
    }

    private static function matchIpv6(string $ip, string $rule): bool
    {
        $rule = trim($rule);
        if ($rule === '') {
            return false;
        }

        // Exact match for IPv6.
        if (!str_contains($rule, '/')) {
            if (@filter_var($rule, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
                return false;
            }
            return strtolower($ip) === strtolower($rule);
        }

        [$net, $bitsRaw] = explode('/', $rule, 2) + [null, null];
        if (!is_string($net) || !is_string($bitsRaw)) {
            return false;
        }
        if (@filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
            return false;
        }
        $bitsRaw = trim($bitsRaw);
        if ($bitsRaw === '' || !ctype_digit($bitsRaw)) {
            return false;
        }
        $bits = (int) $bitsRaw;
        if ($bits < 0 || $bits > 128) {
            return false;
        }

        $ipBin = @inet_pton($ip);
        $netBin = @inet_pton($net);
        if (!is_string($ipBin) || !is_string($netBin)) {
            return false;
        }

        $bytes = intdiv($bits, 8);
        $rem = $bits % 8;

        if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($netBin, 0, $bytes)) {
            return false;
        }

        if ($rem === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $rem)) & 0xFF;
        $ipByte = ord($ipBin[$bytes]);
        $netByte = ord($netBin[$bytes]);

        return (($ipByte & $mask) === ($netByte & $mask));
    }
}

