<?php

declare(strict_types=1);

namespace BlackCat\Core\Security;

/**
 * Trusted-proxy + forwarded-header guard.
 *
 * Goals:
 * - Prevent clients from spoofing forwarding headers (proto/host/for) unless they come from a trusted proxy.
 * - Optionally honor HTTPS forwarding headers (X-Forwarded-Proto / RFC 7239 Forwarded: proto=...)
 *   when the immediate peer is trusted.
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
        if (is_string($raw)) {
            $proto = self::normalizeForwardedProtoToken($raw);
            if ($proto !== null) {
                return $proto;
            }
        }

        // RFC 7239: Forwarded: proto=https; for=...; by=...
        $forwarded = $server['HTTP_FORWARDED'] ?? null;
        if (is_string($forwarded)) {
            return self::parseRfc7239ForwardedProto($forwarded);
        }

        return null;
    }

    private static function normalizeForwardedProtoToken(string $raw): ?string
    {
        $raw = trim($raw);
        if ($raw === '' || str_contains($raw, "\0")) {
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

    private static function parseRfc7239ForwardedProto(string $raw): ?string
    {
        $raw = trim($raw);
        if ($raw === '' || str_contains($raw, "\0")) {
            return null;
        }

        // Parse only the first Forwarded element (left-most), which corresponds to the
        // original request (best-effort). Do not attempt to interpret a chain.
        $element = '';
        $inQuotes = false;
        $len = strlen($raw);
        for ($i = 0; $i < $len; $i++) {
            $ch = $raw[$i];
            if ($ch === '"') {
                $inQuotes = !$inQuotes;
            }
            if ($ch === ',' && !$inQuotes) {
                break;
            }
            $element .= $ch;
        }

        $element = trim($element);
        if ($element === '') {
            return null;
        }

        $params = self::splitOutsideQuotes($element, ';');
        foreach ($params as $param) {
            $param = trim($param);
            if ($param === '') {
                continue;
            }

            $eqPos = strpos($param, '=');
            if ($eqPos === false) {
                continue;
            }

            $key = strtolower(trim(substr($param, 0, $eqPos)));
            if ($key !== 'proto') {
                continue;
            }

            $valueRaw = trim(substr($param, $eqPos + 1));
            if ($valueRaw === '') {
                return null;
            }

            $value = self::unquoteForwardedValue($valueRaw);
            $value = strtolower(trim($value));

            if ($value === 'https') {
                return 'https';
            }
            if ($value === 'http') {
                return 'http';
            }

            return null;
        }

        return null;
    }

    /**
     * Split a string by a delimiter, ignoring delimiters inside quotes.
     *
     * @return list<string>
     */
    private static function splitOutsideQuotes(string $raw, string $delimiter): array
    {
        $out = [];
        $buf = '';
        $inQuotes = false;

        $len = strlen($raw);
        for ($i = 0; $i < $len; $i++) {
            $ch = $raw[$i];
            if ($ch === '"') {
                $inQuotes = !$inQuotes;
            }

            if ($ch === $delimiter && !$inQuotes) {
                $out[] = $buf;
                $buf = '';
                continue;
            }

            $buf .= $ch;
        }

        $out[] = $buf;
        return $out;
    }

    private static function unquoteForwardedValue(string $raw): string
    {
        $raw = trim($raw);
        if ($raw === '') {
            return '';
        }

        if ($raw[0] !== '"' || !str_ends_with($raw, '"')) {
            return $raw;
        }

        $inner = substr($raw, 1, -1);
        $out = '';
        $len = strlen($inner);
        for ($i = 0; $i < $len; $i++) {
            $ch = $inner[$i];
            if ($ch === '\\' && $i + 1 < $len) {
                $i++;
                $out .= $inner[$i];
                continue;
            }
            $out .= $ch;
        }

        return $out;
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
