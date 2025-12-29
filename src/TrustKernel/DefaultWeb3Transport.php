<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class DefaultWeb3Transport implements Web3TransportInterface
{
    private const MAX_RESPONSE_BYTES = 1024 * 1024; // 1 MiB

    public function postJson(string $url, string $jsonBody, int $timeoutSec): string
    {
        $url = trim($url);
        if ($url === '' || str_contains($url, "\0")) {
            throw new \InvalidArgumentException('Invalid RPC URL.');
        }

        self::assertAllowedRpcUrl($url);

        $timeoutSec = max(1, $timeoutSec);

        if (function_exists('curl_init')) {
            /** @var \CurlHandle|false $ch */
            $ch = curl_init($url);
            if ($ch === false) {
                throw new \RuntimeException('Unable to initialize curl.');
            }

            $buffer = '';
            $maxBytes = self::MAX_RESPONSE_BYTES;

            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $jsonBody,
                CURLOPT_HTTPHEADER => [
                    'Content-Type: application/json',
                    'Accept: application/json',
                ],
                CURLOPT_CONNECTTIMEOUT => $timeoutSec,
                CURLOPT_TIMEOUT => $timeoutSec,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_MAXREDIRS => 0,
                CURLOPT_WRITEFUNCTION => static function ($ch, string $data) use (&$buffer, $maxBytes): int {
                    $buffer .= $data;
                    if (strlen($buffer) > $maxBytes) {
                        return 0;
                    }
                    return strlen($data);
                },
            ]);

            if (defined('CURLOPT_PROTOCOLS') && defined('CURLPROTO_HTTP') && defined('CURLPROTO_HTTPS')) {
                curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
            }
            if (defined('CURLOPT_REDIR_PROTOCOLS') && defined('CURLPROTO_HTTP') && defined('CURLPROTO_HTTPS')) {
                curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
            }
            if (defined('CURLOPT_SSL_VERIFYPEER')) {
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            }
            if (defined('CURLOPT_SSL_VERIFYHOST')) {
                curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
            }

            $ok = curl_exec($ch);
            if ($ok === false) {
                $err = curl_error($ch);
                curl_close($ch);
                if (strlen($buffer) > self::MAX_RESPONSE_BYTES) {
                    throw new \RuntimeException('RPC response too large (possible malicious endpoint or MITM).');
                }
                throw new \RuntimeException('RPC request failed (curl): ' . $err);
            }

            $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($code < 200 || $code >= 300) {
                throw new \RuntimeException('RPC HTTP error: ' . $code);
            }

            if ($buffer === '') {
                throw new \RuntimeException('RPC returned empty response.');
            }

            return $buffer;
        }

        /** @var array<string,mixed>|false $parsed */
        $parsed = parse_url($url);
        $host = is_array($parsed) ? ($parsed['host'] ?? null) : null;

        $ssl = [
            // Fail closed: do NOT allow bypassing TLS verification via global php.ini / stream defaults.
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false,
            'SNI_enabled' => true,
            'disable_compression' => true,
        ];
        if (is_string($host) && $host !== '') {
            $ssl['peer_name'] = $host;
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json\r\nAccept: application/json\r\n",
                'content' => $jsonBody,
                'timeout' => $timeoutSec,
                'follow_location' => 0,
                'max_redirects' => 0,
            ],
            'ssl' => $ssl,
        ]);

        /** @var array<int,string>|null $http_response_header */
        $http_response_header = null;
        $fp = @fopen($url, 'rb', false, $context);
        if (!is_resource($fp)) {
            throw new \RuntimeException('RPC request failed.');
        }

        $out = '';
        $maxBytes = self::MAX_RESPONSE_BYTES;
        try {
            while (!feof($fp)) {
                $chunk = fread($fp, 8192);
                if (!is_string($chunk)) {
                    break;
                }
                $out .= $chunk;
                if (strlen($out) > $maxBytes) {
                    throw new \RuntimeException('RPC response too large (possible malicious endpoint or MITM).');
                }
            }
        } finally {
            fclose($fp);
        }

        if ($out === '') {
            throw new \RuntimeException('RPC request failed.');
        }

        $statusLine = is_array($http_response_header) ? ($http_response_header[0] ?? null) : null;
        if (is_string($statusLine) && preg_match('/^HTTP\\/\\d+\\.\\d+\\s+(\\d{3})\\b/', $statusLine, $m)) {
            $code = (int) $m[1];
            if ($code < 200 || $code >= 300) {
                throw new \RuntimeException('RPC HTTP error: ' . $code);
            }
        }

        return $out;
    }

    private static function assertAllowedRpcUrl(string $url): void
    {
        $parts = parse_url($url);
        if (!is_array($parts)) {
            throw new \InvalidArgumentException('Invalid RPC URL.');
        }

        $scheme = $parts['scheme'] ?? null;
        $host = $parts['host'] ?? null;
        $user = $parts['user'] ?? null;
        $pass = $parts['pass'] ?? null;

        if (!is_string($scheme) || $scheme === '') {
            throw new \InvalidArgumentException('RPC URL must include a scheme (http/https).');
        }
        $scheme = strtolower($scheme);
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new \InvalidArgumentException('RPC URL scheme not allowed: ' . $scheme);
        }

        if (!is_string($host) || $host === '') {
            throw new \InvalidArgumentException('RPC URL must include a host.');
        }
        $host = self::normalizeHost($host);

        // SSRF hardening: reject private/reserved IP literals (except loopback).
        if (filter_var($host, FILTER_VALIDATE_IP) !== false && !self::isLoopbackHost($host)) {
            $flags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
            if (filter_var($host, FILTER_VALIDATE_IP, $flags) === false) {
                throw new \InvalidArgumentException('RPC URL host must not be a private/reserved IP address.');
            }
        }

        // Ban unencrypted RPC by default. Allow HTTP only for loopback (localhost dev nodes).
        if ($scheme === 'http' && !self::isLoopbackHost($host)) {
            throw new \InvalidArgumentException('RPC URL must use https (http is only allowed for localhost).');
        }

        // Avoid accidental secret leaks via basic auth in URLs.
        if (is_string($user) || is_string($pass)) {
            throw new \InvalidArgumentException('RPC URL must not include username/password.');
        }
    }

    private static function isLoopbackHost(string $host): bool
    {
        $host = self::normalizeHost($host);
        if ($host === 'localhost' || $host === '127.0.0.1' || $host === '::1') {
            return true;
        }

        return false;
    }

    private static function normalizeHost(string $host): string
    {
        $host = strtolower(trim($host));
        if ($host === '') {
            return '';
        }
        if (str_starts_with($host, '[') && str_ends_with($host, ']') && strlen($host) > 2) {
            $inner = substr($host, 1, -1);
            if (is_string($inner) && $inner !== '') {
                $host = $inner;
            }
        }
        return $host;
    }
}
