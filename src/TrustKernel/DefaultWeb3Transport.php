<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class DefaultWeb3Transport implements Web3TransportInterface
{
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

            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $jsonBody,
                CURLOPT_HTTPHEADER => [
                    'Content-Type: application/json',
                    'Accept: application/json',
                ],
                CURLOPT_CONNECTTIMEOUT => $timeoutSec,
                CURLOPT_TIMEOUT => $timeoutSec,
                CURLOPT_FOLLOWLOCATION => false,
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

            $out = curl_exec($ch);
            if ($out === false) {
                $err = curl_error($ch);
                curl_close($ch);
                throw new \RuntimeException('RPC request failed (curl): ' . $err);
            }

            $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($code < 200 || $code >= 300) {
                throw new \RuntimeException('RPC HTTP error: ' . $code);
            }

            if (!is_string($out) || $out === '') {
                throw new \RuntimeException('RPC returned empty response.');
            }

            return $out;
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
        ]);

        /** @var array<int,string>|null $http_response_header */
        $http_response_header = null;
        $out = @file_get_contents($url, false, $context);
        if (!is_string($out) || $out === '') {
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

        // Avoid accidental secret leaks via basic auth in URLs.
        if (is_string($user) || is_string($pass)) {
            throw new \InvalidArgumentException('RPC URL must not include username/password.');
        }
    }
}
