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
            ]);

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
            ],
        ]);

        $out = @file_get_contents($url, false, $context);
        if (!is_string($out) || $out === '') {
            throw new \RuntimeException('RPC request failed.');
        }

        return $out;
    }
}

