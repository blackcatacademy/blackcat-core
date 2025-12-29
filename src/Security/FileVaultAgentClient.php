<?php

declare(strict_types=1);

namespace BlackCat\Core\Security;

use BlackCat\Core\TrustKernel\TrustKernelException;

final class FileVaultAgentException extends \RuntimeException {}

/**
 * FileVault keyless operations via secrets-agent (UNIX socket).
 *
 * Protocol:
 * - request is a single JSON line (<= 64KB) terminated by "\n"
 * - payload bytes follow (not JSON/base64) and are streamed to the agent
 * - response starts with a single JSON line terminated by "\n"
 * - response bytes follow (encrypted/decrypted payload) until EOF
 *
 * This avoids sending large blobs over JSON while keeping all key usage inside the boundary.
 */
final class FileVaultAgentClient
{
    private const TIMEOUT_SEC = 60;
    private const MAX_HEADER_BYTES = 64 * 1024;
    private const IO_CHUNK = 1024 * 1024; // 1 MiB

    public static function isConfigured(): bool
    {
        return CryptoAgentClient::socketPathFromRuntimeConfig() !== null;
    }

    /**
     * Encrypts a plaintext stream and writes the encrypted payload to $outCipherStream.
     *
     * @param resource $inPlainStream
     * @param resource $outCipherStream
     * @return array<string,mixed> meta payload returned by agent
     */
    public static function encryptStream(
        string $basename,
        int $plainSize,
        mixed $inPlainStream,
        mixed $outCipherStream,
        ?string $context = null,
    ): array
    {
        if (!is_resource($inPlainStream) || !is_resource($outCipherStream)) {
            throw new FileVaultAgentException('FileVault agent client: invalid streams.');
        }
        if ($plainSize < 0) {
            throw new FileVaultAgentException('FileVault agent client: invalid plainSize.');
        }

        $socketPath = CryptoAgentClient::socketPathFromRuntimeConfig();
        if ($socketPath === null) {
            throw new FileVaultAgentException('FileVault agent is not configured (missing crypto.agent.socket_path).');
        }

        $fp = self::connect($socketPath);

        $payload = [
            'op' => 'filevault_encrypt_stream',
            'basename' => $basename,
            'plain_size' => $plainSize,
        ];
        if (is_string($context) && trim($context) !== '' && !str_contains($context, "\0")) {
            $payload['context'] = trim($context);
        }

        self::writeJsonLine($fp, $payload);

        $sent = self::copyExact($inPlainStream, $fp, $plainSize);
        if ($sent !== $plainSize) {
            fclose($fp);
            throw new FileVaultAgentException('FileVault agent client: plaintext stream length mismatch.');
        }

        @stream_socket_shutdown($fp, STREAM_SHUT_WR);

        $resp = self::readJsonLine($fp);
        self::assertOk($resp, 'secrets.filevault_encrypt');

        $cipherSize = $resp['cipher_size'] ?? null;
        if (!is_int($cipherSize)) {
            if (is_string($cipherSize) && ctype_digit(trim($cipherSize))) {
                $cipherSize = (int) trim($cipherSize);
            }
        }
        if (!is_int($cipherSize) || $cipherSize < 0) {
            fclose($fp);
            throw new FileVaultAgentException('FileVault agent protocol violation: missing/invalid cipher_size.');
        }

        $written = self::copyExact($fp, $outCipherStream, $cipherSize);
        fclose($fp);

        if ($written !== $cipherSize) {
            throw new FileVaultAgentException('FileVault agent client: ciphertext stream truncated.');
        }

        $meta = $resp['meta'] ?? null;
        if (!is_array($meta)) {
            throw new FileVaultAgentException('FileVault agent protocol violation: meta must be an object.');
        }

        /** @var array<string,mixed> $meta */
        return $meta;
    }

    /**
     * Decrypts an encrypted stream and writes plaintext bytes to $outPlainStream.
     *
     * @param resource $inCipherStream
     * @param resource $outPlainStream
     * @return array{plain_size:int|null,key_version:string|null}
     */
    public static function decryptStream(
        string $basename,
        int $cipherSize,
        mixed $inCipherStream,
        mixed $outPlainStream,
    ): array
    {
        if (!is_resource($inCipherStream) || !is_resource($outPlainStream)) {
            throw new FileVaultAgentException('FileVault agent client: invalid streams.');
        }
        if ($cipherSize < 0) {
            throw new FileVaultAgentException('FileVault agent client: invalid cipherSize.');
        }

        $socketPath = CryptoAgentClient::socketPathFromRuntimeConfig();
        if ($socketPath === null) {
            throw new FileVaultAgentException('FileVault agent is not configured (missing crypto.agent.socket_path).');
        }

        $fp = self::connect($socketPath);

        self::writeJsonLine($fp, [
            'op' => 'filevault_decrypt_stream',
            'basename' => $basename,
            'cipher_size' => $cipherSize,
        ]);

        $sent = self::copyExact($inCipherStream, $fp, $cipherSize);
        if ($sent !== $cipherSize) {
            fclose($fp);
            throw new FileVaultAgentException('FileVault agent client: ciphertext stream length mismatch.');
        }

        @stream_socket_shutdown($fp, STREAM_SHUT_WR);

        $resp = self::readJsonLine($fp);
        if (($resp['ok'] ?? null) !== true) {
            $err = is_string($resp['error'] ?? null) ? (string) $resp['error'] : 'unknown';
            fclose($fp);
            if ($err === 'denied') {
                throw new TrustKernelException('Denied by TrustKernel: secrets.filevault_decrypt');
            }
            if ($err === 'decrypt_failed') {
                return ['plain_size' => null, 'key_version' => null];
            }
            throw new FileVaultAgentException('FileVault agent error: ' . $err);
        }

        $plainSize = $resp['plain_size'] ?? null;
        if (!is_int($plainSize)) {
            if (is_string($plainSize) && ctype_digit(trim($plainSize))) {
                $plainSize = (int) trim($plainSize);
            }
        }
        if (!is_int($plainSize) || $plainSize < 0) {
            fclose($fp);
            throw new FileVaultAgentException('FileVault agent protocol violation: missing/invalid plain_size.');
        }

        $keyVer = $resp['key_version'] ?? null;
        if (!is_string($keyVer) || !preg_match('/^v[0-9]+$/', $keyVer)) {
            $keyVer = null;
        }

        $written = self::copyExact($fp, $outPlainStream, $plainSize);
        fclose($fp);

        if ($written !== $plainSize) {
            throw new FileVaultAgentException('FileVault agent client: plaintext stream truncated.');
        }

        return ['plain_size' => $plainSize, 'key_version' => $keyVer];
    }

    private static function connect(string $socketPath): mixed
    {
        $socketPath = trim($socketPath);
        if ($socketPath === '' || str_contains($socketPath, "\0")) {
            throw new FileVaultAgentException('FileVault agent socket path is invalid.');
        }

        $endpoint = 'unix://' . $socketPath;
        $errno = 0;
        $errstr = '';
        $fp = @stream_socket_client($endpoint, $errno, $errstr, (float) self::TIMEOUT_SEC, STREAM_CLIENT_CONNECT);
        if (!is_resource($fp)) {
            throw new FileVaultAgentException('FileVault agent connect failed: ' . ($errstr !== '' ? $errstr : 'unknown'));
        }

        stream_set_timeout($fp, self::TIMEOUT_SEC);
        return $fp;
    }

    /**
     * @param resource $fp
     * @param array<string,mixed> $payload
     */
    private static function writeJsonLine(mixed $fp, array $payload): void
    {
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($json)) {
            throw new FileVaultAgentException('FileVault agent request JSON encode failed.');
        }
        if (strlen($json) > self::MAX_HEADER_BYTES) {
            throw new FileVaultAgentException('FileVault agent request header is too large.');
        }

        $written = @fwrite($fp, $json . "\n");
        if ($written === false) {
            throw new FileVaultAgentException('FileVault agent request write failed.');
        }
    }

    /**
     * @param resource $fp
     * @return array<string,mixed>
     */
    private static function readJsonLine(mixed $fp): array
    {
        $line = stream_get_line($fp, self::MAX_HEADER_BYTES + 1, "\n");
        if (!is_string($line) || trim($line) === '') {
            throw new FileVaultAgentException('FileVault agent returned empty response header.');
        }
        if (strlen($line) > self::MAX_HEADER_BYTES) {
            throw new FileVaultAgentException('FileVault agent response header is too large.');
        }

        $line = trim($line);
        try {
            /** @var mixed $decoded */
            $decoded = json_decode($line, true, 256, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new FileVaultAgentException('FileVault agent returned invalid JSON header.', 0, $e);
        }

        if (!is_array($decoded)) {
            throw new FileVaultAgentException('FileVault agent response header must decode to an object/array.');
        }

        /** @var array<string,mixed> $decoded */
        return $decoded;
    }

    /**
     * @param array<string,mixed> $resp
     */
    private static function assertOk(array $resp, string $deniedContext): void
    {
        if (($resp['ok'] ?? null) === true) {
            return;
        }

        $err = is_string($resp['error'] ?? null) ? (string) $resp['error'] : 'unknown';
        if ($err === 'denied') {
            throw new TrustKernelException('Denied by TrustKernel: ' . $deniedContext);
        }
        throw new FileVaultAgentException('FileVault agent error: ' . $err);
    }

    /**
     * Copy exactly $len bytes from $in to $out (both streams).
     *
     * @param resource $in
     * @param resource $out
     */
    private static function copyExact(mixed $in, mixed $out, int $len): int
    {
        $remaining = $len;
        $writtenTotal = 0;

        while ($remaining > 0) {
            $want = min(self::IO_CHUNK, $remaining);
            $buf = fread($in, $want);
            if ($buf === false || $buf === '') {
                break;
            }

            $off = 0;
            $blen = strlen($buf);
            while ($off < $blen) {
                $w = fwrite($out, substr($buf, $off));
                if ($w === false || $w === 0) {
                    return $writtenTotal;
                }
                $off += $w;
                $writtenTotal += $w;
                $remaining -= $w;
            }
        }

        return $writtenTotal;
    }
}

