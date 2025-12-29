<?php

declare(strict_types=1);

namespace BlackCat\Core\Security;

use BlackCat\Core\TrustKernel\TrustKernelException;

final class CryptoAgentException extends \RuntimeException {}

/**
 * Keyless crypto agent client (UNIX socket).
 *
 * Design:
 * - never exports raw key material to the web runtime,
 * - agent enforces TrustKernel read/write gating,
 * - payloads are base64-wrapped to allow binary data in JSON safely.
 */
final class CryptoAgentClient
{
    private const TIMEOUT_SEC = 1;
    private const MAX_REQ_BYTES = 64 * 1024;
    private const MAX_RESP_BYTES = 256 * 1024;

    public static function isConfigured(): bool
    {
        return self::socketPathFromRuntimeConfig() !== null;
    }

    public static function isKeylessMode(): bool
    {
        $socket = self::socketPathFromRuntimeConfig();
        if ($socket === null) {
            return false;
        }

        $mode = self::modeFromRuntimeConfig();
        return $mode === null || $mode === 'keyless';
    }

    public static function socketPathFromRuntimeConfig(): ?string
    {
        if (\function_exists('posix_geteuid')) {
            $euid = @\posix_geteuid();
            if (\is_int($euid) && $euid === 0) {
                return null;
            }
        }

        $configClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'Config']);
        if (!class_exists($configClass) || !is_callable([$configClass, 'isInitialized'])) {
            return null;
        }

        $method = 'isInitialized';
        if (!(bool) $configClass::$method()) {
            return null;
        }

        if (!is_callable([$configClass, 'repo'])) {
            return null;
        }

        $repoMethod = 'repo';
        /** @var mixed $repo */
        $repo = $configClass::$repoMethod();

        if (!is_object($repo) || !method_exists($repo, 'get')) {
            return null;
        }

        $get = 'get';
        /** @var mixed $raw */
        $raw = $repo->$get('crypto.agent.socket_path');
        if (!is_string($raw) || trim($raw) === '' || str_contains($raw, "\0")) {
            return null;
        }

        $path = trim($raw);
        if (method_exists($repo, 'resolvePath')) {
            try {
                $path = $repo->resolvePath($path);
            } catch (\Throwable) {
                return null;
            }
        }

        if (!is_string($path)) {
            return null;
        }

        $path = trim($path);
        if ($path === '' || str_contains($path, "\0")) {
            return null;
        }

        return $path;
    }

    /**
     * @return 'keyless'|'keys'|null
     */
    private static function modeFromRuntimeConfig(): ?string
    {
        $configClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'Config']);
        if (!class_exists($configClass) || !is_callable([$configClass, 'isInitialized'])) {
            return null;
        }

        $method = 'isInitialized';
        if (!(bool) $configClass::$method()) {
            return null;
        }

        if (!is_callable([$configClass, 'repo'])) {
            return null;
        }

        $repoMethod = 'repo';
        /** @var mixed $repo */
        $repo = $configClass::$repoMethod();

        if (!is_object($repo) || !method_exists($repo, 'get')) {
            return null;
        }

        $get = 'get';
        /** @var mixed $raw */
        $raw = $repo->$get('crypto.agent.mode');
        $mode = is_string($raw) ? strtolower(trim($raw)) : '';
        if ($mode === 'keys') {
            return 'keys';
        }
        if ($mode === 'keyless') {
            return 'keyless';
        }

        return null;
    }

    /**
     * @return array{ciphertext:string,key_version:string}
     */
    public static function encryptWithInfo(string $basename, string $plaintext): array
    {
        $socketPath = self::socketPathFromRuntimeConfig();
        if ($socketPath === null) {
            throw new CryptoAgentException('Crypto agent is not configured (missing crypto.agent.socket_path).');
        }

        $res = self::call($socketPath, [
            'op' => 'crypto_encrypt',
            'basename' => $basename,
            'plaintext_b64' => base64_encode($plaintext),
        ]);

        if (($res['ok'] ?? null) !== true) {
            $err = is_string($res['error'] ?? null) ? (string) $res['error'] : 'unknown';
            if ($err === 'denied') {
                throw new TrustKernelException('Denied by TrustKernel: secrets.crypto_encrypt');
            }
            throw new CryptoAgentException('Crypto agent error: ' . $err);
        }

        $cipher = $res['ciphertext'] ?? null;
        if (!is_string($cipher) || trim($cipher) === '' || str_contains($cipher, "\0")) {
            throw new CryptoAgentException('Crypto agent protocol violation: invalid ciphertext.');
        }

        $ver = $res['key_version'] ?? null;
        if (!is_string($ver) || !preg_match('/^v[0-9]+$/', $ver)) {
            throw new CryptoAgentException('Crypto agent protocol violation: invalid key_version.');
        }

        return ['ciphertext' => trim($cipher), 'key_version' => $ver];
    }

    public static function encrypt(string $basename, string $plaintext): string
    {
        $info = self::encryptWithInfo($basename, $plaintext);
        return $info['ciphertext'];
    }

    /**
     * @return array{plaintext:?string,key_version:?string}
     */
    public static function decryptWithInfo(string $basename, string $ciphertext): array
    {
        $socketPath = self::socketPathFromRuntimeConfig();
        if ($socketPath === null) {
            throw new CryptoAgentException('Crypto agent is not configured (missing crypto.agent.socket_path).');
        }

        $res = self::call($socketPath, [
            'op' => 'crypto_decrypt',
            'basename' => $basename,
            'ciphertext' => $ciphertext,
        ]);

        if (($res['ok'] ?? null) !== true) {
            $err = is_string($res['error'] ?? null) ? (string) $res['error'] : 'unknown';
            if ($err === 'denied') {
                throw new TrustKernelException('Denied by TrustKernel: secrets.crypto_decrypt');
            }
            if ($err === 'decrypt_failed') {
                return ['plaintext' => null, 'key_version' => null];
            }
            throw new CryptoAgentException('Crypto agent error: ' . $err);
        }

        $b64 = $res['plaintext_b64'] ?? null;
        if (!is_string($b64) || trim($b64) === '' || str_contains($b64, "\0")) {
            throw new CryptoAgentException('Crypto agent protocol violation: invalid plaintext_b64.');
        }

        $ver = $res['key_version'] ?? null;
        if (!is_string($ver) || !preg_match('/^v[0-9]+$/', $ver)) {
            throw new CryptoAgentException('Crypto agent protocol violation: invalid key_version.');
        }

        $plain = base64_decode($b64, true);
        if (!is_string($plain)) {
            throw new CryptoAgentException('Crypto agent protocol violation: invalid plaintext base64.');
        }

        return ['plaintext' => $plain, 'key_version' => $ver];
    }

    public static function decrypt(string $basename, string $ciphertext): ?string
    {
        $info = self::decryptWithInfo($basename, $ciphertext);
        return $info['plaintext'];
    }

    /**
     * @param array<string,mixed> $payload
     * @return array<string,mixed>
     */
    private static function call(string $socketPath, array $payload): array
    {
        $socketPath = trim($socketPath);
        if ($socketPath === '' || str_contains($socketPath, "\0")) {
            throw new CryptoAgentException('Crypto agent socket path is invalid.');
        }

        try {
            UnixSocketGuard::assertSafeUnixSocketPath($socketPath, UnixSocketGuard::defaultAllowedPrefixes());
        } catch (\Throwable $e) {
            throw new CryptoAgentException('Crypto agent socket rejected: ' . $e->getMessage(), 0, $e);
        }

        $endpoint = 'unix://' . $socketPath;
        $errno = 0;
        $errstr = '';
        $fp = @stream_socket_client($endpoint, $errno, $errstr, (float) self::TIMEOUT_SEC, STREAM_CLIENT_CONNECT);
        if (!is_resource($fp)) {
            throw new CryptoAgentException('Crypto agent connect failed: ' . ($errstr !== '' ? $errstr : 'unknown'));
        }

        stream_set_timeout($fp, self::TIMEOUT_SEC);

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($json)) {
            fclose($fp);
            throw new CryptoAgentException('Crypto agent request JSON encode failed.');
        }
        if (strlen($json) > self::MAX_REQ_BYTES) {
            fclose($fp);
            throw new CryptoAgentException('Crypto agent request is too large.');
        }

        $written = @fwrite($fp, $json . "\n");
        if ($written === false) {
            fclose($fp);
            throw new CryptoAgentException('Crypto agent request write failed.');
        }

        $raw = stream_get_contents($fp, self::MAX_RESP_BYTES + 1);
        fclose($fp);

        if (!is_string($raw) || $raw === '') {
            throw new CryptoAgentException('Crypto agent returned empty response.');
        }
        if (strlen($raw) > self::MAX_RESP_BYTES) {
            throw new CryptoAgentException('Crypto agent response is too large.');
        }

        $raw = trim($raw);

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($raw, true, 256, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new CryptoAgentException('Crypto agent returned invalid JSON.', 0, $e);
        }

        if (!is_array($decoded)) {
            throw new CryptoAgentException('Crypto agent response must decode to an object/array.');
        }

        /** @var array<string,mixed> $decoded */
        return $decoded;
    }
}
