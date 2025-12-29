<?php

declare(strict_types=1);

namespace BlackCat\Core\Database;

use BlackCat\Core\Security\UnixSocketGuard;
use BlackCat\Core\TrustKernel\TrustKernelException;

final class DbCredentialsAgentException extends \RuntimeException {}

/**
 * Minimal client for the local secrets-agent (UNIX socket).
 *
 * Purpose:
 * - keep DB credentials out of the web runtime config surface,
 * - allow the agent to enforce TrustKernel read/write permissions before releasing credentials.
 */
final class DbCredentialsAgentClient
{
    private const TIMEOUT_SEC = 1;
    private const MAX_REQ_BYTES = 8 * 1024;
    private const MAX_RESP_BYTES = 64 * 1024;

    public static function isConfigured(): bool
    {
        return self::socketPathFromRuntimeConfig() !== null;
    }

    public static function socketPathFromRuntimeConfig(): ?string
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
        $raw = $repo->$get('db.agent.socket_path');
        if (!is_string($raw) || trim($raw) === '') {
            /** @var mixed $fallback */
            $fallback = $repo->$get('crypto.agent.socket_path');
            $raw = is_string($fallback) ? $fallback : null;
        }

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
     * @return array{dsn:string,user:string,pass:string}
     */
    public static function fetch(string $role): array
    {
        $role = strtolower(trim($role));
        if (!in_array($role, ['read', 'write'], true)) {
            throw new DbCredentialsAgentException('Invalid DB credentials role (expected read|write).');
        }

        $socketPath = self::socketPathFromRuntimeConfig();
        if ($socketPath === null) {
            throw new DbCredentialsAgentException('DB credentials agent is not configured (missing db.agent.socket_path).');
        }

        $res = self::call($socketPath, [
            'op' => 'get_db_credentials',
            'role' => $role,
        ]);

        if (($res['ok'] ?? null) !== true) {
            $err = is_string($res['error'] ?? null) ? (string) $res['error'] : 'unknown';
            if ($err === 'denied') {
                throw new TrustKernelException('Denied by TrustKernel: db.credentials.' . $role);
            }
            throw new DbCredentialsAgentException('DB credentials agent error: ' . $err);
        }

        $dsn = $res['dsn'] ?? null;
        $user = $res['user'] ?? null;
        $pass = $res['pass'] ?? null;

        if (!is_string($dsn) || trim($dsn) === '' || str_contains($dsn, "\0")) {
            throw new DbCredentialsAgentException('DB credentials agent protocol violation: invalid dsn.');
        }
        if (!is_string($user) || trim($user) === '' || str_contains($user, "\0")) {
            throw new DbCredentialsAgentException('DB credentials agent protocol violation: invalid user.');
        }
        if (!is_string($pass) || trim($pass) === '' || str_contains($pass, "\0")) {
            throw new DbCredentialsAgentException('DB credentials agent protocol violation: invalid pass.');
        }

        $dsn = trim($dsn);
        $user = trim($user);
        $pass = trim($pass);

        if (strlen($dsn) > 2048 || strlen($user) > 128 || strlen($pass) > 256) {
            throw new DbCredentialsAgentException('DB credentials agent protocol violation: value too large.');
        }

        return [
            'dsn' => $dsn,
            'user' => $user,
            'pass' => $pass,
        ];
    }

    /**
     * @param array<string,mixed> $payload
     * @return array<string,mixed>
     */
    private static function call(string $socketPath, array $payload): array
    {
        $socketPath = trim($socketPath);
        if ($socketPath === '' || str_contains($socketPath, "\0")) {
            throw new DbCredentialsAgentException('DB credentials agent socket path is invalid.');
        }

        try {
            UnixSocketGuard::assertSafeUnixSocketPath($socketPath, UnixSocketGuard::defaultAllowedPrefixes());
        } catch (\Throwable $e) {
            throw new DbCredentialsAgentException('DB credentials agent socket rejected: ' . $e->getMessage(), 0, $e);
        }

        $endpoint = 'unix://' . $socketPath;
        $errno = 0;
        $errstr = '';
        $fp = @stream_socket_client($endpoint, $errno, $errstr, (float) self::TIMEOUT_SEC, STREAM_CLIENT_CONNECT);
        if (!is_resource($fp)) {
            throw new DbCredentialsAgentException('DB credentials agent connect failed: ' . ($errstr !== '' ? $errstr : 'unknown'));
        }

        stream_set_timeout($fp, self::TIMEOUT_SEC);

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($json)) {
            fclose($fp);
            throw new DbCredentialsAgentException('DB credentials agent request JSON encode failed.');
        }
        if (strlen($json) > self::MAX_REQ_BYTES) {
            fclose($fp);
            throw new DbCredentialsAgentException('DB credentials agent request is too large.');
        }

        $written = @fwrite($fp, $json . "\n");
        if ($written === false) {
            fclose($fp);
            throw new DbCredentialsAgentException('DB credentials agent request write failed.');
        }

        $raw = stream_get_contents($fp, self::MAX_RESP_BYTES + 1);
        fclose($fp);

        if (!is_string($raw) || $raw === '') {
            throw new DbCredentialsAgentException('DB credentials agent returned empty response.');
        }
        if (strlen($raw) > self::MAX_RESP_BYTES) {
            throw new DbCredentialsAgentException('DB credentials agent response is too large.');
        }

        $raw = trim($raw);

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($raw, true, 128, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new DbCredentialsAgentException('DB credentials agent returned invalid JSON.', 0, $e);
        }

        if (!is_array($decoded)) {
            throw new DbCredentialsAgentException('DB credentials agent response must decode to an object/array.');
        }

        /** @var array<string,mixed> $decoded */
        return $decoded;
    }
}
