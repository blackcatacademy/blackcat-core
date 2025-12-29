<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class TxOutboxException extends \RuntimeException {}

/**
 * Minimal on-disk queue for "transaction intents".
 *
 * Design goals:
 * - never requires private keys in the web runtime,
 * - supports external relayers / monitoring agents (optional),
 * - safe-by-default file writes (no symlink targets, atomic rename).
 *
 * The payload is intentionally generic (method signature + args) so relayers can use
 * tools like Foundry `cast` to encode/broadcast.
 */
final class TxOutbox
{
    private const MAX_PAYLOAD_BYTES = 256 * 1024; // 256 KiB (anti-DoS/disk-fill)

    public readonly string $dir;

    public function __construct(
        string $dir,
    ) {
        $dir = trim($dir);
        $dir = rtrim($dir, "/\\");
        if ($dir === '' || str_contains($dir, "\0")) {
            throw new TxOutboxException('Tx outbox directory is invalid.');
        }

        if (!self::isAbsolutePath($dir)) {
            throw new TxOutboxException('Tx outbox directory must be an absolute path: ' . $dir);
        }

        if (!is_dir($dir) || is_link($dir)) {
            throw new TxOutboxException('Tx outbox directory is not a usable directory: ' . $dir);
        }

        $realDir = realpath($dir);
        if (!is_string($realDir) || trim($realDir) === '') {
            throw new TxOutboxException('Tx outbox directory realpath failed: ' . $dir);
        }
        $realDir = rtrim($realDir, '/\\');

        if (!is_writable($realDir)) {
            throw new TxOutboxException('Tx outbox directory is not writable: ' . $dir);
        }

        // Refuse directories under the web document root (would expose tx intents over HTTP).
        $docRoot = $_SERVER['DOCUMENT_ROOT'] ?? null;
        if (is_string($docRoot)) {
            $docRoot = trim($docRoot);
            if ($docRoot !== '' && !str_contains($docRoot, "\0")) {
                $docReal = realpath($docRoot);
                if (is_string($docReal) && trim($docReal) !== '') {
                    $docReal = rtrim($docReal, '/\\') . DIRECTORY_SEPARATOR;
                    $dirPrefix = $realDir . DIRECTORY_SEPARATOR;
                    if (str_starts_with($dirPrefix, $docReal)) {
                        throw new TxOutboxException('Tx outbox directory must not be under DOCUMENT_ROOT: ' . $dir);
                    }
                }
            }
        }

        // Basic hardening: the outbox directory must not be world-writable.
        // If an attacker can write arbitrary intent files, they can at least spam relayers.
        if (DIRECTORY_SEPARATOR !== '\\') {
            $st = @stat($realDir);
            if (is_array($st)) {
                $mode = (int) ($st['mode'] ?? 0);
                $perms = $mode & 0o777;
                if (($perms & 0o002) !== 0) {
                    throw new TxOutboxException('Tx outbox directory must not be world-writable: ' . $dir);
                }
            }
        }

        $this->dir = $realDir;
    }

    public static function isConfiguredFromRuntimeConfig(): bool
    {
        return self::fromRuntimeConfigBestEffort() !== null;
    }

    public static function fromRuntimeConfigBestEffort(): ?self
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
        $raw = $repo->$get('trust.web3.tx_outbox_dir');
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

        try {
            return new self($path);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * @param array<string,mixed> $payload
     * @return string written file path
     */
    public function enqueue(array $payload): string
    {
        return $this->enqueueWithPrefix('tx', $payload);
    }

    /**
     * @param array<string,mixed> $payload
     * @return string written file path
     */
    public function enqueueWithPrefix(string $prefix, array $payload): string
    {
        $prefix = strtolower(trim($prefix));
        if ($prefix === '' || str_contains($prefix, "\0")) {
            throw new TxOutboxException('Tx outbox prefix is invalid.');
        }
        if (!preg_match('/^[a-z][a-z0-9_-]{0,20}$/', $prefix)) {
            throw new TxOutboxException('Tx outbox prefix must match /^[a-z][a-z0-9_-]{0,20}$/');
        }

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        if (!is_string($json)) {
            throw new TxOutboxException('Tx outbox payload JSON encode failed.');
        }
        if (strlen($json) > self::MAX_PAYLOAD_BYTES) {
            throw new TxOutboxException('Tx outbox payload is too large.');
        }

        $base = $prefix . '.' . gmdate('Ymd\\THis\\Z') . '.' . bin2hex(random_bytes(6));
        $tmp = $this->dir . DIRECTORY_SEPARATOR . $base . '.tmp';
        $final = $this->dir . DIRECTORY_SEPARATOR . $base . '.json';

        $fp = @fopen($tmp, 'xb');
        if ($fp === false) {
            throw new TxOutboxException('Tx outbox could not create temp file in: ' . $this->dir);
        }

        try {
            $bytes = fwrite($fp, $json . "\n");
            if ($bytes === false) {
                throw new TxOutboxException('Tx outbox write failed.');
            }
        } finally {
            fclose($fp);
        }

        if (DIRECTORY_SEPARATOR !== '\\') {
            @chmod($tmp, 0640);
        }

        if (!@rename($tmp, $final)) {
            @unlink($tmp);
            throw new TxOutboxException('Tx outbox could not move file into place.');
        }

        if (DIRECTORY_SEPARATOR !== '\\') {
            @chmod($final, 0640);
        }

        return $final;
    }

    private static function isAbsolutePath(string $path): bool
    {
        if ($path === '') {
            return false;
        }
        if ($path[0] === '/' || $path[0] === '\\') {
            return true;
        }

        return (bool) preg_match('~^[a-zA-Z]:[\\\\/]~', $path);
    }
}
