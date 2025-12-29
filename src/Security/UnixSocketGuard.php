<?php

declare(strict_types=1);

namespace BlackCat\Core\Security;

final class UnixSocketGuard
{
    /**
     * Conservative allowlist for UNIX socket locations.
     *
     * Rationale:
     * - sockets under world-writable dirs (e.g. /tmp) are a common local privilege/escalation surface,
     * - keeping sockets under explicit dirs makes deployments easier to harden (AppArmor/SELinux, mount perms).
     *
     * @return list<string> absolute dir prefixes (with trailing slash)
     */
    public static function defaultAllowedPrefixes(): array
    {
        return [
            '/etc/blackcat/',
            '/var/lib/blackcat/',
            '/run/blackcat/',
            '/var/run/blackcat/',
        ];
    }

    /**
     * Validate a UNIX socket path used for security-critical boundaries (secrets-agent, DB creds agent).
     *
     * @param list<string> $allowedPrefixes absolute prefixes (e.g. "/etc/blackcat/")
     */
    public static function assertSafeUnixSocketPath(string $socketPath, array $allowedPrefixes): void
    {
        $socketPath = trim($socketPath);
        if ($socketPath === '' || str_contains($socketPath, "\0")) {
            throw new \RuntimeException('Socket path is invalid.');
        }

        if (!self::isAbsolutePath($socketPath)) {
            throw new \RuntimeException('Socket path must be absolute.');
        }

        // Keep socket location explicit and predictable.
        $allowed = false;
        foreach ($allowedPrefixes as $prefix) {
            if (!is_string($prefix) || $prefix === '' || str_contains($prefix, "\0")) {
                continue;
            }
            if (str_starts_with($socketPath, $prefix)) {
                $allowed = true;
                break;
            }
        }
        if (!$allowed) {
            throw new \RuntimeException('Socket path is not in an allowed directory.');
        }

        clearstatcache(true, $socketPath);
        if (file_exists($socketPath) && is_link($socketPath)) {
            throw new \RuntimeException('Refusing symlink socket path: ' . $socketPath);
        }

        // If it exists, it must be an actual UNIX socket.
        if (file_exists($socketPath)) {
            $type = @filetype($socketPath);
            if ($type !== 'socket') {
                throw new \RuntimeException('Socket path exists but is not a UNIX socket: ' . $socketPath);
            }
        }

        // Best-effort permission posture checks (POSIX only).
        if (DIRECTORY_SEPARATOR !== '\\') {
            $dir = dirname($socketPath);
            if ($dir !== '' && $dir !== '.' && !str_contains($dir, "\0")) {
                clearstatcache(true, $dir);
                if (is_link($dir)) {
                    throw new \RuntimeException('Socket directory must not be a symlink: ' . $dir);
                }
                $stDir = @stat($dir);
                if (is_array($stDir)) {
                    $mode = (int) ($stDir['mode'] ?? 0);
                    $perms = $mode & 0o777;
                    if (($perms & 0o002) !== 0) {
                        throw new \RuntimeException('Socket directory must not be world-writable: ' . $dir);
                    }
                }
            }

            if (file_exists($socketPath)) {
                $st = @stat($socketPath);
                if (is_array($st)) {
                    $mode = (int) ($st['mode'] ?? 0);
                    $perms = $mode & 0o777;
                    if (($perms & 0o002) !== 0) {
                        throw new \RuntimeException('Socket file must not be world-writable: ' . $socketPath);
                    }
                }
            }
        }
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

