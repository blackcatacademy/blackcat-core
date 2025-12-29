<?php
declare(strict_types=1);

namespace BlackCat\Core\Log;

/**
 * libs/AuditLogger.php
 *
 * Robust audit logger with DB primary and file fallback storage.
 * - Prefers $_ENV values for paths (non-environment dependent setups supported via $GLOBALS['config'])
 * - Atomic file writes with tempfile  rename and append-with-lock fallback
 * - Safe file permissions
 *
 * API:
 *   AuditLogger::log(?PDO $pdo, $actorId, string $action, string $payloadEnc, string $keyVersion = '', array $meta = []): bool
 */

final class AuditLogger
{
    private static ?string $auditDirOverride = null;

    /**
     * Override audit directory resolution for non-ENV environments.
     */
    public static function setAuditDir(string $dir): void
    {
        self::$auditDirOverride = rtrim($dir, DIRECTORY_SEPARATOR);
    }

    /**
     * Public API: attempt to write audit entry to DB, fallback to file.
     * Returns true on success (DB or file), false on failure.
     *
     * @param \PDO|null $pdo
     * @param mixed $actorId anything that can be stringified (or null)
     * @param string $action
     * @param string $payloadEnc JSON or encoded payload string
     * @param string $keyVersion
     * @param array $meta
     * @return bool
     */
    public static function log(?\PDO $pdo, $actorId, string $action, string $payloadEnc, string $keyVersion = '', array $meta = []): bool
    {
        // NOTE: DB writes removed from core (no table-specific SQL/PDO in kernel).
        unset($pdo);
        $now = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s');

        // File-based audit
        try {
            return self::fileFallback($now, (string)($actorId ?? ''), $action, $payloadEnc, $keyVersion, $meta);
        } catch (\Throwable $e) {
            // Never let audit failure kill the app
            error_log('[AuditLogger] file fallback failed: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Resolve audit directory (priority: $_ENV -> $GLOBALS['config'] -> storage/audit default)
     * @return string
     */
    private static function resolveAuditDir(): string
    {
        if (self::$auditDirOverride !== null) {
            return self::$auditDirOverride;
        }
        if (!empty($_ENV['AUDIT_PATH'])) {
            return rtrim($_ENV['AUDIT_PATH'], DIRECTORY_SEPARATOR);
        }
        if (isset($GLOBALS['config']) && is_array($GLOBALS['config']) && !empty($GLOBALS['config']['paths']['audit'])) {
            return rtrim($GLOBALS['config']['paths']['audit'], DIRECTORY_SEPARATOR);
        }
        // fallback to storage path
        if (!empty($_ENV['STORAGE_PATH'])) {
            return rtrim($_ENV['STORAGE_PATH'], DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'audit';
        }
        if (isset($GLOBALS['config']) && is_array($GLOBALS['config']) && !empty($GLOBALS['config']['paths']['storage'])) {
            return rtrim($GLOBALS['config']['paths']['storage'], DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'audit';
        }
        // last resort relative path
        return __DIR__ . '/../storage/audit';
    }

    /**
     * Write audit entry to file in an atomic, locked manner.
     *
     * @param string $timestamp
     * @param string $actorId
     * @param string $action
     * @param string $payloadEnc
     * @param string $keyVersion
     * @param array $meta
     * @return bool
     * @throws \RuntimeException
     */
    private static function fileFallback(string $timestamp, string $actorId, string $action, string $payloadEnc, string $keyVersion, array $meta): bool
    {
        $auditDir = self::resolveAuditDir();
        $auditDir = rtrim($auditDir, DIRECTORY_SEPARATOR);
        if ($auditDir === '' || str_contains($auditDir, "\0")) {
            throw new \RuntimeException('AuditLogger: invalid audit dir');
        }
        if (is_link($auditDir)) {
            throw new \RuntimeException('AuditLogger: audit dir must not be a symlink: ' . $auditDir);
        }
        // ensure dir exists
        if (!is_dir($auditDir)) {
            if (!@mkdir($auditDir, 0700, true) && !is_dir($auditDir)) {
                throw new \RuntimeException('AuditLogger: failed to create audit dir: ' . $auditDir);
            }
            @chmod($auditDir, 0700);
        }
        clearstatcache(true, $auditDir);
        if (@readlink($auditDir) !== false) {
            throw new \RuntimeException('AuditLogger: audit dir must not be a symlink: ' . $auditDir);
        }
        if (DIRECTORY_SEPARATOR !== '\\') {
            $st = @stat($auditDir);
            if (is_array($st)) {
                $mode = (int) ($st['mode'] ?? 0);
                $perms = $mode & 0o777;
                if (($perms & 0o002) !== 0) {
                    throw new \RuntimeException('AuditLogger: audit dir must not be world-writable: ' . $auditDir);
                }
            }
        }

        $entry = [
            'ts' => $timestamp,
            'actor' => $actorId,
            'action' => $action,
            'payload' => $payloadEnc,
            'kv' => $keyVersion,
            'meta' => $meta,
            'host' => function_exists('gethostname') ? gethostname() : php_uname('n'),
        ];
        $line = json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($line === false) {
            throw new \RuntimeException('AuditLogger: json_encode failed');
        }
        $line .= PHP_EOL;

        // create a tempfile in same dir
        $tmp = tempnam($auditDir, 'audit_');
        if ($tmp === false) {
            throw new \RuntimeException('AuditLogger: temp file creation failed in ' . $auditDir);
        }

        $fp = @fopen($tmp, 'cb');
        if ($fp === false) {
            @unlink($tmp);
            throw new \RuntimeException('AuditLogger: cannot open temp file for write: ' . $tmp);
        }

        try {
            if (!flock($fp, LOCK_EX)) {
                throw new \RuntimeException('AuditLogger: flock failed on ' . $tmp);
            }
            $bytes = fwrite($fp, $line);
            if ($bytes === false || $bytes < strlen($line)) {
                throw new \RuntimeException('AuditLogger: incomplete write to temp file');
            }
            fflush($fp);
            // permissions will be set on the filename after closing for portability
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
            @chmod($tmp, 0600); // portable: chmod by filename, works across platforms
        }

        $final = $auditDir . DIRECTORY_SEPARATOR . 'audit.log';
        if (is_link($final)) {
            throw new \RuntimeException('AuditLogger: refusing symlink audit.log: ' . $final);
        }

        // If final doesn't exist, try rename (atomic create)
        if (!file_exists($final)) {
            if (!@rename($tmp, $final)) {
                // rename failed -> try append fallback
                $ok = self::appendFile($final, $line);
                @unlink($tmp);
                if (!$ok) {
                    throw new \RuntimeException('AuditLogger: rename to final failed and append fallback failed');
                }
                @chmod($final, 0600);
                return true;
            }
            @chmod($final, 0600);
            return true;
        }

        // final exists -> append safely
        $ok = self::appendFile($final, $line);
        @unlink($tmp);
        if ($ok) {
            @chmod($final, 0600);
            return true;
        }
        throw new \RuntimeException('AuditLogger: append to final failed');
    }

    /**
     * Append a line to a file with locking. Creates file if not exists.
     * @param string $file
     * @param string $line
     * @return bool
     */
    private static function appendFile(string $file, string $line): bool
    {
        if (is_link($file)) {
            return false;
        }
        $fp = @fopen($file, 'cb');
        if ($fp === false) return false;
        $ok = false;
        try {
            if (!flock($fp, LOCK_EX)) return false;
            if (fseek($fp, 0, SEEK_END) === 0) {
                $bytes = fwrite($fp, $line);
                if ($bytes !== false && $bytes >= strlen($line)) {
                    fflush($fp);
                    $ok = true;
                }
            }
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
            @chmod($file, 0600);
        }
        return $ok;
    }
}
