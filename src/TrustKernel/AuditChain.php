<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class AuditChainException extends \RuntimeException {}

/**
 * Tamper-evident audit log (hash chain) anchored by a rolling head hash.
 *
 * Threat model:
 * - protects against offline log tamper AFTER an on-chain anchor exists,
 * - does NOT protect if the attacker fully controls the host and the anchoring pipeline.
 *
 * Design goals:
 * - append-only NDJSON log (no secrets),
 * - chain head stored in a small JSON file for fast reads,
 * - safe-by-default filesystem behavior (no symlink targets, atomic rename, no world-writable dir).
 */
final class AuditChain
{
    private const HEAD_FILE = 'audit.head.json';
    private const LOG_FILE = 'audit.log.ndjson';
    private const LOCK_FILE = '.audit.lock';
    private const MAX_HEAD_BYTES = 64 * 1024; // 64 KiB (bounded read)
    private const MAX_ENTRY_BYTES = 64 * 1024; // 64 KiB (anti-DoS/disk-fill)

    public readonly string $dir;

    public function __construct(
        string $dir,
    ) {
        $dir = trim($dir);
        $dir = rtrim($dir, "/\\");
        if ($dir === '' || str_contains($dir, "\0")) {
            throw new AuditChainException('Audit chain directory is invalid.');
        }

        if (!self::isAbsolutePath($dir)) {
            throw new AuditChainException('Audit chain directory must be an absolute path: ' . $dir);
        }

        if (!is_dir($dir) || is_link($dir)) {
            throw new AuditChainException('Audit chain directory is not a usable directory: ' . $dir);
        }

        $realDir = realpath($dir);
        if (!is_string($realDir) || trim($realDir) === '') {
            throw new AuditChainException('Audit chain directory realpath failed: ' . $dir);
        }
        $realDir = rtrim($realDir, '/\\');

        if (!is_writable($realDir)) {
            throw new AuditChainException('Audit chain directory is not writable: ' . $dir);
        }

        // Refuse directories under the web document root (would expose audit logs over HTTP).
        $docRoot = $_SERVER['DOCUMENT_ROOT'] ?? null;
        if (is_string($docRoot)) {
            $docRoot = trim($docRoot);
            if ($docRoot !== '' && !str_contains($docRoot, "\0")) {
                $docReal = realpath($docRoot);
                if (is_string($docReal) && trim($docReal) !== '') {
                    $docReal = rtrim($docReal, '/\\') . DIRECTORY_SEPARATOR;
                    $dirPrefix = $realDir . DIRECTORY_SEPARATOR;
                    if (str_starts_with($dirPrefix, $docReal)) {
                        throw new AuditChainException('Audit chain directory must not be under DOCUMENT_ROOT: ' . $dir);
                    }
                }
            }
        }

        // Basic hardening: the directory must not be world-writable.
        if (DIRECTORY_SEPARATOR !== '\\') {
            $st = @stat($realDir);
            if (is_array($st)) {
                $mode = (int) ($st['mode'] ?? 0);
                $perms = $mode & 0o777;
                if (($perms & 0o002) !== 0) {
                    throw new AuditChainException('Audit chain directory must not be world-writable: ' . $dir);
                }
            }
        }

        $this->dir = $realDir;
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
        $raw = $repo->$get('trust.audit.dir');
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
     * Append an audit event and advance the head hash.
     *
     * IMPORTANT: Never put secrets into $meta.
     *
     * @param array<string,mixed> $meta
     * @param array<string,mixed>|null $actor
     * @return array{seq:int,head_hash:string,updated_at:string,last_type:string}
     */
    public function append(string $type, array $meta = [], ?array $actor = null): array
    {
        $type = trim($type);
        if ($type === '' || str_contains($type, "\0")) {
            throw new AuditChainException('Audit event type is invalid.');
        }

        $lockPath = $this->path(self::LOCK_FILE);
        if (file_exists($lockPath) && is_link($lockPath)) {
            throw new AuditChainException('Refusing symlink lock file: ' . $lockPath);
        }

        $fp = @fopen($lockPath, 'c');
        if ($fp === false) {
            throw new AuditChainException('Unable to open audit lock file: ' . $lockPath);
        }

        try {
            if (DIRECTORY_SEPARATOR !== '\\') {
                @chmod($lockPath, 0644);
            }
            $this->inheritGroup($lockPath);
            if (!flock($fp, LOCK_EX)) {
                throw new AuditChainException('Unable to lock audit chain.');
            }

            $head = $this->readHeadUnsafe();
            $prev = $head['head_hash'];
            $seq = $head['seq'];

            $nextSeq = $seq + 1;
            $now = gmdate('c');

            // Canonical payload that will be hashed (no "hash" field yet).
            $entry = [
                'schema_version' => 1,
                'seq' => $nextSeq,
                'ts' => $now,
                'type' => $type,
                'actor' => is_array($actor) ? $actor : null,
                'meta' => $meta,
                'prev' => $prev,
            ];

            $entryHash = CanonicalJson::sha256Bytes32($entry);
            $line = $entry;
            $line['hash'] = Bytes32::normalizeHex($entryHash);

            $this->appendLineUnsafe($line);

            $newHead = [
                'schema_version' => 1,
                'seq' => $nextSeq,
                'head_hash' => Bytes32::normalizeHex($entryHash),
                'updated_at' => $now,
                'last_type' => $type,
            ];

            $this->writeHeadUnsafe($newHead);

            return $newHead;
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }

    /**
     * @return array{seq:int,head_hash:string,updated_at:string,last_type:string}
     */
    public function head(): array
    {
        $lockPath = $this->path(self::LOCK_FILE);
        if (file_exists($lockPath) && is_link($lockPath)) {
            throw new AuditChainException('Refusing symlink lock file: ' . $lockPath);
        }

        // No lock file yet (genesis): safe to read without locking.
        if (!is_file($lockPath)) {
            return $this->readHeadUnsafe();
        }

        $fp = @fopen($lockPath, 'rb');
        if ($fp === false) {
            throw new AuditChainException('Unable to open audit lock file for read: ' . $lockPath);
        }

        try {
            if (!flock($fp, LOCK_SH)) {
                throw new AuditChainException('Unable to lock audit chain for read.');
            }
            return $this->readHeadUnsafe();
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }

    /**
     * @return array{seq:int,head_hash:string,updated_at:string,last_type:string}
     */
    private function readHeadUnsafe(): array
    {
        $headPath = $this->path(self::HEAD_FILE);
        $zero = '0x' . str_repeat('00', 32);

        if (!is_file($headPath)) {
            return [
                'schema_version' => 1,
                'seq' => 0,
                'head_hash' => $zero,
                'updated_at' => gmdate('c'),
                'last_type' => 'genesis',
            ];
        }

        clearstatcache(true, $headPath);
        if (is_link($headPath)) {
            throw new AuditChainException('Refusing symlink head file: ' . $headPath);
        }

        $size = @filesize($headPath);
        if (is_int($size) && $size > self::MAX_HEAD_BYTES) {
            throw new AuditChainException('Audit head file is too large.');
        }

        $raw = @file_get_contents($headPath, false, null, 0, self::MAX_HEAD_BYTES + 1);
        if (!is_string($raw) || $raw === '') {
            throw new AuditChainException('Audit head file is empty/unreadable.');
        }
        if (strlen($raw) > self::MAX_HEAD_BYTES) {
            throw new AuditChainException('Audit head file is too large.');
        }
        if (trim($raw) === '') {
            throw new AuditChainException('Audit head file is empty/unreadable.');
        }

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($raw, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new AuditChainException('Audit head file is invalid JSON.', 0, $e);
        }

        if (!is_array($decoded)) {
            throw new AuditChainException('Audit head file must decode to an object/array.');
        }

        $seqRaw = $decoded['seq'] ?? null;
        $seq = is_int($seqRaw) ? $seqRaw : (is_string($seqRaw) && ctype_digit(trim($seqRaw)) ? (int) trim($seqRaw) : null);
        if (!is_int($seq) || $seq < 0) {
            throw new AuditChainException('Audit head file has invalid seq.');
        }

        $hash = $decoded['head_hash'] ?? null;
        if (!is_string($hash) || trim($hash) === '' || str_contains($hash, "\0")) {
            throw new AuditChainException('Audit head file has invalid head_hash.');
        }

        $updatedAt = $decoded['updated_at'] ?? null;
        $updatedAt = is_string($updatedAt) && trim($updatedAt) !== '' ? trim($updatedAt) : gmdate('c');

        $lastType = $decoded['last_type'] ?? null;
        $lastType = is_string($lastType) && trim($lastType) !== '' ? trim($lastType) : 'unknown';

        return [
            'seq' => $seq,
            'head_hash' => Bytes32::normalizeHex($hash),
            'updated_at' => $updatedAt,
            'last_type' => $lastType,
        ];
    }

    /**
     * @param array<string,mixed> $entry
     */
    private function appendLineUnsafe(array $entry): void
    {
        $logPath = $this->path(self::LOG_FILE);
        if (file_exists($logPath) && is_link($logPath)) {
            throw new AuditChainException('Refusing symlink log file: ' . $logPath);
        }

        $json = json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($json)) {
            throw new AuditChainException('Audit entry JSON encode failed.');
        }
        if (strlen($json) > self::MAX_ENTRY_BYTES) {
            throw new AuditChainException('Audit entry is too large.');
        }

        $fp = @fopen($logPath, 'ab');
        if ($fp === false) {
            throw new AuditChainException('Unable to open audit log file: ' . $logPath);
        }

        try {
            $bytes = fwrite($fp, $json . "\n");
            if ($bytes === false) {
                throw new AuditChainException('Audit log write failed.');
            }
        } finally {
            fclose($fp);
        }

        if (DIRECTORY_SEPARATOR !== '\\') {
            @chmod($logPath, 0600);
        }
        $this->inheritGroup($logPath);
    }

    /**
     * @param array{seq:int,head_hash:string,updated_at:string,last_type:string} $head
     */
    private function writeHeadUnsafe(array $head): void
    {
        $headPath = $this->path(self::HEAD_FILE);
        if (file_exists($headPath) && is_link($headPath)) {
            throw new AuditChainException('Refusing symlink head file: ' . $headPath);
        }

        $json = json_encode($head, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        if (!is_string($json)) {
            throw new AuditChainException('Audit head JSON encode failed.');
        }

        $tmp = $headPath . '.tmp-' . bin2hex(random_bytes(6));
        $fp = @fopen($tmp, 'xb');
        if ($fp === false) {
            throw new AuditChainException('Unable to create audit head temp file.');
        }

        try {
            $bytes = fwrite($fp, $json . "\n");
            if ($bytes === false) {
                throw new AuditChainException('Audit head write failed.');
            }
        } finally {
            fclose($fp);
        }

        if (DIRECTORY_SEPARATOR !== '\\') {
            @chmod($tmp, 0640);
        }
        $this->inheritGroup($tmp);

        if (!@rename($tmp, $headPath)) {
            @unlink($tmp);
            throw new AuditChainException('Unable to move audit head file into place.');
        }

        if (DIRECTORY_SEPARATOR !== '\\') {
            @chmod($headPath, 0640);
        }
        $this->inheritGroup($headPath);
    }

    private function path(string $file): string
    {
        return rtrim($this->dir, '/\\') . DIRECTORY_SEPARATOR . $file;
    }

    private function inheritGroup(string $path): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            return;
        }

        $gid = @filegroup($this->dir);
        if (!is_int($gid) || $gid < 0) {
            return;
        }

        @chgrp($path, $gid);
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
