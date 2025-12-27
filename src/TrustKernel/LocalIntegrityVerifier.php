<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class LocalIntegrityVerifier
{
    /** @var array<string,array{mtime:int,size:int,hash:string}> */
    private array $hashCache = [];

    private string $rootDir;

    public function __construct(
        string $rootDir,
    ) {
        $rootDir = trim($rootDir);
        if ($rootDir === '' || str_contains($rootDir, "\0")) {
            throw new \InvalidArgumentException('Invalid integrity rootDir.');
        }
        if (!self::isAbsolutePath($rootDir)) {
            throw new \InvalidArgumentException('Integrity rootDir must be an absolute path.');
        }
        if (!is_dir($rootDir)) {
            throw new \RuntimeException('Integrity rootDir is not a directory: ' . $rootDir);
        }
        if (is_link($rootDir)) {
            throw new \RuntimeException('Integrity rootDir must not be a symlink: ' . $rootDir);
        }

        $this->rootDir = $rootDir;
    }

    /**
     * Verify that local files match the manifest hashes and return the computed merkle root.
     */
    public function computeAndVerifyRoot(IntegrityManifestV1 $manifest): string
    {
        foreach ($manifest->files as $path => $expectedHash) {
            $absolute = $this->absolutePathFor($path);

            if (!is_file($absolute)) {
                throw new IntegrityViolationException('integrity_missing_file', 'Integrity check failed: missing file: ' . $path);
            }
            if (is_link($absolute)) {
                throw new IntegrityViolationException('integrity_symlink_file', 'Integrity check failed: symlink is not allowed: ' . $path);
            }

            $actualHash = $this->sha256Bytes32Cached($absolute);
            if (!hash_equals($expectedHash, $actualHash)) {
                throw new IntegrityViolationException('integrity_hash_mismatch', 'Integrity check failed: hash mismatch: ' . $path);
            }
        }

        return $manifest->rootBytes32();
    }

    /**
     * Strict mode: also fails if there are unexpected files under the integrity root.
     *
     * Intended for production deployments where `rootDir` is immutable (no uploads, no caches).
     */
    public function computeAndVerifyRootStrict(IntegrityManifestV1 $manifest): string
    {
        $root = $this->computeAndVerifyRoot($manifest);
        $this->assertNoUnexpectedFiles($manifest);
        return $root;
    }

    private function assertNoUnexpectedFiles(IntegrityManifestV1 $manifest): void
    {
        $allowed = [];
        foreach (array_keys($manifest->files) as $path) {
            $allowed[Sha256Merkle::normalizePath($path)] = true;
        }

        $root = rtrim($this->rootDir, "/\\");
        $prefix = $root . DIRECTORY_SEPARATOR;
        $prefixLen = strlen($prefix);

        $dirIt = new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS);
        $it = new \RecursiveIteratorIterator($dirIt);

        /** @var \SplFileInfo $file */
        foreach ($it as $file) {
            if ($file->isDir()) {
                continue;
            }
            if ($file->isLink()) {
                throw new IntegrityViolationException('integrity_symlink_file', 'Integrity check failed: symlink is not allowed: ' . $file->getPathname());
            }

            $abs = $file->getPathname();
            if (!str_starts_with($abs, $prefix)) {
                throw new IntegrityViolationException('integrity_check_failed', 'Integrity check failed: unexpected root path.');
            }

            $relFs = substr($abs, $prefixLen);
            $rel = str_replace(DIRECTORY_SEPARATOR, '/', $relFs);
            $rel = Sha256Merkle::normalizePath($rel);

            if (!isset($allowed[$rel])) {
                throw new IntegrityViolationException('integrity_unexpected_file', 'Integrity check failed: unexpected file: ' . $rel);
            }
        }
    }

    private function absolutePathFor(string $normalizedPath): string
    {
        $normalizedPath = Sha256Merkle::normalizePath($normalizedPath);
        $fsPath = str_replace('/', DIRECTORY_SEPARATOR, $normalizedPath);
        $root = rtrim($this->rootDir, "/\\");
        return $root . DIRECTORY_SEPARATOR . $fsPath;
    }

    private function sha256Bytes32Cached(string $absolutePath): string
    {
        clearstatcache(true, $absolutePath);
        $mtime = @filemtime($absolutePath);
        $size = @filesize($absolutePath);
        if (!is_int($mtime) || $mtime <= 0 || !is_int($size)) {
            throw new IntegrityViolationException('integrity_stat_failed', 'Integrity check failed: unable to stat file.');
        }

        $cached = $this->hashCache[$absolutePath] ?? null;
        if ($cached !== null && $cached['mtime'] === $mtime && $cached['size'] === $size) {
            return $cached['hash'];
        }

        $hex = @hash_file('sha256', $absolutePath);
        if ($hex === false) {
            throw new IntegrityViolationException('integrity_hash_failed', 'Integrity check failed: unable to hash file.');
        }

        $hash = Bytes32::normalizeHex('0x' . $hex);
        $this->hashCache[$absolutePath] = [
            'mtime' => $mtime,
            'size' => $size,
            'hash' => $hash,
        ];

        return $hash;
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
