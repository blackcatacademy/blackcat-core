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
                throw new \RuntimeException('Integrity check failed: missing file: ' . $path);
            }
            if (is_link($absolute)) {
                throw new \RuntimeException('Integrity check failed: symlink is not allowed: ' . $path);
            }

            $actualHash = $this->sha256Bytes32Cached($absolute);
            if (!hash_equals($expectedHash, $actualHash)) {
                throw new \RuntimeException('Integrity check failed: hash mismatch: ' . $path);
            }
        }

        return $manifest->rootBytes32();
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
            throw new \RuntimeException('Integrity check failed: unable to stat file.');
        }

        $cached = $this->hashCache[$absolutePath] ?? null;
        if ($cached !== null && $cached['mtime'] === $mtime && $cached['size'] === $size) {
            return $cached['hash'];
        }

        $hex = @hash_file('sha256', $absolutePath);
        if ($hex === false) {
            throw new \RuntimeException('Integrity check failed: unable to hash file.');
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
