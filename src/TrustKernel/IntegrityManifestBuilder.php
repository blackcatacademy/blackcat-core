<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class IntegrityManifestBuilder
{
    /**
     * Build an integrity manifest for a directory tree.
     *
     * No exclusions are applied by default (maximum coverage). Choose `rootDir` accordingly:
     * - do not include upload/cache/temp directories
     * - prefer an immutable code directory
     *
     * @return array{
     *   manifest:array{schema_version:int,type:string,files:array<string,string>,uri?:string},
     *   root:string,
     *   uri_hash:?string,
     *   files_count:int
     * }
     */
    public static function build(string $rootDir, ?string $uri = null): array
    {
        $rootDir = trim($rootDir);
        if ($rootDir === '' || str_contains($rootDir, "\0")) {
            throw new \InvalidArgumentException('Invalid rootDir.');
        }
        if (!self::isAbsolutePath($rootDir)) {
            throw new \InvalidArgumentException('rootDir must be an absolute path.');
        }
        if (!is_dir($rootDir)) {
            throw new \RuntimeException('rootDir is not a directory: ' . $rootDir);
        }
        if (is_link($rootDir)) {
            throw new \RuntimeException('rootDir must not be a symlink: ' . $rootDir);
        }

        if ($uri !== null) {
            $uri = trim($uri);
            if ($uri === '' || str_contains($uri, "\0")) {
                throw new \InvalidArgumentException('Invalid uri.');
            }
        }

        $root = rtrim($rootDir, "/\\");
        $prefix = $root . DIRECTORY_SEPARATOR;
        $prefixLen = strlen($prefix);

        $files = [];

        $dirIt = new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS);
        $it = new \RecursiveIteratorIterator($dirIt);

        /** @var \SplFileInfo $file */
        foreach ($it as $file) {
            if ($file->isDir()) {
                continue;
            }

            if ($file->isLink()) {
                throw new \RuntimeException('Integrity manifest build failed: symlink is not allowed: ' . $file->getPathname());
            }

            $abs = $file->getPathname();
            if (!str_starts_with($abs, $prefix)) {
                throw new \RuntimeException('Integrity manifest build failed: unexpected root path.');
            }

            $relFs = substr($abs, $prefixLen);
            $rel = str_replace(DIRECTORY_SEPARATOR, '/', $relFs);
            $rel = Sha256Merkle::normalizePath($rel);

            $hex = @hash_file('sha256', $abs);
            if ($hex === false) {
                throw new \RuntimeException('Integrity manifest build failed: unable to hash file: ' . $rel);
            }

            $files[$rel] = Bytes32::normalizeHex('0x' . $hex);
        }

        if ($files === []) {
            throw new \RuntimeException('Integrity manifest build failed: no files found under rootDir.');
        }

        $manifest = [
            'schema_version' => 1,
            'type' => 'blackcat.integrity.manifest',
            'files' => $files,
        ];
        if ($uri !== null) {
            $manifest['uri'] = $uri;
        }

        $rootBytes32 = Sha256Merkle::root($files);
        $uriHash = $uri !== null ? UriHasher::sha256Bytes32($uri) : null;

        return [
            'manifest' => $manifest,
            'root' => $rootBytes32,
            'uri_hash' => $uriHash,
            'files_count' => count($files),
        ];
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

