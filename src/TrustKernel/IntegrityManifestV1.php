<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class IntegrityManifestV1
{
    private const MAX_MANIFEST_BYTES = 32 * 1024 * 1024; // 32 MiB

    /**
     * @param array<string,string> $files path => sha256 bytes32 hex
     */
    private function __construct(
        public readonly array $files,
        public readonly ?string $uri,
    ) {
    }

    public static function fromJsonFile(string $path): self
    {
        $path = trim($path);
        if ($path === '' || str_contains($path, "\0")) {
            throw new \InvalidArgumentException('Invalid manifest path.');
        }

        clearstatcache(true, $path);
        if (is_link($path)) {
            throw new \RuntimeException('Integrity manifest must not be a symlink: ' . $path);
        }
        if (!is_file($path) || !is_readable($path)) {
            throw new \RuntimeException('Unable to read integrity manifest: ' . $path);
        }

        $size = @filesize($path);
        if (is_int($size) && $size > self::MAX_MANIFEST_BYTES) {
            throw new \RuntimeException('Integrity manifest is too large.');
        }

        $raw = @file_get_contents($path, false, null, 0, self::MAX_MANIFEST_BYTES + 1);
        if (!is_string($raw) || $raw === '') {
            throw new \RuntimeException('Unable to read integrity manifest: ' . $path);
        }
        if (strlen($raw) > self::MAX_MANIFEST_BYTES) {
            throw new \RuntimeException('Integrity manifest is too large.');
        }

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new \RuntimeException('Invalid JSON integrity manifest: ' . $path, 0, $e);
        }

        if (!is_array($decoded)) {
            throw new \RuntimeException('Integrity manifest JSON must decode to an object: ' . $path);
        }

        $schemaVersion = $decoded['schema_version'] ?? null;
        if (!is_int($schemaVersion) || $schemaVersion !== 1) {
            throw new \RuntimeException('Unsupported integrity manifest schema_version (expected 1).');
        }

        $type = $decoded['type'] ?? null;
        if ($type !== null && (!is_string($type) || trim($type) === '')) {
            throw new \RuntimeException('Invalid integrity manifest type (expected string).');
        }

        $files = $decoded['files'] ?? null;
        if (!is_array($files) || $files === []) {
            throw new \RuntimeException('Integrity manifest must contain a non-empty files object.');
        }

        $normalizedFiles = [];
        foreach ($files as $filePath => $hash) {
            if (!is_string($filePath) || trim($filePath) === '') {
                throw new \RuntimeException('Integrity manifest files keys must be non-empty strings.');
            }
            if (!is_string($hash) || trim($hash) === '') {
                throw new \RuntimeException('Integrity manifest file hash must be a non-empty string: ' . $filePath);
            }

            $normalizedPath = Sha256Merkle::normalizePath($filePath);
            $normalizedFiles[$normalizedPath] = Bytes32::normalizeHex($hash);
        }

        $uri = $decoded['uri'] ?? null;
        if ($uri !== null && $uri !== '') {
            if (!is_string($uri)) {
                throw new \RuntimeException('Integrity manifest uri must be a string.');
            }
            $uri = trim($uri);
            if ($uri === '' || str_contains($uri, "\0")) {
                throw new \RuntimeException('Integrity manifest uri is invalid.');
            }
        } else {
            $uri = null;
        }

        return new self($normalizedFiles, $uri);
    }

    public function uriHashBytes32(): ?string
    {
        if ($this->uri === null) {
            return null;
        }

        return UriHasher::sha256Bytes32($this->uri);
    }

    public function rootBytes32(): string
    {
        return Sha256Merkle::root($this->files);
    }
}
