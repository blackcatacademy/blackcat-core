<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class ArrayRuntimeConfigRepository implements RuntimeConfigRepositoryInterface
{
    /**
     * @param array<string,mixed> $data
     */
    public function __construct(
        private readonly array $data,
        private readonly ?string $sourcePath = null,
    ) {
    }

    /**
     * Dot-notation lookup (e.g., "trust.web3.chain_id").
     */
    public function get(string $key, mixed $default = null): mixed
    {
        if ($key === '') {
            return $default;
        }

        $cur = $this->data;
        foreach (explode('.', $key) as $segment) {
            if ($segment === '') {
                return $default;
            }
            if (!is_array($cur) || !array_key_exists($segment, $cur)) {
                return $default;
            }
            $cur = $cur[$segment];
        }

        return $cur;
    }

    public function requireString(string $key): string
    {
        $val = $this->get($key);
        if (!is_string($val) || $val === '') {
            throw new \RuntimeException('Missing required config string: ' . $key);
        }
        return $val;
    }

    public function requireInt(string $key): int
    {
        $val = $this->get($key);
        if (is_int($val)) {
            return $val;
        }
        if (is_string($val)) {
            $trimmed = trim($val);
            if ($trimmed !== '' && ctype_digit($trimmed)) {
                return (int) $trimmed;
            }
        }

        throw new \RuntimeException('Missing required config integer: ' . $key);
    }

    public function resolvePath(string $path): string
    {
        $path = trim($path);
        if ($path === '') {
            throw new \RuntimeException('Config path is empty.');
        }
        if (str_contains($path, "\0")) {
            throw new \RuntimeException('Config path contains null byte.');
        }

        if (self::isAbsolutePath($path)) {
            return $path;
        }

        if ($this->sourcePath === null) {
            throw new \RuntimeException('Relative paths require a config sourcePath.');
        }

        $baseDir = dirname($this->sourcePath);
        if ($baseDir === '' || $baseDir === '.') {
            throw new \RuntimeException('Unable to resolve relative path (invalid sourcePath): ' . $this->sourcePath);
        }

        return rtrim($baseDir, "/\\") . DIRECTORY_SEPARATOR . $path;
    }

    public function sourcePath(): ?string
    {
        return $this->sourcePath;
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

