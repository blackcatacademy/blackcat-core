<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class BlackCatConfigRepositoryAdapter implements RuntimeConfigRepositoryInterface
{
    public function __construct(
        private readonly object $repo,
    ) {
        foreach (['get', 'requireString', 'requireInt'] as $method) {
            if (!method_exists($repo, $method)) {
                throw new \InvalidArgumentException('Runtime config repo missing method: ' . $method);
            }
        }
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $method = 'get';
        /** @var mixed $value */
        $value = $this->repo->$method($key, $default);
        return $value;
    }

    public function requireString(string $key): string
    {
        $method = 'requireString';
        /** @var string $value */
        $value = $this->repo->$method($key);
        return $value;
    }

    public function requireInt(string $key): int
    {
        $method = 'requireInt';
        /** @var int $value */
        $value = $this->repo->$method($key);
        return $value;
    }

    public function resolvePath(string $path): string
    {
        if (method_exists($this->repo, 'resolvePath')) {
            /** @var string $resolved */
            $resolved = $this->repo->resolvePath($path);
            return $resolved;
        }

        $path = trim($path);
        if ($path === '' || str_contains($path, "\0")) {
            throw new \RuntimeException('Config path is invalid.');
        }

        if (self::isAbsolutePath($path)) {
            return $path;
        }

        $source = $this->sourcePath();
        if ($source === null) {
            throw new \RuntimeException('Relative paths require a sourcePath/resolvePath support in runtime config repo.');
        }

        $baseDir = dirname($source);
        if ($baseDir === '' || $baseDir === '.') {
            throw new \RuntimeException('Unable to resolve relative path (invalid sourcePath): ' . $source);
        }

        return rtrim($baseDir, "/\\") . DIRECTORY_SEPARATOR . $path;
    }

    public function sourcePath(): ?string
    {
        if (!method_exists($this->repo, 'sourcePath')) {
            return null;
        }

        /** @var mixed $value */
        $value = $this->repo->sourcePath();
        return is_string($value) && $value !== '' ? $value : null;
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
