<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel\AttackFlows\Support;

use BlackCat\Core\TrustKernel\IntegrityManifestV1;

final class IntegrityFixture
{
    public string $rootDir;
    public string $manifestPath;
    public IntegrityManifestV1 $manifest;
    public string $rootBytes32;
    public ?string $uriHashBytes32;

    /**
     * @param array<string,string> $files relative path => content
     */
    public static function create(array $files = ['app.txt' => 'ok'], ?string $uri = 'https://example.invalid/blackcat'): self
    {
        $base = rtrim(sys_get_temp_dir(), "/\\");
        $id = bin2hex(random_bytes(8));
        $rootDir = $base . DIRECTORY_SEPARATOR . 'blackcat-core-tk-' . $id;

        if (!@mkdir($rootDir, 0700, true) && !is_dir($rootDir)) {
            throw new \RuntimeException('Unable to create temp root dir.');
        }

        $hashes = [];
        foreach ($files as $rel => $content) {
            $rel = str_replace('\\', '/', trim($rel));
            if ($rel === '' || str_contains($rel, "\0")) {
                throw new \InvalidArgumentException('Invalid fixture path.');
            }
            $abs = $rootDir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);
            $dir = dirname($abs);
            if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
                throw new \RuntimeException('Unable to create fixture dir: ' . $dir);
            }

            if (@file_put_contents($abs, $content) === false) {
                throw new \RuntimeException('Unable to write fixture file: ' . $abs);
            }

            $hex = hash('sha256', $content);
            $hashes[$rel] = '0x' . $hex;
        }

        $manifestPath = $base . DIRECTORY_SEPARATOR . 'blackcat-core-tk-' . $id . '.integrity.manifest.json';
        $json = json_encode([
            'schema_version' => 1,
            'type' => 'blackcat.integrity.manifest',
            'files' => $hashes,
            'uri' => $uri,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (!is_string($json) || @file_put_contents($manifestPath, $json) === false) {
            throw new \RuntimeException('Unable to write manifest JSON.');
        }

        $manifest = IntegrityManifestV1::fromJsonFile($manifestPath);
        $self = new self();
        $self->rootDir = $rootDir;
        $self->manifestPath = $manifestPath;
        $self->manifest = $manifest;
        $self->rootBytes32 = $manifest->rootBytes32();
        $self->uriHashBytes32 = $manifest->uriHashBytes32();
        return $self;
    }

    public function tamper(string $relativePath, string $newContent): void
    {
        $relativePath = str_replace('\\', '/', trim($relativePath));
        if ($relativePath === '' || str_contains($relativePath, "\0")) {
            throw new \InvalidArgumentException('Invalid fixture path.');
        }
        $abs = $this->rootDir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relativePath);
        if (@file_put_contents($abs, $newContent) === false) {
            throw new \RuntimeException('Unable to tamper file: ' . $abs);
        }
    }

    public function cleanup(): void
    {
        @unlink($this->manifestPath);
        self::rmTree($this->rootDir);
    }

    private static function rmTree(string $path): void
    {
        if ($path === '' || $path === DIRECTORY_SEPARATOR) {
            return;
        }
        if (!file_exists($path)) {
            return;
        }
        if (is_file($path) || is_link($path)) {
            @unlink($path);
            return;
        }
        $items = @scandir($path);
        if (!is_array($items)) {
            return;
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            self::rmTree($path . DIRECTORY_SEPARATOR . $item);
        }
        @rmdir($path);
    }
}
