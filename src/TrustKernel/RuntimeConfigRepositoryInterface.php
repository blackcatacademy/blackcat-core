<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

interface RuntimeConfigRepositoryInterface
{
    public function get(string $key, mixed $default = null): mixed;

    public function requireString(string $key): string;

    public function requireInt(string $key): int;

    public function resolvePath(string $path): string;

    public function sourcePath(): ?string;
}

