<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class UriHasher
{
    public static function sha256Bytes32(string $uri): string
    {
        $uri = trim($uri);
        if ($uri === '' || str_contains($uri, "\0")) {
            throw new \InvalidArgumentException('Invalid URI string.');
        }

        return '0x' . hash('sha256', $uri);
    }
}

