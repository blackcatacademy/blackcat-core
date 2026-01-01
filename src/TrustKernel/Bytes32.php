<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class Bytes32
{
    public static function normalizeHex(string $hex): string
    {
        $hex = trim($hex);
        if ($hex === '' || str_contains($hex, "\0")) {
            throw new \InvalidArgumentException('Invalid bytes32 hex string.');
        }

        $hex = strtolower($hex);
        if (str_starts_with($hex, '0x')) {
            $hex = substr($hex, 2);
        }

        if (!preg_match('/^[0-9a-f]{64}$/', $hex)) {
            throw new \InvalidArgumentException('Invalid bytes32 hex string (expected 32 bytes).');
        }

        return '0x' . $hex;
    }

    public static function toHex(string $bytes32): string
    {
        if (strlen($bytes32) !== 32) {
            throw new \InvalidArgumentException('Invalid bytes32 binary string.');
        }

        return '0x' . bin2hex($bytes32);
    }

    public static function toBinary(string $hex): string
    {
        $hex = self::normalizeHex($hex);
        $bin = hex2bin(substr($hex, 2));
        if (!is_string($bin) || strlen($bin) !== 32) {
            throw new \InvalidArgumentException('Invalid bytes32 hex string (hex2bin failed).');
        }

        return $bin;
    }
}

