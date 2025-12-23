<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class Sha256Merkle
{
    /**
     * Canonical tree root builder (v1).
     *
     * - Sort entries lexicographically by normalized path.
     * - Leaf hash: sha256(0x00 || path || 0x00 || fileHashBytes32)
     * - Node hash: sha256(0x01 || left || right)
     * - Odd node: duplicate the last leaf.
     *
     * @param array<string,string> $entries path => bytes32 hex (0x-prefixed or not)
     */
    public static function root(array $entries): string
    {
        if ($entries === []) {
            throw new \InvalidArgumentException('Merkle root requires at least one entry.');
        }

        $normalized = [];
        foreach ($entries as $path => $hash) {
            if (!is_string($path) || $path === '') {
                throw new \InvalidArgumentException('Invalid merkle entry path.');
            }
            if (!is_string($hash) || $hash === '') {
                throw new \InvalidArgumentException('Invalid merkle entry hash.');
            }

            $path = self::normalizePath($path);
            $hashHex = Bytes32::normalizeHex($hash);
            $normalized[$path] = $hashHex;
        }

        ksort($normalized, SORT_STRING);

        $level = [];
        foreach ($normalized as $path => $hashHex) {
            $hashBytes = Bytes32::toBinary($hashHex);
            $level[] = hash('sha256', "\x00" . $path . "\x00" . $hashBytes, true);
        }

        return Bytes32::toHex(self::rootBinary($level));
    }

    /**
     * @param list<string> $nodes list of 32-byte binary hashes
     */
    private static function rootBinary(array $nodes): string
    {
        foreach ($nodes as $n) {
            if (!is_string($n) || strlen($n) !== 32) {
                throw new \InvalidArgumentException('Invalid merkle node (expected 32 bytes).');
            }
        }

        $level = array_values($nodes);
        while (count($level) > 1) {
            $next = [];
            $count = count($level);

            for ($i = 0; $i < $count; $i += 2) {
                $left = $level[$i];
                $right = $level[$i + 1] ?? $left;
                $next[] = hash('sha256', "\x01" . $left . $right, true);
            }

            $level = $next;
        }

        return $level[0];
    }

    public static function normalizePath(string $path): string
    {
        $path = trim($path);
        if ($path === '' || str_contains($path, "\0")) {
            throw new \InvalidArgumentException('Invalid path (empty or contains null byte).');
        }

        $path = str_replace('\\', '/', $path);
        $path = preg_replace('#/+#', '/', $path) ?? $path;
        $path = preg_replace('#^\\./+#', '', $path) ?? $path;
        $path = ltrim($path, '/');

        if ($path === '') {
            throw new \InvalidArgumentException('Invalid path (empty after normalization).');
        }

        foreach (explode('/', $path) as $seg) {
            if ($seg === '' || $seg === '.') {
                continue;
            }
            if ($seg === '..') {
                throw new \InvalidArgumentException('Invalid path (must not contain "..").');
            }
        }

        return $path;
    }
}

