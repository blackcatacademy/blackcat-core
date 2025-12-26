<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel\AttackFlows\Support;

final class Abi
{
    public static function word(string $hex): string
    {
        $hex = strtolower(ltrim($hex, '0x'));
        if ($hex === '') {
            $hex = '0';
        }
        if (!ctype_xdigit($hex)) {
            throw new \InvalidArgumentException('Abi.word: non-hex.');
        }
        return str_pad($hex, 64, '0', STR_PAD_LEFT);
    }

    public static function bytes32Word(string $bytes32): string
    {
        $bytes32 = strtolower(trim($bytes32));
        if (!str_starts_with($bytes32, '0x') || strlen($bytes32) !== 66) {
            throw new \InvalidArgumentException('Abi.bytes32Word: expected 0x + 64 hex chars.');
        }
        $hex = substr($bytes32, 2);
        if (!ctype_xdigit($hex)) {
            throw new \InvalidArgumentException('Abi.bytes32Word: non-hex.');
        }
        return $hex;
    }

    public static function u64Word(int $n): string
    {
        if ($n < 0) {
            throw new \InvalidArgumentException('Abi.u64Word: expected >= 0.');
        }
        return str_repeat('0', 48) . str_pad(dechex($n), 16, '0', STR_PAD_LEFT);
    }

    public static function addressResult(string $address): string
    {
        $address = strtolower(trim($address));
        if (!preg_match('/^0x[a-f0-9]{40}$/', $address)) {
            throw new \InvalidArgumentException('Abi.addressResult: invalid address.');
        }
        return '0x' . str_repeat('0', 24) . substr($address, 2);
    }

    public static function boolResult(bool $value): string
    {
        return '0x' . str_repeat('0', 63) . ($value ? '1' : '0');
    }

    public static function snapshotResult(
        int $version,
        bool $paused,
        string $activeRoot,
        string $activeUriHash,
        string $activePolicyHash,
        string $pendingRoot,
        string $pendingUriHash,
        string $pendingPolicyHash,
        int $pendingCreatedAt,
        int $pendingTtlSec,
        int $genesisAt,
        int $lastUpgradeAt,
    ): string {
        $payload = implode('', [
            self::word(dechex($version)),
            self::word($paused ? '1' : '0'),
            self::bytes32Word($activeRoot),
            self::bytes32Word($activeUriHash),
            self::bytes32Word($activePolicyHash),
            self::bytes32Word($pendingRoot),
            self::bytes32Word($pendingUriHash),
            self::bytes32Word($pendingPolicyHash),
            self::u64Word($pendingCreatedAt),
            self::u64Word($pendingTtlSec),
            self::u64Word($genesisAt),
            self::u64Word($lastUpgradeAt),
        ]);

        return '0x' . $payload;
    }
}

