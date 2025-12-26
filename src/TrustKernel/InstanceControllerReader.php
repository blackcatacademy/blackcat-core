<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class InstanceControllerReader
{
    private const SNAPSHOT_SELECTOR = '0x9711715a'; // snapshot()
    private const RELEASE_REGISTRY_SELECTOR = '0x19ee073e'; // releaseRegistry()

    public function __construct(
        private readonly Web3RpcQuorumClient $rpc,
    ) {
    }

    public function snapshot(string $instanceControllerAddress): InstanceControllerSnapshot
    {
        $hex = $this->rpc->ethCallQuorum($instanceControllerAddress, self::SNAPSHOT_SELECTOR, 'latest');
        return self::decodeSnapshot($hex);
    }

    public function releaseRegistry(string $instanceControllerAddress): string
    {
        $hex = $this->rpc->ethCallQuorum($instanceControllerAddress, self::RELEASE_REGISTRY_SELECTOR, 'latest');
        return self::decodeAddress($hex);
    }

    private static function decodeSnapshot(string $hex): InstanceControllerSnapshot
    {
        $hex = trim($hex);
        if ($hex === '' || !str_starts_with($hex, '0x')) {
            throw new \RuntimeException('Invalid snapshot result.');
        }

        $payload = substr(strtolower($hex), 2);
        $expectedWords = 12;
        $expectedChars = $expectedWords * 64;
        if (strlen($payload) < $expectedChars) {
            throw new \RuntimeException('Invalid snapshot result length.');
        }

        $word = static function (int $i) use ($payload): string {
            $chunk = substr($payload, $i * 64, 64);
            if (!is_string($chunk) || strlen($chunk) !== 64) {
                throw new \RuntimeException('Invalid ABI word.');
            }
            return $chunk;
        };

        $version = (int) hexdec(substr($word(0), 62, 2));
        $paused = ((int) hexdec(substr($word(1), 62, 2))) !== 0;

        $activeRoot = '0x' . $word(2);
        $activeUriHash = '0x' . $word(3);
        $activePolicyHash = '0x' . $word(4);

        $pendingRoot = '0x' . $word(5);
        $pendingUriHash = '0x' . $word(6);
        $pendingPolicyHash = '0x' . $word(7);

        $pendingCreatedAt = (int) hexdec(substr($word(8), 48, 16));
        $pendingTtlSec = (int) hexdec(substr($word(9), 48, 16));
        $genesisAt = (int) hexdec(substr($word(10), 48, 16));
        $lastUpgradeAt = (int) hexdec(substr($word(11), 48, 16));

        return new InstanceControllerSnapshot(
            $version,
            $paused,
            $activeRoot,
            $activeUriHash,
            $activePolicyHash,
            $pendingRoot,
            $pendingUriHash,
            $pendingPolicyHash,
            $pendingCreatedAt,
            $pendingTtlSec,
            $genesisAt,
            $lastUpgradeAt,
        );
    }

    private static function decodeAddress(string $hex): string
    {
        $hex = trim($hex);
        if ($hex === '' || !str_starts_with($hex, '0x')) {
            throw new \RuntimeException('Invalid address result.');
        }

        $payload = substr(strtolower($hex), 2);
        if (strlen($payload) < 64) {
            throw new \RuntimeException('Invalid address result length.');
        }

        $word = substr($payload, 0, 64);
        if (!is_string($word) || strlen($word) !== 64 || !ctype_xdigit($word)) {
            throw new \RuntimeException('Invalid address ABI word.');
        }

        $addr = '0x' . substr($word, 24, 40);
        // normalize to lowercase + validate.
        Bytes32::normalizeHex('0x' . substr($word, 0, 64));
        if ($addr === '0x0000000000000000000000000000000000000000') {
            throw new \RuntimeException('Invalid address (zero).');
        }
        return $addr;
    }
}
