<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class InstanceControllerReader
{
    private const SNAPSHOT_SELECTOR = '0x9711715a'; // snapshot()
    private const RELEASE_REGISTRY_SELECTOR = '0x19ee073e'; // releaseRegistry()
    private const EXPECTED_COMPONENT_ID_SELECTOR = '0xd6c1b425'; // expectedComponentId()
    private const REPORTER_AUTHORITY_SELECTOR = '0x44f644a9'; // reporterAuthority()
    private const MAX_CHECKIN_AGE_SEC_SELECTOR = '0x011641f2'; // maxCheckInAgeSec()
    private const LAST_CHECKIN_AT_SELECTOR = '0x11077470'; // lastCheckInAt()
    private const LAST_CHECKIN_OK_SELECTOR = '0x23b44f3b'; // lastCheckInOk()
    private const ATTESTATIONS_SELECTOR = '0x940992a3'; // attestations(bytes32)
    private const ATTESTATION_UPDATED_AT_SELECTOR = '0xb54917aa'; // attestationUpdatedAt(bytes32)
    private const ATTESTATION_LOCKED_SELECTOR = '0xa93a4e86'; // attestationLocked(bytes32)

    public function __construct(
        private readonly Web3RpcQuorumClient $rpc,
    ) {
    }

    public function snapshot(string $instanceControllerAddress): InstanceControllerSnapshot
    {
        $hex = $this->rpc->ethCallQuorum($instanceControllerAddress, self::SNAPSHOT_SELECTOR, 'latest');
        return self::decodeSnapshot($hex);
    }

    /**
     * Batch read commonly used kernel fields to reduce RPC round-trips.
     *
     * Returns:
     * - snapshot()
     * - releaseRegistry()
     * - attestations(key) + attestationLocked(key) for each provided key
     *
     * @param list<string> $attestationKeysBytes32
     * @return array{
     *   snapshot:InstanceControllerSnapshot,
     *   release_registry:string,
     *   attestations:array<string,array{value:string,locked:bool}>
     * }
     */
    public function kernelProbe(string $instanceControllerAddress, array $attestationKeysBytes32): array
    {
        $instanceControllerAddress = self::normalizeAddress($instanceControllerAddress);

        $keys = [];
        foreach ($attestationKeysBytes32 as $i => $k) {
            if (!is_string($k)) {
                throw new \InvalidArgumentException('Invalid attestation key type at index ' . $i . ' (expected string).');
            }
            $k = Bytes32::normalizeHex($k);
            $keys[$k] = true;
        }
        $keyList = array_keys($keys);
        sort($keyList, SORT_STRING);

        $calls = [
            [
                'to' => $instanceControllerAddress,
                'data' => self::SNAPSHOT_SELECTOR,
            ],
            [
                'to' => $instanceControllerAddress,
                'data' => self::RELEASE_REGISTRY_SELECTOR,
            ],
        ];

        foreach ($keyList as $k) {
            $calls[] = [
                'to' => $instanceControllerAddress,
                'data' => self::ATTESTATIONS_SELECTOR . substr($k, 2),
            ];
        }
        foreach ($keyList as $k) {
            $calls[] = [
                'to' => $instanceControllerAddress,
                'data' => self::ATTESTATION_LOCKED_SELECTOR . substr($k, 2),
            ];
        }

        $results = $this->rpc->ethCallBatchQuorum($calls, 'latest');

        $snapshotHex = $results[0] ?? null;
        $rrHex = $results[1] ?? null;
        if (!is_string($snapshotHex) || !is_string($rrHex)) {
            throw new \RuntimeException('Invalid kernel probe response shape.');
        }

        $snapshot = self::decodeSnapshot($snapshotHex);
        $releaseRegistry = self::decodeAddress($rrHex);

        $attestations = [];
        $n = count($keyList);
        for ($i = 0; $i < $n; $i++) {
            $key = $keyList[$i];
            $valueHex = $results[2 + $i] ?? null;
            $lockedHex = $results[2 + $n + $i] ?? null;
            if (!is_string($valueHex) || !is_string($lockedHex)) {
                throw new \RuntimeException('Invalid kernel probe response index for key ' . $key . '.');
            }

            $attestations[$key] = [
                'value' => self::decodeBytes32($valueHex),
                'locked' => self::decodeBool($lockedHex),
            ];
        }

        return [
            'snapshot' => $snapshot,
            'release_registry' => $releaseRegistry,
            'attestations' => $attestations,
        ];
    }

    public function releaseRegistry(string $instanceControllerAddress): string
    {
        $hex = $this->rpc->ethCallQuorum($instanceControllerAddress, self::RELEASE_REGISTRY_SELECTOR, 'latest');
        return self::decodeAddress($hex);
    }

    public function expectedComponentId(string $instanceControllerAddress): string
    {
        $hex = $this->rpc->ethCallQuorum($instanceControllerAddress, self::EXPECTED_COMPONENT_ID_SELECTOR, 'latest');
        return self::decodeBytes32($hex);
    }

    public function reporterAuthority(string $instanceControllerAddress): string
    {
        $hex = $this->rpc->ethCallQuorum($instanceControllerAddress, self::REPORTER_AUTHORITY_SELECTOR, 'latest');
        return self::decodeAddress($hex);
    }

    public function maxCheckInAgeSec(string $instanceControllerAddress): int
    {
        $hex = $this->rpc->ethCallQuorum($instanceControllerAddress, self::MAX_CHECKIN_AGE_SEC_SELECTOR, 'latest');
        return self::decodeUint64($hex);
    }

    public function lastCheckInAt(string $instanceControllerAddress): int
    {
        $hex = $this->rpc->ethCallQuorum($instanceControllerAddress, self::LAST_CHECKIN_AT_SELECTOR, 'latest');
        return self::decodeUint64($hex);
    }

    public function lastCheckInOk(string $instanceControllerAddress): bool
    {
        $hex = $this->rpc->ethCallQuorum($instanceControllerAddress, self::LAST_CHECKIN_OK_SELECTOR, 'latest');
        return self::decodeBool($hex);
    }

    public function attestation(string $instanceControllerAddress, string $keyBytes32): string
    {
        $data = self::ATTESTATIONS_SELECTOR . substr(Bytes32::normalizeHex($keyBytes32), 2);
        $hex = $this->rpc->ethCallQuorum($instanceControllerAddress, $data, 'latest');
        return self::decodeBytes32($hex);
    }

    public function attestationUpdatedAt(string $instanceControllerAddress, string $keyBytes32): int
    {
        $data = self::ATTESTATION_UPDATED_AT_SELECTOR . substr(Bytes32::normalizeHex($keyBytes32), 2);
        $hex = $this->rpc->ethCallQuorum($instanceControllerAddress, $data, 'latest');
        return self::decodeUint64($hex);
    }

    public function attestationLocked(string $instanceControllerAddress, string $keyBytes32): bool
    {
        $data = self::ATTESTATION_LOCKED_SELECTOR . substr(Bytes32::normalizeHex($keyBytes32), 2);
        $hex = $this->rpc->ethCallQuorum($instanceControllerAddress, $data, 'latest');
        return self::decodeBool($hex);
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

    private static function normalizeAddress(string $address): string
    {
        $address = trim($address);
        if ($address === '' || str_contains($address, "\0")) {
            throw new \InvalidArgumentException('Invalid EVM address.');
        }
        if (!preg_match('/^0x[a-fA-F0-9]{40}$/', $address)) {
            throw new \InvalidArgumentException('Invalid EVM address.');
        }
        $address = '0x' . strtolower(substr($address, 2));
        if ($address === '0x0000000000000000000000000000000000000000') {
            throw new \InvalidArgumentException('Invalid EVM address (zero).');
        }
        return $address;
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
        return $addr;
    }

    private static function decodeBytes32(string $hex): string
    {
        $hex = trim($hex);
        if ($hex === '' || !str_starts_with($hex, '0x')) {
            throw new \RuntimeException('Invalid bytes32 result.');
        }

        $payload = substr(strtolower($hex), 2);
        if (strlen($payload) < 64) {
            throw new \RuntimeException('Invalid bytes32 result length.');
        }

        $word = substr($payload, 0, 64);
        if (!is_string($word) || strlen($word) !== 64 || !ctype_xdigit($word)) {
            throw new \RuntimeException('Invalid bytes32 ABI word.');
        }

        return Bytes32::normalizeHex('0x' . $word);
    }

    private static function decodeUint64(string $hex): int
    {
        $hex = trim($hex);
        if ($hex === '' || !str_starts_with($hex, '0x')) {
            throw new \RuntimeException('Invalid uint64 result.');
        }

        $payload = substr(strtolower($hex), 2);
        if (strlen($payload) < 64) {
            throw new \RuntimeException('Invalid uint64 result length.');
        }

        $word = substr($payload, 0, 64);
        if (!is_string($word) || strlen($word) !== 64 || !ctype_xdigit($word)) {
            throw new \RuntimeException('Invalid uint64 ABI word.');
        }

        return (int) hexdec(substr($word, 48, 16));
    }

    private static function decodeBool(string $hex): bool
    {
        $hex = trim($hex);
        if ($hex === '' || !str_starts_with($hex, '0x')) {
            throw new \RuntimeException('Invalid bool result.');
        }

        $payload = substr(strtolower($hex), 2);
        if (strlen($payload) < 64) {
            throw new \RuntimeException('Invalid bool result length.');
        }

        $word = substr($payload, 0, 64);
        if (!is_string($word) || strlen($word) !== 64 || !ctype_xdigit($word)) {
            throw new \RuntimeException('Invalid bool ABI word.');
        }

        return ((int) hexdec(substr($word, 62, 2))) !== 0;
    }
}
