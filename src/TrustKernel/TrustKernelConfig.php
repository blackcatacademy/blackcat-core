<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class TrustKernelConfig
{
    private const RUNTIME_CONFIG_ATTESTATION_KEY_LABEL_V1 = 'blackcat.runtime_config.canonical_sha256.v1';
    private const RUNTIME_CONFIG_ATTESTATION_KEY_LABEL_V2 = 'blackcat.runtime_config.canonical_sha256.v2';
    private const COMPOSER_LOCK_ATTESTATION_KEY_LABEL_V1 = 'blackcat.composer.lock.canonical_sha256.v1';
    private const PHP_FINGERPRINT_ATTESTATION_KEY_LABEL_V2 = 'blackcat.php.fingerprint.canonical_sha256.v2';
    private const IMAGE_DIGEST_ATTESTATION_KEY_LABEL_V1 = 'blackcat.image.digest.sha256.v1';
    private const HTTP_ALLOWED_HOSTS_ATTESTATION_KEY_LABEL_V1 = 'blackcat.http.allowed_hosts.canonical_sha256.v1';

    /** @var list<string> */
    public readonly array $rpcEndpoints;

    public readonly int $rpcQuorum;

    public readonly int $chainId;

    public readonly int $maxStaleSec;

    /** @var 'root_uri'|'full' */
    public readonly string $mode;

    public readonly string $instanceController;

    public readonly ?string $releaseRegistry;

    public readonly string $integrityRootDir;

    public readonly string $integrityManifestPath;

    public readonly int $rpcTimeoutSec;

    public readonly string $policyHashV1;
    public readonly string $policyHashV2Strict;
    public readonly string $policyHashV2Warn;
    public readonly string $policyHashV3Strict;
    public readonly string $policyHashV3Warn;
    public readonly string $policyHashV3StrictV2;
    public readonly string $policyHashV3WarnV2;
    public readonly string $policyHashV4Strict;
    public readonly string $policyHashV4Warn;
    public readonly string $policyHashV4StrictV2;
    public readonly string $policyHashV4WarnV2;
    public readonly string $policyHashV5Strict;
    public readonly string $policyHashV5Warn;
    public readonly string $policyHashV5StrictV2;
    public readonly string $policyHashV5WarnV2;

    /** On-chain key (bytes32) used for runtime config commitment. */
    public readonly string $runtimeConfigAttestationKey;
    /** Alternate on-chain key (bytes32) for runtime config commitment rotation (v2). */
    public readonly string $runtimeConfigAttestationKeyV2;
    /** On-chain key (bytes32) for composer.lock commitment (v1). */
    public readonly string $composerLockAttestationKeyV1;
    /** On-chain key (bytes32) for PHP fingerprint commitment (v2; stable across worker SAPIs). */
    public readonly string $phpFingerprintAttestationKeyV2;
    /** On-chain key (bytes32) for image digest commitment (v1). */
    public readonly string $imageDigestAttestationKeyV1;
    /** On-chain key (bytes32) for HTTP allowed hosts commitment (v1). */
    public readonly string $httpAllowedHostsAttestationKeyV1;
    /** Canonical SHA-256 (bytes32) of the loaded runtime config (optional; only available when sourcePath is known). */
    public readonly ?string $runtimeConfigCanonicalSha256;
    /** Canonical SHA-256 (bytes32) of normalized http.allowed_hosts list (optional). */
    public readonly ?string $httpAllowedHostsCanonicalSha256;
    /** Path of the runtime config file used to compute {@see self::$runtimeConfigCanonicalSha256}. */
    public readonly ?string $runtimeConfigSourcePath;
    /** Optional image digest file path (used only for v4 attestation enforcement). */
    public readonly ?string $imageDigestFilePath;

    /**
     * @param list<string> $rpcEndpoints
     * @param 'root_uri'|'full' $mode
     */
    public function __construct(
        int $chainId,
        array $rpcEndpoints,
        int $rpcQuorum,
        int $maxStaleSec,
        string $mode,
        string $instanceController,
        ?string $releaseRegistry,
        string $integrityRootDir,
        string $integrityManifestPath,
        int $rpcTimeoutSec,
        ?string $runtimeConfigCanonicalSha256 = null,
        ?string $httpAllowedHostsCanonicalSha256 = null,
        ?string $runtimeConfigSourcePath = null,
        ?string $imageDigestFilePath = null,
    )
    {
        if ($chainId <= 0) {
            throw new \InvalidArgumentException('Invalid chainId.');
        }
        if ($rpcEndpoints === []) {
            throw new \InvalidArgumentException('At least one RPC endpoint is required.');
        }
        $max = count($rpcEndpoints);
        if ($rpcQuorum < 1 || $rpcQuorum > $max) {
            throw new \InvalidArgumentException('Invalid rpcQuorum (expected 1..' . $max . ').');
        }
        if ($maxStaleSec < 1 || $maxStaleSec > 86400) {
            throw new \InvalidArgumentException('Invalid maxStaleSec (expected 1..86400).');
        }
        if (!in_array($mode, ['root_uri', 'full'], true)) {
            throw new \InvalidArgumentException('Invalid mode (expected root_uri|full).');
        }
        if ($rpcTimeoutSec < 1 || $rpcTimeoutSec > 60) {
            throw new \InvalidArgumentException('Invalid rpcTimeoutSec (expected 1..60).');
        }

        $this->chainId = $chainId;
        $this->rpcEndpoints = $rpcEndpoints;
        $this->rpcQuorum = $rpcQuorum;
        $this->maxStaleSec = $maxStaleSec;
        $this->mode = $mode;
        $this->instanceController = $instanceController;
        $this->releaseRegistry = $releaseRegistry;
        $this->integrityRootDir = $integrityRootDir;
        $this->integrityManifestPath = $integrityManifestPath;
        $this->rpcTimeoutSec = $rpcTimeoutSec;
        $this->policyHashV1 = (new TrustPolicyV1($mode, $maxStaleSec))->hashBytes32();
        $this->policyHashV2Strict = (new TrustPolicyV2($mode, $maxStaleSec, 'strict'))->hashBytes32();
        $this->policyHashV2Warn = (new TrustPolicyV2($mode, $maxStaleSec, 'warn'))->hashBytes32();
        $runtimeConfigAttestationKey = Bytes32::normalizeHex(
            '0x' . hash('sha256', self::RUNTIME_CONFIG_ATTESTATION_KEY_LABEL_V1)
        );
        $this->runtimeConfigAttestationKey = $runtimeConfigAttestationKey;

        $runtimeConfigAttestationKeyV2 = Bytes32::normalizeHex(
            '0x' . hash('sha256', self::RUNTIME_CONFIG_ATTESTATION_KEY_LABEL_V2)
        );
        $this->runtimeConfigAttestationKeyV2 = $runtimeConfigAttestationKeyV2;

        $this->policyHashV3Strict = (new TrustPolicyV3($mode, $maxStaleSec, 'strict', $this->runtimeConfigAttestationKey))->hashBytes32();
        $this->policyHashV3Warn = (new TrustPolicyV3($mode, $maxStaleSec, 'warn', $this->runtimeConfigAttestationKey))->hashBytes32();
        $this->policyHashV3StrictV2 = (new TrustPolicyV3($mode, $maxStaleSec, 'strict', $this->runtimeConfigAttestationKeyV2))->hashBytes32();
        $this->policyHashV3WarnV2 = (new TrustPolicyV3($mode, $maxStaleSec, 'warn', $this->runtimeConfigAttestationKeyV2))->hashBytes32();

        $this->composerLockAttestationKeyV1 = Bytes32::normalizeHex(
            '0x' . hash('sha256', self::COMPOSER_LOCK_ATTESTATION_KEY_LABEL_V1)
        );

        $this->phpFingerprintAttestationKeyV2 = Bytes32::normalizeHex(
            '0x' . hash('sha256', self::PHP_FINGERPRINT_ATTESTATION_KEY_LABEL_V2)
        );

        $this->imageDigestAttestationKeyV1 = Bytes32::normalizeHex(
            '0x' . hash('sha256', self::IMAGE_DIGEST_ATTESTATION_KEY_LABEL_V1)
        );

        $this->httpAllowedHostsAttestationKeyV1 = Bytes32::normalizeHex(
            '0x' . hash('sha256', self::HTTP_ALLOWED_HOSTS_ATTESTATION_KEY_LABEL_V1)
        );

        $this->policyHashV4Strict = (new TrustPolicyV4(
            $mode,
            $maxStaleSec,
            'strict',
            $this->runtimeConfigAttestationKey,
            true,
            true,
            $this->composerLockAttestationKeyV1,
            true,
            true,
            $this->phpFingerprintAttestationKeyV2,
            true,
            true,
            $this->imageDigestAttestationKeyV1,
            true,
            true,
        ))->hashBytes32();

        $this->policyHashV5Strict = (new TrustPolicyV5(
            $mode,
            $maxStaleSec,
            'strict',
            $this->runtimeConfigAttestationKey,
            $this->httpAllowedHostsAttestationKeyV1,
            true,
            true,
            true,
            true,
            $this->composerLockAttestationKeyV1,
            true,
            true,
            $this->phpFingerprintAttestationKeyV2,
            true,
            true,
            $this->imageDigestAttestationKeyV1,
            true,
            true,
        ))->hashBytes32();

        $this->policyHashV4Warn = (new TrustPolicyV4(
            $mode,
            $maxStaleSec,
            'warn',
            $this->runtimeConfigAttestationKey,
            true,
            true,
            $this->composerLockAttestationKeyV1,
            true,
            true,
            $this->phpFingerprintAttestationKeyV2,
            true,
            true,
            $this->imageDigestAttestationKeyV1,
            true,
            true,
        ))->hashBytes32();

        $this->policyHashV5Warn = (new TrustPolicyV5(
            $mode,
            $maxStaleSec,
            'warn',
            $this->runtimeConfigAttestationKey,
            $this->httpAllowedHostsAttestationKeyV1,
            true,
            true,
            true,
            true,
            $this->composerLockAttestationKeyV1,
            true,
            true,
            $this->phpFingerprintAttestationKeyV2,
            true,
            true,
            $this->imageDigestAttestationKeyV1,
            true,
            true,
        ))->hashBytes32();

        $this->policyHashV4StrictV2 = (new TrustPolicyV4(
            $mode,
            $maxStaleSec,
            'strict',
            $this->runtimeConfigAttestationKeyV2,
            true,
            true,
            $this->composerLockAttestationKeyV1,
            true,
            true,
            $this->phpFingerprintAttestationKeyV2,
            true,
            true,
            $this->imageDigestAttestationKeyV1,
            true,
            true,
        ))->hashBytes32();

        $this->policyHashV5StrictV2 = (new TrustPolicyV5(
            $mode,
            $maxStaleSec,
            'strict',
            $this->runtimeConfigAttestationKeyV2,
            $this->httpAllowedHostsAttestationKeyV1,
            true,
            true,
            true,
            true,
            $this->composerLockAttestationKeyV1,
            true,
            true,
            $this->phpFingerprintAttestationKeyV2,
            true,
            true,
            $this->imageDigestAttestationKeyV1,
            true,
            true,
        ))->hashBytes32();

        $this->policyHashV4WarnV2 = (new TrustPolicyV4(
            $mode,
            $maxStaleSec,
            'warn',
            $this->runtimeConfigAttestationKeyV2,
            true,
            true,
            $this->composerLockAttestationKeyV1,
            true,
            true,
            $this->phpFingerprintAttestationKeyV2,
            true,
            true,
            $this->imageDigestAttestationKeyV1,
            true,
            true,
        ))->hashBytes32();

        $this->policyHashV5WarnV2 = (new TrustPolicyV5(
            $mode,
            $maxStaleSec,
            'warn',
            $this->runtimeConfigAttestationKeyV2,
            $this->httpAllowedHostsAttestationKeyV1,
            true,
            true,
            true,
            true,
            $this->composerLockAttestationKeyV1,
            true,
            true,
            $this->phpFingerprintAttestationKeyV2,
            true,
            true,
            $this->imageDigestAttestationKeyV1,
            true,
            true,
        ))->hashBytes32();

        $this->runtimeConfigCanonicalSha256 = $runtimeConfigCanonicalSha256 !== null
            ? Bytes32::normalizeHex($runtimeConfigCanonicalSha256)
            : null;
        $this->httpAllowedHostsCanonicalSha256 = $httpAllowedHostsCanonicalSha256 !== null
            ? Bytes32::normalizeHex($httpAllowedHostsCanonicalSha256)
            : null;
        $this->runtimeConfigSourcePath = $runtimeConfigSourcePath;

        $imageDigestFilePath = is_string($imageDigestFilePath) ? trim($imageDigestFilePath) : null;
        if ($imageDigestFilePath === '' || $imageDigestFilePath === null || str_contains($imageDigestFilePath, "\0")) {
            $imageDigestFilePath = null;
        }
        $this->imageDigestFilePath = $imageDigestFilePath;
    }

    public static function fromRuntimeConfig(RuntimeConfigRepositoryInterface $repo): ?self
    {
        $web3 = $repo->get('trust.web3');
        if ($web3 === null) {
            return null;
        }
        if (!is_array($web3)) {
            throw new \RuntimeException('Invalid config type for trust.web3 (expected object).');
        }

        $chainId = $repo->requireInt('trust.web3.chain_id');
        if ($chainId <= 0) {
            throw new \RuntimeException('Invalid config value for trust.web3.chain_id (expected > 0).');
        }

        $endpoints = $repo->get('trust.web3.rpc_endpoints');
        if (!is_array($endpoints) || $endpoints === []) {
            throw new \RuntimeException('Missing required config list: trust.web3.rpc_endpoints');
        }

        $normalizedEndpoints = [];
        foreach ($endpoints as $i => $endpoint) {
            if (!is_string($endpoint)) {
                throw new \RuntimeException('Invalid config type for trust.web3.rpc_endpoints[' . $i . '] (expected string).');
            }
            $endpoint = trim($endpoint);
            if ($endpoint === '' || str_contains($endpoint, "\0")) {
                throw new \RuntimeException('Invalid config value for trust.web3.rpc_endpoints[' . $i . '].');
            }
            $normalizedEndpoints[] = $endpoint;
        }
        $normalizedEndpoints = array_values(array_unique($normalizedEndpoints));
        if ($normalizedEndpoints === []) {
            throw new \RuntimeException('Missing required config list: trust.web3.rpc_endpoints');
        }

        $quorum = self::parseIntLike($repo->get('trust.web3.rpc_quorum', 1), 'trust.web3.rpc_quorum');
        $max = count($normalizedEndpoints);
        if ($quorum < 1 || $quorum > $max) {
            throw new \RuntimeException('Invalid config value for trust.web3.rpc_quorum (expected 1..' . $max . ').');
        }

        $maxStaleSec = self::parseIntLike($repo->get('trust.web3.max_stale_sec', 180), 'trust.web3.max_stale_sec');
        if ($maxStaleSec < 1 || $maxStaleSec > 86400) {
            throw new \RuntimeException('Invalid config value for trust.web3.max_stale_sec (expected 1..86400).');
        }

        $modeRaw = $repo->get('trust.web3.mode', 'full');
        if (!is_string($modeRaw)) {
            throw new \RuntimeException('Invalid config type for trust.web3.mode (expected string).');
        }
        $mode = strtolower(trim($modeRaw));
        if ($mode === '' || !in_array($mode, ['root_uri', 'full'], true)) {
            throw new \RuntimeException('Invalid config value for trust.web3.mode (expected "root_uri" or "full").');
        }

        $controller = $repo->requireString('trust.web3.contracts.instance_controller');
        self::assertEvmAddress($controller, 'trust.web3.contracts.instance_controller');

        $releaseRegistry = $repo->get('trust.web3.contracts.release_registry');
        if ($releaseRegistry !== null && $releaseRegistry !== '') {
            if (!is_string($releaseRegistry)) {
                throw new \RuntimeException('Invalid config type for trust.web3.contracts.release_registry (expected string).');
            }
            self::assertEvmAddress($releaseRegistry, 'trust.web3.contracts.release_registry');
        } else {
            $releaseRegistry = null;
        }

        $integrityRootDir = $repo->resolvePath($repo->requireString('trust.integrity.root_dir'));
        $integrityManifestPath = $repo->resolvePath($repo->requireString('trust.integrity.manifest'));

        $timeoutSec = self::parseIntLike($repo->get('trust.web3.timeout_sec', 5), 'trust.web3.timeout_sec');
        if ($timeoutSec < 1 || $timeoutSec > 60) {
            throw new \RuntimeException('Invalid config value for trust.web3.timeout_sec (expected 1..60).');
        }

        $runtimeConfigCanonicalSha256 = null;
        $httpAllowedHostsCanonicalSha256 = null;
        $runtimeConfigSourcePath = $repo->sourcePath();
        if ($runtimeConfigSourcePath !== null && is_file($runtimeConfigSourcePath)) {
            $raw = @file_get_contents($runtimeConfigSourcePath);
            if ($raw === false) {
                throw new \RuntimeException('Unable to read runtime config file: ' . $runtimeConfigSourcePath);
            }

            try {
                /** @var mixed $decoded */
                $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
            } catch (\JsonException $e) {
                throw new \RuntimeException('Invalid JSON runtime config file: ' . $runtimeConfigSourcePath, 0, $e);
            }

            if (!is_array($decoded)) {
                throw new \RuntimeException('Runtime config JSON must decode to an object/array: ' . $runtimeConfigSourcePath);
            }

            /** @var array<string,mixed> $decoded */
            $runtimeConfigCanonicalSha256 = CanonicalJson::sha256Bytes32($decoded);
        }

        $allowedHostsRaw = $repo->get('http.allowed_hosts');
        $normalizedAllowedHosts = self::normalizeAllowedHostsList($allowedHostsRaw);
        if ($normalizedAllowedHosts !== null) {
            $httpAllowedHostsCanonicalSha256 = CanonicalJson::sha256Bytes32([
                'schema_version' => 1,
                'type' => 'blackcat.http.allowed_hosts',
                'hosts' => $normalizedAllowedHosts,
            ]);
        }

        $imageDigestFilePath = null;
        $imageDigestRaw = $repo->get('trust.integrity.image_digest_file');
        if (is_string($imageDigestRaw) && trim($imageDigestRaw) !== '') {
            $resolved = $repo->resolvePath($imageDigestRaw);
            if (trim($resolved) !== '' && !str_contains($resolved, "\0")) {
                $imageDigestFilePath = $resolved;
            }
        }

        return new self(
            chainId: $chainId,
            rpcEndpoints: $normalizedEndpoints,
            rpcQuorum: $quorum,
            maxStaleSec: $maxStaleSec,
            mode: $mode,
            instanceController: $controller,
            releaseRegistry: $releaseRegistry,
            integrityRootDir: $integrityRootDir,
            integrityManifestPath: $integrityManifestPath,
            rpcTimeoutSec: $timeoutSec,
            runtimeConfigCanonicalSha256: $runtimeConfigCanonicalSha256,
            httpAllowedHostsCanonicalSha256: $httpAllowedHostsCanonicalSha256,
            runtimeConfigSourcePath: $runtimeConfigSourcePath,
            imageDigestFilePath: $imageDigestFilePath,
        );
    }

    /**
     * @return list<string>|null Normalized patterns (lowercase, sorted, unique) or null when missing/invalid.
     */
    private static function normalizeAllowedHostsList(mixed $raw): ?array
    {
        if (!is_array($raw) || $raw === []) {
            return null;
        }

        $out = [];
        foreach ($raw as $v) {
            if (!is_string($v)) {
                continue;
            }
            $v = trim($v);
            if ($v === '' || str_contains($v, "\0") || str_contains($v, "\r") || str_contains($v, "\n")) {
                continue;
            }

            $isWildcard = str_starts_with($v, '*.');
            if ($isWildcard) {
                $suffix = substr($v, 2);
                $suffix = strtolower(trim($suffix));
                if ($suffix === '' || str_contains($suffix, "\0")) {
                    continue;
                }
                if (!preg_match('/^[a-z0-9.-]+$/', $suffix)) {
                    continue;
                }
                if (str_contains($suffix, '..') || str_starts_with($suffix, '.') || str_ends_with($suffix, '.')) {
                    continue;
                }
                $out['*.' . $suffix] = true;
                continue;
            }

            $host = self::normalizeHostLike($v);
            if ($host === null) {
                continue;
            }
            $out[$host] = true;
        }

        $list = array_keys($out);
        sort($list, SORT_STRING);
        return $list !== [] ? $list : null;
    }

    private static function normalizeHostLike(string $host): ?string
    {
        $host = trim($host);
        if ($host === '' || str_contains($host, "\0")) {
            return null;
        }

        if (str_contains($host, '://') || str_contains($host, '/') || str_contains($host, '\\')) {
            return null;
        }

        // Accept bracketed IPv6 in config: [::1]:443 or [::1]
        if (str_starts_with($host, '[')) {
            $end = strpos($host, ']');
            if ($end === false) {
                return null;
            }
            $ipv6 = substr($host, 1, $end - 1);
            if ($ipv6 === '') {
                return null;
            }
            if (@filter_var($ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
                return null;
            }

            $rest = trim(substr($host, $end + 1));
            if ($rest !== '') {
                if (!str_starts_with($rest, ':')) {
                    return null;
                }
                $port = trim(substr($rest, 1));
                if ($port === '' || !ctype_digit($port)) {
                    return null;
                }
                $portNum = (int) $port;
                if ($portNum < 1 || $portNum > 65535) {
                    return null;
                }
            }

            return strtolower($ipv6);
        }

        // Drop optional ":port" suffix.
        if (str_contains($host, ':')) {
            [$h, $p] = explode(':', $host, 2) + [null, null];
            if (!is_string($h) || !is_string($p)) {
                return null;
            }
            $p = trim($p);
            if ($p === '' || !ctype_digit($p)) {
                return null;
            }
            $portNum = (int) $p;
            if ($portNum < 1 || $portNum > 65535) {
                return null;
            }
            $host = $h;
        }

        $host = strtolower(trim($host));
        if ($host === '' || str_contains($host, "\0")) {
            return null;
        }

        if (@filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6) !== false) {
            return $host;
        }

        if (!preg_match('/^[a-z0-9.-]+$/', $host)) {
            return null;
        }
        if (str_contains($host, '..') || str_starts_with($host, '.') || str_ends_with($host, '.')) {
            return null;
        }

        return $host;
    }

    private static function parseIntLike(mixed $value, string $key): int
    {
        if (is_int($value)) {
            return $value;
        }
        if (is_string($value)) {
            $trimmed = trim($value);
            if ($trimmed !== '' && ctype_digit($trimmed)) {
                return (int) $trimmed;
            }
        }

        throw new \RuntimeException('Invalid config type/value for ' . $key . ' (expected integer).');
    }

    private static function assertEvmAddress(string $address, string $key): void
    {
        $address = trim($address);
        if ($address === '') {
            throw new \RuntimeException('Missing required config string: ' . $key);
        }

        if (!preg_match('/^0x[a-fA-F0-9]{40}$/', $address)) {
            throw new \RuntimeException('Invalid EVM address for ' . $key . '.');
        }

        if (strtolower($address) === '0x0000000000000000000000000000000000000000') {
            throw new \RuntimeException('Invalid EVM address for ' . $key . ' (zero address).');
        }
    }
}
