<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class TrustKernelConfig
{
    /** @var list<string> */
    public readonly array $rpcEndpoints;

    public readonly int $rpcQuorum;

    public readonly int $chainId;

    public readonly int $maxStaleSec;

    /** @var 'root_uri'|'full' */
    public readonly string $mode;

    public readonly string $instanceController;

    public readonly string $integrityRootDir;

    public readonly string $integrityManifestPath;

    /** @var 'strict'|'warn' */
    public readonly string $enforcement;

    public readonly int $rpcTimeoutSec;

    public readonly string $expectedPolicyHash;

    /**
     * @param list<string> $rpcEndpoints
     * @param 'root_uri'|'full' $mode
     * @param 'strict'|'warn' $enforcement
     */
    public function __construct(
        int $chainId,
        array $rpcEndpoints,
        int $rpcQuorum,
        int $maxStaleSec,
        string $mode,
        string $instanceController,
        string $integrityRootDir,
        string $integrityManifestPath,
        string $enforcement,
        int $rpcTimeoutSec,
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
        if (!in_array($enforcement, ['strict', 'warn'], true)) {
            throw new \InvalidArgumentException('Invalid enforcement (expected strict|warn).');
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
        $this->integrityRootDir = $integrityRootDir;
        $this->integrityManifestPath = $integrityManifestPath;
        $this->enforcement = $enforcement;
        $this->rpcTimeoutSec = $rpcTimeoutSec;
        $this->expectedPolicyHash = (new TrustPolicyV1($mode, $maxStaleSec))->hashBytes32();
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

        $modeRaw = $repo->get('trust.web3.mode', 'root_uri');
        if (!is_string($modeRaw)) {
            throw new \RuntimeException('Invalid config type for trust.web3.mode (expected string).');
        }
        $mode = strtolower(trim($modeRaw));
        if ($mode === '' || !in_array($mode, ['root_uri', 'full'], true)) {
            throw new \RuntimeException('Invalid config value for trust.web3.mode (expected "root_uri" or "full").');
        }

        $controller = $repo->requireString('trust.web3.contracts.instance_controller');
        self::assertEvmAddress($controller, 'trust.web3.contracts.instance_controller');

        $integrityRootDir = $repo->resolvePath($repo->requireString('trust.integrity.root_dir'));
        $integrityManifestPath = $repo->resolvePath($repo->requireString('trust.integrity.manifest'));

        $enforcementRaw = $repo->get('trust.enforcement', 'strict');
        if (!is_string($enforcementRaw)) {
            throw new \RuntimeException('Invalid config type for trust.enforcement (expected string).');
        }
        $enforcement = strtolower(trim($enforcementRaw));
        if ($enforcement === '' || !in_array($enforcement, ['strict', 'warn'], true)) {
            throw new \RuntimeException('Invalid config value for trust.enforcement (expected "strict" or "warn").');
        }

        $timeoutSec = self::parseIntLike($repo->get('trust.web3.timeout_sec', 5), 'trust.web3.timeout_sec');
        if ($timeoutSec < 1 || $timeoutSec > 60) {
            throw new \RuntimeException('Invalid config value for trust.web3.timeout_sec (expected 1..60).');
        }

        return new self(
            chainId: $chainId,
            rpcEndpoints: $normalizedEndpoints,
            rpcQuorum: $quorum,
            maxStaleSec: $maxStaleSec,
            mode: $mode,
            instanceController: $controller,
            integrityRootDir: $integrityRootDir,
            integrityManifestPath: $integrityManifestPath,
            enforcement: $enforcement,
            rpcTimeoutSec: $timeoutSec,
        );
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
