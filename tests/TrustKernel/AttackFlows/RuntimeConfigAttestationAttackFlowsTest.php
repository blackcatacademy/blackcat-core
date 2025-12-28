<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel\AttackFlows;

use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\Abi;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\IntegrityFixture;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\ScenarioTransport;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\TestLogger;
use BlackCat\Core\TrustKernel\CanonicalJson;
use BlackCat\Core\TrustKernel\TrustKernel;
use BlackCat\Core\TrustKernel\TrustKernelConfig;
use BlackCat\Core\TrustKernel\TrustKernelException;
use PHPUnit\Framework\TestCase;

final class RuntimeConfigAttestationAttackFlowsTest extends TestCase
{
    public function testPolicyV3StrictRejectsMismatchedRuntimeConfigAttestation(): void
    {
        $fixture = IntegrityFixture::create(['app.txt' => 'ok']);

        $instanceController = '0x1111111111111111111111111111111111111111';

        $runtimeConfig = [
            'trust' => [
                'integrity' => [
                    'root_dir' => '/srv/blackcat',
                    'manifest' => '/etc/blackcat/integrity.manifest.json',
                ],
                'web3' => [
                    'chain_id' => 4207,
                    'rpc_endpoints' => ['https://a', 'https://b'],
                    'rpc_quorum' => 2,
                    'max_stale_sec' => 180,
                    'timeout_sec' => 5,
                    'mode' => 'root_uri',
                    'contracts' => [
                        'instance_controller' => $instanceController,
                    ],
                ],
            ],
        ];

        $canonical = CanonicalJson::sha256Bytes32($runtimeConfig);

        $runtimeConfigPath = $fixture->rootDir . DIRECTORY_SEPARATOR . 'config.runtime.json';
        $json = json_encode($runtimeConfig, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        if (!is_string($json) || @file_put_contents($runtimeConfigPath, $json) === false) {
            throw new \RuntimeException('Unable to write runtime config fixture file.');
        }

        $cfg = new TrustKernelConfig(
            chainId: 4207,
            rpcEndpoints: ['https://a', 'https://b'],
            rpcQuorum: 2,
            maxStaleSec: 3,
            mode: 'root_uri',
            instanceController: $instanceController,
            releaseRegistry: null,
            integrityRootDir: $fixture->rootDir,
            integrityManifestPath: $fixture->manifestPath,
            rpcTimeoutSec: 5,
            runtimeConfigCanonicalSha256: $canonical,
            runtimeConfigSourcePath: $runtimeConfigPath,
        );

        $key = strtolower($cfg->runtimeConfigAttestationKey);
        $attestationCall = '0x940992a3' . substr($key, 2);
        $lockedCall = '0xa93a4e86' . substr($key, 2);

        $transport = new ScenarioTransport(static function (string $url, array $req, int $timeoutSec, int $callIndex) use ($cfg, $fixture, $instanceController, $attestationCall, $lockedCall): string {
            $method = $req['method'] ?? null;
            if ($method === 'eth_chainId') {
                return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => '0x106f'], JSON_THROW_ON_ERROR);
            }

            if ($method === 'eth_getCode') {
                return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => '0x6000'], JSON_THROW_ON_ERROR);
            }

            if ($method === 'eth_call') {
                $params = $req['params'] ?? null;
                $to = is_array($params) && isset($params[0]['to']) ? strtolower((string) $params[0]['to']) : '';
                $data = is_array($params) && isset($params[0]['data']) ? strtolower((string) $params[0]['data']) : '';

                if ($to === strtolower($instanceController) && $data === '0x9711715a') {
                    $snapshotHex = Abi::snapshotResult(
                        version: 1,
                        paused: false,
                        activeRoot: $fixture->rootBytes32,
                        activeUriHash: $fixture->uriHashBytes32 ?? ('0x' . str_repeat('00', 32)),
                        activePolicyHash: $cfg->policyHashV3Strict,
                        pendingRoot: '0x' . str_repeat('00', 32),
                        pendingUriHash: '0x' . str_repeat('00', 32),
                        pendingPolicyHash: '0x' . str_repeat('00', 32),
                        pendingCreatedAt: 0,
                        pendingTtlSec: 0,
                        genesisAt: 1,
                        lastUpgradeAt: 1,
                    );
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => $snapshotHex], JSON_THROW_ON_ERROR);
                }

                if ($to === strtolower($instanceController) && $data === '0x19ee073e') {
                    return json_encode([
                        'jsonrpc' => '2.0',
                        'id' => 1,
                        'result' => Abi::addressResult('0x0000000000000000000000000000000000000000'),
                    ], JSON_THROW_ON_ERROR);
                }

                if ($to === strtolower($instanceController) && $data === $attestationCall) {
                    // mismatched on-chain value
                    return json_encode([
                        'jsonrpc' => '2.0',
                        'id' => 1,
                        'result' => '0x' . str_repeat('11', 32),
                    ], JSON_THROW_ON_ERROR);
                }

                if ($to === strtolower($instanceController) && $data === $lockedCall) {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::boolResult(true)], JSON_THROW_ON_ERROR);
                }
            }

            throw new \RuntimeException('unexpected request');
        });

        $kernel = new TrustKernel($cfg, new TestLogger(), $transport);

        try {
            $status = $kernel->check();
            self::assertFalse($status->trustedNow);
            self::assertContains('Runtime config commitment mismatch.', $status->errors);

            $this->expectException(TrustKernelException::class);
            $kernel->assertWriteAllowed('db.write');
        } finally {
            $fixture->cleanup();
        }
    }

    public function testPolicyV3StrictAcceptsMatchingLockedRuntimeConfigAttestation(): void
    {
        $fixture = IntegrityFixture::create(['app.txt' => 'ok']);

        $instanceController = '0x1111111111111111111111111111111111111111';

        $runtimeConfig = [
            'trust' => [
                'integrity' => [
                    'root_dir' => '/srv/blackcat',
                    'manifest' => '/etc/blackcat/integrity.manifest.json',
                ],
                'web3' => [
                    'chain_id' => 4207,
                    'rpc_endpoints' => ['https://a', 'https://b'],
                    'rpc_quorum' => 2,
                    'max_stale_sec' => 180,
                    'timeout_sec' => 5,
                    'mode' => 'root_uri',
                    'contracts' => [
                        'instance_controller' => $instanceController,
                    ],
                ],
            ],
        ];

        $canonical = CanonicalJson::sha256Bytes32($runtimeConfig);

        $runtimeConfigPath = $fixture->rootDir . DIRECTORY_SEPARATOR . 'config.runtime.json';
        $json = json_encode($runtimeConfig, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        if (!is_string($json) || @file_put_contents($runtimeConfigPath, $json) === false) {
            throw new \RuntimeException('Unable to write runtime config fixture file.');
        }

        $cfg = new TrustKernelConfig(
            chainId: 4207,
            rpcEndpoints: ['https://a', 'https://b'],
            rpcQuorum: 2,
            maxStaleSec: 3,
            mode: 'root_uri',
            instanceController: $instanceController,
            releaseRegistry: null,
            integrityRootDir: $fixture->rootDir,
            integrityManifestPath: $fixture->manifestPath,
            rpcTimeoutSec: 5,
            runtimeConfigCanonicalSha256: $canonical,
            runtimeConfigSourcePath: $runtimeConfigPath,
        );

        $key = strtolower($cfg->runtimeConfigAttestationKey);
        $attestationCall = '0x940992a3' . substr($key, 2);
        $lockedCall = '0xa93a4e86' . substr($key, 2);

        $transport = new ScenarioTransport(static function (string $url, array $req, int $timeoutSec, int $callIndex) use ($cfg, $fixture, $instanceController, $canonical, $attestationCall, $lockedCall): string {
            $method = $req['method'] ?? null;
            if ($method === 'eth_chainId') {
                return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => '0x106f'], JSON_THROW_ON_ERROR);
            }

            if ($method === 'eth_getCode') {
                return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => '0x6000'], JSON_THROW_ON_ERROR);
            }

            if ($method === 'eth_call') {
                $params = $req['params'] ?? null;
                $to = is_array($params) && isset($params[0]['to']) ? strtolower((string) $params[0]['to']) : '';
                $data = is_array($params) && isset($params[0]['data']) ? strtolower((string) $params[0]['data']) : '';

                if ($to === strtolower($instanceController) && $data === '0x9711715a') {
                    $snapshotHex = Abi::snapshotResult(
                        version: 1,
                        paused: false,
                        activeRoot: $fixture->rootBytes32,
                        activeUriHash: $fixture->uriHashBytes32 ?? ('0x' . str_repeat('00', 32)),
                        activePolicyHash: $cfg->policyHashV3Strict,
                        pendingRoot: '0x' . str_repeat('00', 32),
                        pendingUriHash: '0x' . str_repeat('00', 32),
                        pendingPolicyHash: '0x' . str_repeat('00', 32),
                        pendingCreatedAt: 0,
                        pendingTtlSec: 0,
                        genesisAt: 1,
                        lastUpgradeAt: 1,
                    );
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => $snapshotHex], JSON_THROW_ON_ERROR);
                }

                if ($to === strtolower($instanceController) && $data === '0x19ee073e') {
                    return json_encode([
                        'jsonrpc' => '2.0',
                        'id' => 1,
                        'result' => Abi::addressResult('0x0000000000000000000000000000000000000000'),
                    ], JSON_THROW_ON_ERROR);
                }

                if ($to === strtolower($instanceController) && $data === $attestationCall) {
                    return json_encode([
                        'jsonrpc' => '2.0',
                        'id' => 1,
                        'result' => $canonical,
                    ], JSON_THROW_ON_ERROR);
                }

                if ($to === strtolower($instanceController) && $data === $lockedCall) {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::boolResult(true)], JSON_THROW_ON_ERROR);
                }
            }

            throw new \RuntimeException('unexpected request');
        });

        $kernel = new TrustKernel($cfg, new TestLogger(), $transport);

        try {
            $status = $kernel->check();
            self::assertTrue($status->trustedNow);
            self::assertTrue($status->readAllowed);
            self::assertTrue($status->writeAllowed);
        } finally {
            $fixture->cleanup();
        }
    }

    public function testPolicyV3StrictV2KeyAcceptsMatchingLockedRuntimeConfigAttestation(): void
    {
        $fixture = IntegrityFixture::create(['app.txt' => 'ok']);

        $instanceController = '0x1111111111111111111111111111111111111111';

        $runtimeConfig = [
            'trust' => [
                'integrity' => [
                    'root_dir' => '/srv/blackcat',
                    'manifest' => '/etc/blackcat/integrity.manifest.json',
                ],
                'web3' => [
                    'chain_id' => 4207,
                    'rpc_endpoints' => ['https://a', 'https://b'],
                    'rpc_quorum' => 2,
                    'max_stale_sec' => 180,
                    'timeout_sec' => 5,
                    'mode' => 'root_uri',
                    'contracts' => [
                        'instance_controller' => $instanceController,
                    ],
                ],
            ],
        ];

        $canonical = CanonicalJson::sha256Bytes32($runtimeConfig);

        $runtimeConfigPath = $fixture->rootDir . DIRECTORY_SEPARATOR . 'config.runtime.json';
        $json = json_encode($runtimeConfig, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        if (!is_string($json) || @file_put_contents($runtimeConfigPath, $json) === false) {
            throw new \RuntimeException('Unable to write runtime config fixture file.');
        }

        $cfg = new TrustKernelConfig(
            chainId: 4207,
            rpcEndpoints: ['https://a', 'https://b'],
            rpcQuorum: 2,
            maxStaleSec: 3,
            mode: 'root_uri',
            instanceController: $instanceController,
            releaseRegistry: null,
            integrityRootDir: $fixture->rootDir,
            integrityManifestPath: $fixture->manifestPath,
            rpcTimeoutSec: 5,
            runtimeConfigCanonicalSha256: $canonical,
            runtimeConfigSourcePath: $runtimeConfigPath,
        );

        $keyV1 = strtolower($cfg->runtimeConfigAttestationKey);
        $keyV2 = strtolower($cfg->runtimeConfigAttestationKeyV2);
        $attestationCallV1 = '0x940992a3' . substr($keyV1, 2);
        $lockedCallV1 = '0xa93a4e86' . substr($keyV1, 2);
        $attestationCallV2 = '0x940992a3' . substr($keyV2, 2);
        $lockedCallV2 = '0xa93a4e86' . substr($keyV2, 2);

        $transport = new ScenarioTransport(static function (string $url, array $req, int $timeoutSec, int $callIndex) use (
            $cfg,
            $fixture,
            $instanceController,
            $canonical,
            $attestationCallV1,
            $lockedCallV1,
            $attestationCallV2,
            $lockedCallV2,
        ): string {
            $method = $req['method'] ?? null;
            if ($method === 'eth_chainId') {
                return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => '0x106f'], JSON_THROW_ON_ERROR);
            }

            if ($method === 'eth_getCode') {
                return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => '0x6000'], JSON_THROW_ON_ERROR);
            }

            if ($method === 'eth_call') {
                $params = $req['params'] ?? null;
                $to = is_array($params) && isset($params[0]['to']) ? strtolower((string) $params[0]['to']) : '';
                $data = is_array($params) && isset($params[0]['data']) ? strtolower((string) $params[0]['data']) : '';

                if ($to === strtolower($instanceController) && $data === '0x9711715a') {
                    $snapshotHex = Abi::snapshotResult(
                        version: 1,
                        paused: false,
                        activeRoot: $fixture->rootBytes32,
                        activeUriHash: $fixture->uriHashBytes32 ?? ('0x' . str_repeat('00', 32)),
                        activePolicyHash: $cfg->policyHashV3StrictV2,
                        pendingRoot: '0x' . str_repeat('00', 32),
                        pendingUriHash: '0x' . str_repeat('00', 32),
                        pendingPolicyHash: '0x' . str_repeat('00', 32),
                        pendingCreatedAt: 0,
                        pendingTtlSec: 0,
                        genesisAt: 1,
                        lastUpgradeAt: 1,
                    );
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => $snapshotHex], JSON_THROW_ON_ERROR);
                }

                if ($to === strtolower($instanceController) && $data === '0x19ee073e') {
                    return json_encode([
                        'jsonrpc' => '2.0',
                        'id' => 1,
                        'result' => Abi::addressResult('0x0000000000000000000000000000000000000000'),
                    ], JSON_THROW_ON_ERROR);
                }

                // Ensure the v2 policy hash binds to the v2 runtime-config attestation key (not v1).
                if ($to === strtolower($instanceController) && $data === $attestationCallV1) {
                    return json_encode([
                        'jsonrpc' => '2.0',
                        'id' => 1,
                        'result' => '0x' . str_repeat('00', 32),
                    ], JSON_THROW_ON_ERROR);
                }
                if ($to === strtolower($instanceController) && $data === $lockedCallV1) {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::boolResult(true)], JSON_THROW_ON_ERROR);
                }

                if ($to === strtolower($instanceController) && $data === $attestationCallV2) {
                    return json_encode([
                        'jsonrpc' => '2.0',
                        'id' => 1,
                        'result' => $canonical,
                    ], JSON_THROW_ON_ERROR);
                }
                if ($to === strtolower($instanceController) && $data === $lockedCallV2) {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::boolResult(true)], JSON_THROW_ON_ERROR);
                }
            }

            throw new \RuntimeException('unexpected request');
        });

        $kernel = new TrustKernel($cfg, new TestLogger(), $transport);

        try {
            $status = $kernel->check();
            self::assertTrue($status->trustedNow);
            self::assertTrue($status->readAllowed);
            self::assertTrue($status->writeAllowed);
        } finally {
            $fixture->cleanup();
        }
    }
}
