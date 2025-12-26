<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel\AttackFlows;

use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\Abi;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\IntegrityFixture;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\ScenarioTransport;
use BlackCat\Core\TrustKernel\TrustKernel;
use BlackCat\Core\TrustKernel\TrustKernelConfig;
use BlackCat\Core\TrustKernel\TrustKernelException;
use PHPUnit\Framework\TestCase;

final class ReleaseRegistryAttackFlowsTest extends TestCase
{
    public function testUntrustedActiveRootDeniesEvenWithoutConfigPin(): void
    {
        $fixture = IntegrityFixture::create(['app.txt' => 'ok']);

        $instanceController = '0x1111111111111111111111111111111111111111';
        $releaseRegistry = '0x2222222222222222222222222222222222222222';

        $cfg = new TrustKernelConfig(
            chainId: 4207,
            rpcEndpoints: ['https://a'],
            rpcQuorum: 1,
            maxStaleSec: 3,
            mode: 'root_uri',
            instanceController: $instanceController,
            releaseRegistry: null, // no pin => should still enforce via controller pointer
            integrityRootDir: $fixture->rootDir,
            integrityManifestPath: $fixture->manifestPath,
            rpcTimeoutSec: 5,
        );

        $snapshotHex = Abi::snapshotResult(
            version: 1,
            paused: false,
            activeRoot: $fixture->rootBytes32,
            activeUriHash: $fixture->uriHashBytes32 ?? ('0x' . str_repeat('00', 32)),
            activePolicyHash: $cfg->policyHashV2Strict,
            pendingRoot: '0x' . str_repeat('00', 32),
            pendingUriHash: '0x' . str_repeat('00', 32),
            pendingPolicyHash: '0x' . str_repeat('00', 32),
            pendingCreatedAt: 0,
            pendingTtlSec: 0,
            genesisAt: 1,
            lastUpgradeAt: 1,
        );

        $transport = new ScenarioTransport(static function (string $url, array $req, int $timeout, int $callIndex) use (
            $snapshotHex,
            $instanceController,
            $releaseRegistry,
            $fixture,
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
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => $snapshotHex], JSON_THROW_ON_ERROR);
                }
                if ($to === strtolower($instanceController) && $data === '0x19ee073e') {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::addressResult($releaseRegistry)], JSON_THROW_ON_ERROR);
                }

                if ($to === strtolower($releaseRegistry) && str_starts_with($data, '0x3cb692b8')) {
                    $expectedPrefix = '0x3cb692b8' . substr(strtolower($fixture->rootBytes32), 2);
                    if (!str_starts_with($data, $expectedPrefix)) {
                        throw new \RuntimeException('unexpected isTrustedRoot data');
                    }
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::boolResult(false)], JSON_THROW_ON_ERROR);
                }
            }

            throw new \RuntimeException('unexpected request');
        });

        $kernel = new TrustKernel($cfg, null, $transport);

        try {
            $kernel->assertWriteAllowed('db.write');
            self::fail('Expected strict denial.');
        } catch (TrustKernelException) {
            self::assertTrue(true);
        } finally {
            $fixture->cleanup();
        }
    }

    public function testConfigPinnedReleaseRegistryMismatchDenies(): void
    {
        $fixture = IntegrityFixture::create(['app.txt' => 'ok']);

        $instanceController = '0x1111111111111111111111111111111111111111';
        $releaseRegistryOnChain = '0x2222222222222222222222222222222222222222';
        $releaseRegistryPinned = '0x3333333333333333333333333333333333333333';

        $cfg = new TrustKernelConfig(
            chainId: 4207,
            rpcEndpoints: ['https://a'],
            rpcQuorum: 1,
            maxStaleSec: 3,
            mode: 'root_uri',
            instanceController: $instanceController,
            releaseRegistry: $releaseRegistryPinned, // pin mismatch must fail
            integrityRootDir: $fixture->rootDir,
            integrityManifestPath: $fixture->manifestPath,
            rpcTimeoutSec: 5,
        );

        $snapshotHex = Abi::snapshotResult(
            version: 1,
            paused: false,
            activeRoot: $fixture->rootBytes32,
            activeUriHash: $fixture->uriHashBytes32 ?? ('0x' . str_repeat('00', 32)),
            activePolicyHash: $cfg->policyHashV2Strict,
            pendingRoot: '0x' . str_repeat('00', 32),
            pendingUriHash: '0x' . str_repeat('00', 32),
            pendingPolicyHash: '0x' . str_repeat('00', 32),
            pendingCreatedAt: 0,
            pendingTtlSec: 0,
            genesisAt: 1,
            lastUpgradeAt: 1,
        );

        $transport = new ScenarioTransport(static function (string $url, array $req, int $timeout, int $callIndex) use (
            $snapshotHex,
            $instanceController,
            $releaseRegistryOnChain,
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
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => $snapshotHex], JSON_THROW_ON_ERROR);
                }
                if ($to === strtolower($instanceController) && $data === '0x19ee073e') {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::addressResult($releaseRegistryOnChain)], JSON_THROW_ON_ERROR);
                }
            }

            throw new \RuntimeException('unexpected request');
        });

        $kernel = new TrustKernel($cfg, null, $transport);

        try {
            $kernel->check();
            $kernel->assertWriteAllowed('db.write');
            self::fail('Expected strict denial.');
        } catch (TrustKernelException $e) {
            self::assertStringContainsString('ReleaseRegistry mismatch', $e->getMessage());
        } finally {
            $fixture->cleanup();
        }
    }

    public function testReleaseRegistryPointerZeroIsAllowedWhenNotPinned(): void
    {
        $fixture = IntegrityFixture::create(['app.txt' => 'ok']);

        $instanceController = '0x1111111111111111111111111111111111111111';
        $zero = '0x0000000000000000000000000000000000000000';

        $cfg = new TrustKernelConfig(
            chainId: 4207,
            rpcEndpoints: ['https://a'],
            rpcQuorum: 1,
            maxStaleSec: 3,
            mode: 'root_uri',
            instanceController: $instanceController,
            releaseRegistry: null,
            integrityRootDir: $fixture->rootDir,
            integrityManifestPath: $fixture->manifestPath,
            rpcTimeoutSec: 5,
        );

        $snapshotHex = Abi::snapshotResult(
            version: 1,
            paused: false,
            activeRoot: $fixture->rootBytes32,
            activeUriHash: $fixture->uriHashBytes32 ?? ('0x' . str_repeat('00', 32)),
            activePolicyHash: $cfg->policyHashV2Strict,
            pendingRoot: '0x' . str_repeat('00', 32),
            pendingUriHash: '0x' . str_repeat('00', 32),
            pendingPolicyHash: '0x' . str_repeat('00', 32),
            pendingCreatedAt: 0,
            pendingTtlSec: 0,
            genesisAt: 1,
            lastUpgradeAt: 1,
        );

        $transport = new ScenarioTransport(static function (string $url, array $req, int $timeout, int $callIndex) use (
            $snapshotHex,
            $instanceController,
            $zero,
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
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => $snapshotHex], JSON_THROW_ON_ERROR);
                }
                if ($to === strtolower($instanceController) && $data === '0x19ee073e') {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::addressResult($zero)], JSON_THROW_ON_ERROR);
                }
            }

            throw new \RuntimeException('unexpected request');
        });

        $kernel = new TrustKernel($cfg, null, $transport);

        try {
            $status = $kernel->check();
            self::assertTrue($status->trustedNow);
        } finally {
            $fixture->cleanup();
        }
    }
}
