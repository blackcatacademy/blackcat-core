<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel\AttackFlows;

use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\Abi;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\IntegrityFixture;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\ScenarioTransport;
use BlackCat\Core\TrustKernel\TrustKernel;
use BlackCat\Core\TrustKernel\TrustKernelConfig;
use PHPUnit\Framework\TestCase;

final class ProxyAttackFlowsTest extends TestCase
{
    public function testEip1167CloneWithMissingImplementationCodeDenies(): void
    {
        $fixture = IntegrityFixture::create(['app.txt' => 'ok']);

        $instanceController = '0x1111111111111111111111111111111111111111';
        $releaseRegistry = '0x2222222222222222222222222222222222222222';

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

        $impl = '0x9999999999999999999999999999999999999999';
        $eip1167 = '0x'
            . '363d3d373d3d3d363d73'
            . substr($impl, 2)
            . '5af43d82803e903d91602b57fd5bf3';

        $transport = new ScenarioTransport(static function (string $url, array $req, int $timeout, int $callIndex) use (
            $snapshotHex,
            $instanceController,
            $releaseRegistry,
            $fixture,
            $impl,
            $eip1167,
        ): string {
            $method = $req['method'] ?? null;

            if ($method === 'eth_chainId') {
                return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => '0x106f'], JSON_THROW_ON_ERROR);
            }

            if ($method === 'eth_getCode') {
                $params = $req['params'] ?? null;
                $addr = is_array($params) && isset($params[0]) ? strtolower((string) $params[0]) : '';
                if ($addr === strtolower($instanceController)) {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => $eip1167], JSON_THROW_ON_ERROR);
                }
                if ($addr === strtolower($impl)) {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => '0x'], JSON_THROW_ON_ERROR);
                }
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
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::boolResult(true)], JSON_THROW_ON_ERROR);
                }
            }

            throw new \RuntimeException('unexpected request');
        });

        $kernel = new TrustKernel($cfg, null, $transport);

        try {
            $status = $kernel->check();
            self::assertFalse($status->trustedNow);
            self::assertContains('InstanceController EIP-1167 implementation has no code.', $status->errors);
        } finally {
            $fixture->cleanup();
        }
    }
}
