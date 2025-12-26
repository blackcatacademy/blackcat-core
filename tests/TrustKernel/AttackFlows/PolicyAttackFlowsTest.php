<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel\AttackFlows;

use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\Abi;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\IntegrityFixture;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\ScenarioTransport;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\TestLogger;
use BlackCat\Core\TrustKernel\TrustKernel;
use BlackCat\Core\TrustKernel\TrustKernelConfig;
use BlackCat\Core\TrustKernel\TrustKernelException;
use PHPUnit\Framework\TestCase;

final class PolicyAttackFlowsTest extends TestCase
{
    public function testUnknownPolicyNeverFallsBackToWarn(): void
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
            releaseRegistry: null,
            integrityRootDir: $fixture->rootDir,
            integrityManifestPath: $fixture->manifestPath,
            rpcTimeoutSec: 5,
        );

        $logger = new TestLogger();

        $step = 0;
        $transport = new ScenarioTransport(static function (string $url, array $req, int $timeout, int $callIndex) use (
            &$step,
            $cfg,
            $fixture,
            $instanceController,
            $releaseRegistry,
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
                    $step++;
                    $policy = match ($step) {
                        1, 2 => $cfg->policyHashV2Warn,
                        default => '0x' . str_repeat('11', 32),
                    };
                    $paused = $step >= 2;

                    $snapshotHex = Abi::snapshotResult(
                        version: 1,
                        paused: $paused,
                        activeRoot: $fixture->rootBytes32,
                        activeUriHash: $fixture->uriHashBytes32 ?? ('0x' . str_repeat('00', 32)),
                        activePolicyHash: $policy,
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
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::addressResult($releaseRegistry)], JSON_THROW_ON_ERROR);
                }

                if ($to === strtolower($releaseRegistry) && str_starts_with($data, '0x3cb692b8')) {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::boolResult(true)], JSON_THROW_ON_ERROR);
                }
            }

            throw new \RuntimeException('unexpected request');
        });

        $kernel = new TrustKernel($cfg, $logger, $transport);

        try {
            // Step 1: warn policy, trusted => OK.
            $status1 = $kernel->check();
            self::assertTrue($status1->trustedNow);

            // Step 2: warn policy + paused => not trusted, but warn-only (no throw).
            usleep(1_100_000);
            $kernel->assertWriteAllowed('db.write');
            $banner = array_values(array_filter(
                $logger->records,
                static fn (array $r): bool => str_contains($r['message'], 'WARNING MODE enabled')
            ));
            self::assertNotEmpty($banner);

            // Step 3: unknown policy => must enforce strict (throw), never fallback to warn.
            usleep(1_100_000);
            $this->expectException(TrustKernelException::class);
            $kernel->assertWriteAllowed('db.write');
        } finally {
            $fixture->cleanup();
        }
    }
}
