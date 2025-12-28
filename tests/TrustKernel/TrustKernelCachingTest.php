<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel;

use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\Abi;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\IntegrityFixture;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\ScenarioTransport;
use BlackCat\Core\TrustKernel\TrustKernel;
use BlackCat\Core\TrustKernel\TrustKernelConfig;
use PHPUnit\Framework\TestCase;

final class TrustKernelCachingTest extends TestCase
{
    public function testCheckCachesOnlyWithinSameRequest(): void
    {
        $fixture = IntegrityFixture::create(['app.txt' => 'ok'], 'https://example.invalid/blackcat');

        $prevRequestTime = $_SERVER['REQUEST_TIME_FLOAT'] ?? null;
        $prevMethod = $_SERVER['REQUEST_METHOD'] ?? null;
        $prevUri = $_SERVER['REQUEST_URI'] ?? null;

        try {
            $_SERVER['REQUEST_METHOD'] = 'GET';
            $_SERVER['REQUEST_URI'] = '/';

            $chainId = 4207;
            $instanceController = '0x1111111111111111111111111111111111111111';

            $cfg = new TrustKernelConfig(
                chainId: $chainId,
                rpcEndpoints: ['https://a', 'https://b'],
                rpcQuorum: 2,
                maxStaleSec: 60,
                mode: 'root_uri',
                instanceController: $instanceController,
                releaseRegistry: null,
                integrityRootDir: $fixture->rootDir,
                integrityManifestPath: $fixture->manifestPath,
                rpcTimeoutSec: 1,
            );

            $snapshotCalls = 0;

            $snapshot = Abi::snapshotResult(
                version: 1,
                paused: false,
                activeRoot: $fixture->rootBytes32,
                activeUriHash: $fixture->uriHashBytes32 ?? ('0x' . str_repeat('00', 32)),
                activePolicyHash: $cfg->policyHashV1,
                pendingRoot: '0x' . str_repeat('00', 32),
                pendingUriHash: '0x' . str_repeat('00', 32),
                pendingPolicyHash: '0x' . str_repeat('00', 32),
                pendingCreatedAt: 0,
                pendingTtlSec: 0,
                genesisAt: 0,
                lastUpgradeAt: 0,
            );

            $transport = new ScenarioTransport(static function (string $url, array $req, int $timeoutSec, int $callIndex) use ($chainId, &$snapshotCalls, $snapshot): string {
                $method = $req['method'] ?? null;
                $params = $req['params'] ?? null;

                if ($method === 'eth_chainId') {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => '0x' . dechex($chainId)], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
                }

                if ($method === 'eth_call' && is_array($params) && isset($params[0]) && is_array($params[0])) {
                    $data = $params[0]['data'] ?? null;
                    if (is_string($data)) {
                        $data = strtolower($data);
                        if ($data === '0x9711715a') { // snapshot()
                            $snapshotCalls++;
                            return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => $snapshot], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
                        }
                        if ($data === '0x19ee073e') { // releaseRegistry()
                            return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::addressResult('0x0000000000000000000000000000000000000000')], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
                        }
                    }

                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => '0x'], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
                }

                if ($method === 'eth_getCode') {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => '0x6001600055'], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
                }

                return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'error' => ['message' => 'unexpected method']], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            });

            $kernel = new TrustKernel($cfg, null, $transport);

            $_SERVER['REQUEST_TIME_FLOAT'] = 1000.000001;
            $kernel->check();
            $kernel->check();
            self::assertSame(2, $snapshotCalls, 'Expected snapshot() to be cached within the same request (2 endpoints, quorum=2).');

            $_SERVER['REQUEST_TIME_FLOAT'] = 1000.000002;
            $kernel->check();
            self::assertSame(4, $snapshotCalls, 'Expected snapshot() to be re-fetched on a new request (2 endpoints, quorum=2).');
        } finally {
            if ($prevRequestTime === null) {
                unset($_SERVER['REQUEST_TIME_FLOAT']);
            } else {
                $_SERVER['REQUEST_TIME_FLOAT'] = $prevRequestTime;
            }

            if ($prevMethod === null) {
                unset($_SERVER['REQUEST_METHOD']);
            } else {
                $_SERVER['REQUEST_METHOD'] = $prevMethod;
            }

            if ($prevUri === null) {
                unset($_SERVER['REQUEST_URI']);
            } else {
                $_SERVER['REQUEST_URI'] = $prevUri;
            }
            $fixture->cleanup();
        }
    }
}
