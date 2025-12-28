<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel\AttackFlows;

use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\Abi;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\IntegrityFixture;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\ScenarioTransport;
use BlackCat\Core\TrustKernel\TrustKernel;
use BlackCat\Core\TrustKernel\TrustKernelConfig;
use PHPUnit\Framework\TestCase;

final class StaleModeStateFileAttackFlowsTest extends TestCase
{
    public function testRpcOutageAllowsStaleReadOnlyWhenStateFileIsProtectedFromRuntimeWrites(): void
    {
        $fixture = IntegrityFixture::create(['app.txt' => 'ok']);

        $instanceController = '0x1111111111111111111111111111111111111111';
        $releaseRegistry = '0x2222222222222222222222222222222222222222';

        $cfgDir = $fixture->rootDir . DIRECTORY_SEPARATOR . 'cfg';
        if (!@mkdir($cfgDir, 0700, true) && !is_dir($cfgDir)) {
            self::fail('Unable to create cfg dir.');
        }

        $runtimeConfigPath = $cfgDir . DIRECTORY_SEPARATOR . 'runtime-config.json';
        if (@file_put_contents($runtimeConfigPath, "{\n  \"ok\": true\n}\n") === false) {
            self::fail('Unable to write runtime config JSON.');
        }

        $cfg = new TrustKernelConfig(
            chainId: 4207,
            rpcEndpoints: ['https://a', 'https://b'],
            rpcQuorum: 2,
            maxStaleSec: 5,
            mode: 'root_uri',
            instanceController: $instanceController,
            releaseRegistry: null,
            integrityRootDir: $fixture->rootDir,
            integrityManifestPath: $fixture->manifestPath,
            rpcTimeoutSec: 5,
            runtimeConfigCanonicalSha256: null,
            runtimeConfigSourcePath: $runtimeConfigPath,
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

        $transportOk = new ScenarioTransport(static function (string $url, array $req, int $timeout, int $callIndex) use (
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
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::boolResult(true)], JSON_THROW_ON_ERROR);
                }
            }

            throw new \RuntimeException('unexpected request');
        });

        $transportDown = new ScenarioTransport(static function (string $url, array $req, int $timeout, int $callIndex): string {
            throw new \RuntimeException('simulated rpc outage');
        });

        $stateFile = $cfgDir . DIRECTORY_SEPARATOR . 'trust.last_ok.v1.json';

        try {
            $kernel1 = new TrustKernel($cfg, null, $transportOk);
            $status1 = $kernel1->check();
            self::assertTrue($status1->trustedNow);

            // Simulate a hardened deployment: the web runtime can read the state file, but cannot modify
            // it (neither write-in-place nor replace-in-dir).
            self::assertFileExists($stateFile, 'expected persisted state file');
            @chmod($stateFile, 0444);
            @chmod($cfgDir, 0555);

            $canUsePersistedState = false;
            if (function_exists('posix_geteuid')) {
                $euid = @posix_geteuid();
                if (is_int($euid) && $euid === 0) {
                    $canUsePersistedState = true;
                } elseif (is_int($euid)) {
                    $ownerFile = @fileowner($stateFile);
                    $ownerDir = @fileowner($cfgDir);
                    $permsFile = @fileperms($stateFile);
                    $permsDir = @fileperms($cfgDir);

                    $canUsePersistedState = !is_writable($stateFile)
                        && !is_writable($cfgDir)
                        && !is_link($stateFile)
                        && !is_link($cfgDir)
                        && is_int($ownerFile) && $ownerFile !== $euid
                        && is_int($ownerDir) && $ownerDir !== $euid
                        && is_int($permsFile) && (($permsFile & 0o022) === 0)
                        && is_int($permsDir) && (($permsDir & 0o022) === 0);
                }
            }

            usleep(1_100_000);

            $kernel2 = new TrustKernel($cfg, null, $transportDown);
            $status2 = $kernel2->check();
            self::assertFalse($status2->rpcOkNow);
            if ($canUsePersistedState) {
                self::assertNotNull($status2->lastOkAt, 'expected last_ok_at to load from protected state file');
                self::assertTrue($status2->readAllowed, 'stale read should be allowed using persisted last OK');
            } else {
                self::assertNull($status2->lastOkAt, 'expected last_ok_at to be ignored when state file can be forged by the runtime user');
                self::assertFalse($status2->readAllowed, 'stale read must be denied when state file is not protected from runtime writes');
            }

            $fixture->tamper('app.txt', 'tampered');
            usleep(1_100_000);

            $status3 = $kernel2->check();
            self::assertFalse($status3->readAllowed, 'stale read must be denied after local tamper');
        } finally {
            @chmod($cfgDir, 0700);
            @chmod($stateFile, 0644);
            $fixture->cleanup();
        }
    }
}
