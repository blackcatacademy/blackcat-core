<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel\AttackFlows;

use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\Abi;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\IntegrityFixture;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\ScenarioTransport;
use BlackCat\Core\TrustKernel\TrustKernel;
use BlackCat\Core\TrustKernel\TrustKernelConfig;
use PHPUnit\Framework\TestCase;

final class IntegrityAttackFlowsTest extends TestCase
{
    public function testFullModeDeniesUnexpectedFilesInIntegrityRoot(): void
    {
        $fixture = IntegrityFixture::create(['app.txt' => 'ok']);

        $instanceController = '0x1111111111111111111111111111111111111111';

        $cfg = new TrustKernelConfig(
            chainId: 4207,
            rpcEndpoints: ['https://a'],
            rpcQuorum: 1,
            maxStaleSec: 3,
            mode: 'full',
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
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::addressResult('0x0000000000000000000000000000000000000000')], JSON_THROW_ON_ERROR);
                }
            }

            throw new \RuntimeException('unexpected request');
        });

        $kernel = new TrustKernel($cfg, null, $transport);

        try {
            $ok = $kernel->check();
            self::assertTrue($ok->trustedNow);

            $extra = $fixture->rootDir . DIRECTORY_SEPARATOR . 'evil.txt';
            if (@file_put_contents($extra, 'x') === false) {
                self::fail('Unable to create extra file.');
            }

            $kernel2 = new TrustKernel($cfg, null, $transport);
            $status = $kernel2->check();
            self::assertFalse($status->trustedNow);
            self::assertContains('integrity_unexpected_file', $status->errorCodes);
        } finally {
            $fixture->cleanup();
        }
    }

    public function testRemovingUriFromManifestCannotBypassUriHashCheck(): void
    {
        $fixture = IntegrityFixture::create(['app.txt' => 'ok'], 'https://example.invalid/blackcat');

        $instanceController = '0x1111111111111111111111111111111111111111';

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
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::addressResult('0x0000000000000000000000000000000000000000')], JSON_THROW_ON_ERROR);
                }
            }

            throw new \RuntimeException('unexpected request');
        });

        try {
            $kernel = new TrustKernel($cfg, null, $transport);
            $ok = $kernel->check();
            self::assertTrue($ok->trustedNow);

            $raw = @file_get_contents($fixture->manifestPath);
            if (!is_string($raw)) {
                self::fail('Unable to read manifest.');
            }

            /** @var mixed $decoded */
            $decoded = json_decode($raw, true);
            if (!is_array($decoded)) {
                self::fail('Manifest JSON did not decode.');
            }

            unset($decoded['uri']);
            $newRaw = json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            if (!is_string($newRaw)) {
                self::fail('Unable to encode tampered manifest JSON.');
            }
            if (@file_put_contents($fixture->manifestPath, $newRaw) === false) {
                self::fail('Unable to write tampered manifest JSON.');
            }

            $kernel2 = new TrustKernel($cfg, null, $transport);
            $status = $kernel2->check();
            self::assertFalse($status->trustedNow);
            self::assertContains('uri_hash_missing', $status->errorCodes);
        } finally {
            $fixture->cleanup();
        }
    }
}

