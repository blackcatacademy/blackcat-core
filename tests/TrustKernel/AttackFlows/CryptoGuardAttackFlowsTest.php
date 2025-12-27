<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel\AttackFlows;

use BlackCat\Core\Database;
use BlackCat\Core\Security\Crypto;
use BlackCat\Core\Security\KeyManager;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\Abi;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\IntegrityFixture;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\ScenarioTransport;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\TestLogger;
use BlackCat\Core\TrustKernel\TrustKernel;
use BlackCat\Core\TrustKernel\TrustKernelConfig;
use BlackCat\Core\TrustKernel\TrustKernelException;
use PHPUnit\Framework\TestCase;

final class CryptoGuardAttackFlowsTest extends TestCase
{
    protected function tearDown(): void
    {
        try {
            Crypto::clearKey();
        } catch (\Throwable) {
            // ignore
        }

        self::writePrivateStatic(KeyManager::class, 'accessGuardLocked', false);
        self::writePrivateStatic(KeyManager::class, 'accessGuard', null);
        self::writePrivateStatic(KeyManager::class, 'trustKernelAutoBootAttempted', false);
        self::writePrivateStatic(KeyManager::class, 'cache', []);

        self::writePrivateStatic(Database::class, 'writeGuardLocked', false);
        self::writePrivateStatic(Database::class, 'writeGuard', null);
        self::writePrivateStatic(Database::class, 'pdoAccessGuardLocked', false);
        self::writePrivateStatic(Database::class, 'pdoAccessGuard', null);
        self::writePrivateStatic(Database::class, 'trustKernelAutoBootAttempted', false);
    }

    public function testCryptoOperationsFailClosedAfterTrustBecomesUntrustedInStrictPolicy(): void
    {
        $fixture = IntegrityFixture::create(['app.txt' => 'ok']);

        $keysDir = $fixture->rootDir . DIRECTORY_SEPARATOR . 'keys';
        if (!@mkdir($keysDir, 0700, true) && !is_dir($keysDir)) {
            self::fail('Unable to create keys dir.');
        }

        $keyPath = $keysDir . DIRECTORY_SEPARATOR . 'crypto_key_v1.key';
        if (@file_put_contents($keyPath, str_repeat('a', 32)) === false) {
            self::fail('Unable to write crypto key file.');
        }

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

        $snapshotCalls = 0;
        $transport = new ScenarioTransport(static function (string $url, array $req, int $timeoutSec, int $callIndex) use ($cfg, $fixture, $instanceController, &$snapshotCalls): string {
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
                    $snapshotCalls++;
                    $paused = $snapshotCalls >= 2;

                    $snapshotHex = Abi::snapshotResult(
                        version: 1,
                        paused: $paused,
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
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => $snapshotHex], JSON_THROW_ON_ERROR);
                }

                if ($to === strtolower($instanceController) && $data === '0x19ee073e') {
                    return json_encode([
                        'jsonrpc' => '2.0',
                        'id' => 1,
                        'result' => Abi::addressResult('0x0000000000000000000000000000000000000000'),
                    ], JSON_THROW_ON_ERROR);
                }
            }

            throw new \RuntimeException('unexpected request');
        });

        $logger = new TestLogger();
        $kernel = new TrustKernel($cfg, $logger, $transport);
        $kernel->installGuards();

        try {
            // Snapshot #1: trusted => init OK.
            Crypto::initFromKeyManager($keysDir, $logger);

            // Snapshot #2: paused => TrustKernel denies reads, Crypto must fail closed even with cached keys.
            usleep(1_100_000);
            $this->expectException(TrustKernelException::class);
            Crypto::encrypt('hello');
        } finally {
            $fixture->cleanup();
        }
    }

    public function testCryptoOperationsLogButProceedInWarnPolicy(): void
    {
        $fixture = IntegrityFixture::create(['app.txt' => 'ok']);

        $keysDir = $fixture->rootDir . DIRECTORY_SEPARATOR . 'keys';
        if (!@mkdir($keysDir, 0700, true) && !is_dir($keysDir)) {
            self::fail('Unable to create keys dir.');
        }

        $keyPath = $keysDir . DIRECTORY_SEPARATOR . 'crypto_key_v1.key';
        if (@file_put_contents($keyPath, str_repeat('a', 32)) === false) {
            self::fail('Unable to write crypto key file.');
        }

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

        $snapshotCalls = 0;
        $transport = new ScenarioTransport(static function (string $url, array $req, int $timeoutSec, int $callIndex) use ($cfg, $fixture, $instanceController, &$snapshotCalls): string {
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
                    $snapshotCalls++;
                    $paused = $snapshotCalls >= 2;

                    $snapshotHex = Abi::snapshotResult(
                        version: 1,
                        paused: $paused,
                        activeRoot: $fixture->rootBytes32,
                        activeUriHash: $fixture->uriHashBytes32 ?? ('0x' . str_repeat('00', 32)),
                        activePolicyHash: $cfg->policyHashV2Warn,
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
            }

            throw new \RuntimeException('unexpected request');
        });

        $logger = new TestLogger();
        $kernel = new TrustKernel($cfg, $logger, $transport);
        $kernel->installGuards();

        try {
            // Snapshot #1: trusted => init OK.
            Crypto::initFromKeyManager($keysDir, $logger);

            // Snapshot #2: paused => warn-only => Crypto proceeds, but should emit warnings.
            usleep(1_100_000);
            $cipher = Crypto::encrypt('hello');
            self::assertNotSame('', $cipher);

            $banner = array_values(array_filter(
                $logger->records,
                static fn (array $r): bool => str_contains($r['message'], 'WARNING MODE enabled')
            ));
            self::assertNotEmpty($banner);

            $denies = array_values(array_filter(
                $logger->records,
                static fn (array $r): bool => str_contains($r['message'], '[trust-kernel] denied: secrets.read')
            ));
            self::assertNotEmpty($denies);
        } finally {
            $fixture->cleanup();
        }
    }

    private static function writePrivateStatic(string $class, string $property, mixed $value): void
    {
        $ref = new \ReflectionProperty($class, $property);
        $ref->setAccessible(true);
        $ref->setValue(null, $value);
    }
}
