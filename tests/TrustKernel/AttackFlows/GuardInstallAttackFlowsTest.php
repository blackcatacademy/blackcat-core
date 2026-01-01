<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel\AttackFlows;

use BlackCat\Core\Database;
use BlackCat\Core\DatabaseException;
use BlackCat\Core\Security\KeyManager;
use BlackCat\Core\Security\KeyManagerException;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\Abi;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\IntegrityFixture;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\ScenarioTransport;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\TestLogger;
use BlackCat\Core\TrustKernel\TrustKernel;
use BlackCat\Core\TrustKernel\TrustKernelConfig;
use BlackCat\Core\TrustKernel\TrustKernelException;
use PHPUnit\Framework\TestCase;

final class GuardInstallAttackFlowsTest extends TestCase
{
    protected function tearDown(): void
    {
        // Avoid leaking guards/locks into other tests.
        self::writePrivateStatic(KeyManager::class, 'accessGuardLocked', false);
        self::writePrivateStatic(KeyManager::class, 'accessGuard', null);
        self::writePrivateStatic(KeyManager::class, 'cache', []);

        self::writePrivateStatic(Database::class, 'readGuardLocked', false);
        self::writePrivateStatic(Database::class, 'readGuard', null);
        self::writePrivateStatic(Database::class, 'writeGuardLocked', false);
        self::writePrivateStatic(Database::class, 'writeGuard', null);
        self::writePrivateStatic(Database::class, 'pdoAccessGuardLocked', false);
        self::writePrivateStatic(Database::class, 'pdoAccessGuard', null);
    }

    public function testInstallGuardsDeniesKeyReadsAndDbWritesInStrictMode(): void
    {
        $fixture = IntegrityFixture::create(['app.txt' => 'ok']);

        $keysDir = $fixture->rootDir . DIRECTORY_SEPARATOR . 'keys';
        if (!@mkdir($keysDir, 0700, true) && !is_dir($keysDir)) {
            self::fail('Unable to create keys dir.');
        }

        // 32 bytes (avoid sodium constants in this test).
        $keyPath = $keysDir . DIRECTORY_SEPARATOR . 'app_salt_v1.key';
        if (@file_put_contents($keyPath, str_repeat('a', 32)) === false) {
            self::fail('Unable to write key file.');
        }

        $instanceController = '0x1111111111111111111111111111111111111111';

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

        $transport = new ScenarioTransport(static function (string $url, array $req, int $timeoutSec, int $callIndex) use ($cfg, $fixture, $instanceController): string {
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
                        paused: true,
                        activeRoot: $fixture->rootBytes32,
                        activeUriHash: $fixture->uriHashBytes32 ?? ('0x' . str_repeat('00', 32)),
                        activePolicyHash: $cfg->policyHashV1,
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

        $kernel = new TrustKernel($cfg, new TestLogger(), $transport);
        $kernel->installGuards();

        $keyGuard = self::readPrivateStatic(KeyManager::class, 'accessGuard');
        self::assertIsCallable($keyGuard);

        $readGuard = self::readPrivateStatic(Database::class, 'readGuard');
        self::assertIsCallable($readGuard);

        $dbGuard = self::readPrivateStatic(Database::class, 'writeGuard');
        self::assertIsCallable($dbGuard);

        $pdoGuard = self::readPrivateStatic(Database::class, 'pdoAccessGuard');
        self::assertIsCallable($pdoGuard);

        // Guards must not be disable-able at runtime.
        try {
            KeyManager::setAccessGuard(null);
            self::fail('Expected KeyManagerException when disabling the access guard.');
        } catch (KeyManagerException) {
            // ok
        }
        try {
            Database::setReadGuard(null);
            self::fail('Expected DatabaseException when disabling the DB read guard.');
        } catch (DatabaseException) {
            // ok
        }
        try {
            Database::setWriteGuard(null);
            self::fail('Expected DatabaseException when disabling the DB write guard.');
        } catch (DatabaseException) {
            // ok
        }
        try {
            Database::setPdoAccessGuard(null);
            self::fail('Expected DatabaseException when disabling the PDO access guard.');
        } catch (DatabaseException) {
            // ok
        }

        try {
            KeyManager::getAllRawKeys('APP_SALT', $keysDir, 'app_salt', 32);
            self::fail('Expected TrustKernelException for KeyManager::getAllRawKeys().');
        } catch (TrustKernelException) {
            // ok
        }

        try {
            /** @var callable(string):void $keyGuard */
            $keyGuard('read');
            self::fail('Expected TrustKernelException for key reads.');
        } catch (TrustKernelException) {
            // ok
        }

        try {
            /** @var callable(string):void $readGuard */
            $readGuard('SELECT 1');
            self::fail('Expected TrustKernelException for DB reads.');
        } catch (TrustKernelException) {
            // ok
        }

        try {
            /** @var callable(string):void $dbGuard */
            $dbGuard('UPDATE example SET x=1');
            self::fail('Expected TrustKernelException for DB writes.');
        } catch (TrustKernelException) {
            // ok
        }

        try {
            /** @var callable(string):void $pdoGuard */
            $pdoGuard('db.raw_pdo');
            self::fail('Expected TrustKernelException for raw PDO access.');
        } catch (TrustKernelException) {
            // ok
        } finally {
            $fixture->cleanup();
        }
    }

    public function testInstallGuardsWarnsButDoesNotThrowInWarnPolicy(): void
    {
        $fixture = IntegrityFixture::create(['app.txt' => 'ok']);

        $keysDir = $fixture->rootDir . DIRECTORY_SEPARATOR . 'keys';
        if (!@mkdir($keysDir, 0700, true) && !is_dir($keysDir)) {
            self::fail('Unable to create keys dir.');
        }

        // 32 bytes (avoid sodium constants in this test).
        $keyPath = $keysDir . DIRECTORY_SEPARATOR . 'app_salt_v1.key';
        if (@file_put_contents($keyPath, str_repeat('a', 32)) === false) {
            self::fail('Unable to write key file.');
        }

        $instanceController = '0x1111111111111111111111111111111111111111';

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

        $logger = new TestLogger();
        $transport = new ScenarioTransport(static function (string $url, array $req, int $timeoutSec, int $callIndex) use ($cfg, $fixture, $instanceController): string {
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
                        activeRoot: '0x' . str_repeat('22', 32),
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

        $kernel = new TrustKernel($cfg, $logger, $transport);
        $kernel->installGuards();

        $keyGuard = self::readPrivateStatic(KeyManager::class, 'accessGuard');
        self::assertIsCallable($keyGuard);

        $readGuard = self::readPrivateStatic(Database::class, 'readGuard');
        self::assertIsCallable($readGuard);

        $dbGuard = self::readPrivateStatic(Database::class, 'writeGuard');
        self::assertIsCallable($dbGuard);

        $pdoGuard = self::readPrivateStatic(Database::class, 'pdoAccessGuard');
        self::assertIsCallable($pdoGuard);

        // Guards must not be disable-able at runtime.
        try {
            KeyManager::setAccessGuard(null);
            self::fail('Expected KeyManagerException when disabling the access guard.');
        } catch (KeyManagerException) {
            // ok
        }
        try {
            Database::setReadGuard(null);
            self::fail('Expected DatabaseException when disabling the DB read guard.');
        } catch (DatabaseException) {
            // ok
        }
        try {
            Database::setWriteGuard(null);
            self::fail('Expected DatabaseException when disabling the DB write guard.');
        } catch (DatabaseException) {
            // ok
        }
        try {
            Database::setPdoAccessGuard(null);
            self::fail('Expected DatabaseException when disabling the PDO access guard.');
        } catch (DatabaseException) {
            // ok
        }

        // Must NOT throw (warn mode).
        /** @var callable(string):void $keyGuard */
        $keyGuard('read');
        // Must NOT throw (warn mode).
        /** @var callable(string):void $readGuard */
        $readGuard('SELECT 1');
        // Must NOT throw (warn mode).
        /** @var callable(string):void $dbGuard */
        $dbGuard('UPDATE example SET x=1');
        /** @var callable(string):void $pdoGuard */
        try {
            $pdoGuard('db.raw_pdo');
            self::fail('Expected TrustKernelException for raw PDO bypass (always forbidden, even in warn mode).');
        } catch (TrustKernelException) {
            // ok
        }

        $keys = KeyManager::getAllRawKeys('APP_SALT', $keysDir, 'app_salt', 32);
        self::assertCount(1, $keys);
        self::assertSame(str_repeat('a', 32), $keys[0]);

        $banner = array_values(array_filter(
            $logger->records,
            static fn (array $r): bool => str_contains($r['message'], 'WARNING MODE enabled')
        ));
        self::assertNotEmpty($banner);

        $denies = array_values(array_filter(
            $logger->records,
            static fn (array $r): bool => str_contains($r['message'], '[trust-kernel] denied:')
        ));
        self::assertNotEmpty($denies);

        $fixture->cleanup();
    }

    /**
     * @return mixed
     */
    private static function readPrivateStatic(string $class, string $property): mixed
    {
        $ref = new \ReflectionProperty($class, $property);
        $ref->setAccessible(true);
        return $ref->getValue();
    }

    private static function writePrivateStatic(string $class, string $property, mixed $value): void
    {
        $ref = new \ReflectionProperty($class, $property);
        $ref->setAccessible(true);
        $ref->setValue(null, $value);
    }
}
