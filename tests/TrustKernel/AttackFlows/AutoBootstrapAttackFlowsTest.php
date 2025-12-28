<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel\AttackFlows {

use BlackCat\Config\Runtime\Config;
use BlackCat\Core\Database;
use BlackCat\Core\Security\KeyManager;
use BlackCat\Core\Security\KeyManagerException;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\Abi;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\IntegrityFixture;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\ScenarioTransport;
use BlackCat\Core\TrustKernel\ArrayRuntimeConfigRepository;
use BlackCat\Core\TrustKernel\CanonicalJson;
use BlackCat\Core\TrustKernel\TrustKernelBootstrap;
use BlackCat\Core\TrustKernel\TrustKernelConfig;
use BlackCat\Core\TrustKernel\TrustKernelException;
use PHPUnit\Framework\TestCase;

/**
 * This test defines blackcat-config stubs and must not leak them into other test cases.
 *
 * @runClassInSeparateProcess
 */
final class AutoBootstrapAttackFlowsTest extends TestCase
{
    protected function setUp(): void
    {
        require_once __DIR__ . '/Support/BlackCatConfigRuntimeStub.php';

        // Ensure a clean baseline even if earlier tests triggered auto-boot without the stub loaded.
        self::writePrivateStatic(KeyManager::class, 'accessGuardLocked', false);
        self::writePrivateStatic(KeyManager::class, 'accessGuard', null);
        self::writePrivateStatic(KeyManager::class, 'trustKernelAutoBootAttempted', false);
        self::writePrivateStatic(KeyManager::class, 'cache', []);

        self::writePrivateStatic(Database::class, 'readGuardLocked', false);
        self::writePrivateStatic(Database::class, 'readGuard', null);
        self::writePrivateStatic(Database::class, 'writeGuardLocked', false);
        self::writePrivateStatic(Database::class, 'writeGuard', null);
        self::writePrivateStatic(Database::class, 'pdoAccessGuardLocked', false);
        self::writePrivateStatic(Database::class, 'pdoAccessGuard', null);
        self::writePrivateStatic(Database::class, 'trustKernelAutoBootAttempted', false);

        TrustKernelBootstrap::setDefaultTransport(null);
        Config::_clearRepo();
    }

    protected function tearDown(): void
    {
        // Avoid leaking guards/locks into other tests.
        self::writePrivateStatic(KeyManager::class, 'accessGuardLocked', false);
        self::writePrivateStatic(KeyManager::class, 'accessGuard', null);
        self::writePrivateStatic(KeyManager::class, 'trustKernelAutoBootAttempted', false);
        self::writePrivateStatic(KeyManager::class, 'cache', []);

        self::writePrivateStatic(Database::class, 'readGuardLocked', false);
        self::writePrivateStatic(Database::class, 'readGuard', null);
        self::writePrivateStatic(Database::class, 'writeGuardLocked', false);
        self::writePrivateStatic(Database::class, 'writeGuard', null);
        self::writePrivateStatic(Database::class, 'pdoAccessGuardLocked', false);
        self::writePrivateStatic(Database::class, 'pdoAccessGuard', null);
        self::writePrivateStatic(Database::class, 'trustKernelAutoBootAttempted', false);

        // Reset optional transport override.
        TrustKernelBootstrap::setDefaultTransport(null);

        // Reset the blackcat-config stub.
        Config::_clearRepo();

        // Reset DB singleton if initialized by the test.
        if (Database::isInitialized()) {
            self::writePrivateStatic(Database::class, 'instance', null);
        }
    }

    public function testKeyManagerAutoBootsTrustKernelAndInstallsGuards(): void
    {
        $fixture = IntegrityFixture::create(['app.txt' => 'ok']);

        $keysDir = $fixture->rootDir . DIRECTORY_SEPARATOR . 'keys';
        if (!@mkdir($keysDir, 0700, true) && !is_dir($keysDir)) {
            self::fail('Unable to create keys dir.');
        }
        $keyPath = $keysDir . DIRECTORY_SEPARATOR . 'app_salt_v1.key';
        if (@file_put_contents($keyPath, str_repeat('a', 32)) === false) {
            self::fail('Unable to write key file.');
        }

        $instanceController = '0x1111111111111111111111111111111111111111';

        $runtimeConfig = [
            'trust' => [
                'integrity' => [
                    'root_dir' => $fixture->rootDir,
                    'manifest' => $fixture->manifestPath,
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

        $runtimeConfigPath = $fixture->rootDir . DIRECTORY_SEPARATOR . 'runtime-config.json';
        $json = json_encode($runtimeConfig, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (!is_string($json) || @file_put_contents($runtimeConfigPath, $json) === false) {
            self::fail('Unable to write runtime config JSON.');
        }

        $cfg = TrustKernelConfig::fromRuntimeConfig(new ArrayRuntimeConfigRepository($runtimeConfig, $runtimeConfigPath));
        self::assertNotNull($cfg);

        $expectedRuntimeConfigSha = CanonicalJson::sha256Bytes32($runtimeConfig);

        $transport = new ScenarioTransport(static function (string $url, array $req, int $timeoutSec, int $callIndex) use ($cfg, $fixture, $instanceController, $expectedRuntimeConfigSha): string {
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

                if ($to === strtolower($instanceController) && str_starts_with($data, '0x940992a3')) {
                    // attestations(bytes32)
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => $expectedRuntimeConfigSha], JSON_THROW_ON_ERROR);
                }

                if ($to === strtolower($instanceController) && str_starts_with($data, '0xa93a4e86')) {
                    // attestationLocked(bytes32)
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::boolResult(true)], JSON_THROW_ON_ERROR);
                }
            }

            throw new \RuntimeException('unexpected request');
        });

        TrustKernelBootstrap::setDefaultTransport($transport);
        Config::_setRepo(new ArrayRuntimeConfigRepository($runtimeConfig, $runtimeConfigPath));

        self::assertFalse(KeyManager::hasAccessGuard());
        self::assertFalse(KeyManager::isAccessGuardLocked());

        $keys = KeyManager::getAllRawKeys('APP_SALT', $keysDir, 'app_salt', 32);
        self::assertCount(1, $keys);
        self::assertSame(str_repeat('a', 32), $keys[0]);

        self::assertTrue(KeyManager::hasAccessGuard());
        self::assertTrue(KeyManager::isAccessGuardLocked());

        // Raw PDO access is a bypass and must be denied even when trusted.
        $pdo = new \PDO('sqlite::memory:');
        Database::initFromPdo($pdo);

        $this->expectException(TrustKernelException::class);
        Database::getInstance()->getPdo();
    }

    public function testAutoBootFailsClosedOnInvalidRuntimeConfig(): void
    {
        Config::_setRepo(new ArrayRuntimeConfigRepository([
            'trust' => [
                // Wrong type: should be an object/array.
                'web3' => 'invalid',
            ],
        ]));

        $this->expectException(KeyManagerException::class);
        $this->expectExceptionMessage('TrustKernel auto-boot failed');
        KeyManager::assertAccessAllowed('read');
    }

    public function testAutoBootFailsClosedWhenRuntimeConfigIsMissing(): void
    {
        Config::_clearRepo();

        $this->expectException(KeyManagerException::class);
        $this->expectExceptionMessage('TrustKernel auto-boot failed');
        KeyManager::assertAccessAllowed('read');
    }

    public function testAutoBootFailsClosedWhenTrustIsNotConfigured(): void
    {
        Config::_setRepo(new ArrayRuntimeConfigRepository([
            // trust.web3 missing → TrustKernel is not configured
            'trust' => [
                'integrity' => [
                    'root_dir' => '/srv/blackcat',
                    'manifest' => '/etc/blackcat/integrity.manifest.json',
                ],
            ],
        ]));

        $this->expectException(KeyManagerException::class);
        $this->expectExceptionMessage('TrustKernel auto-boot failed');
        KeyManager::assertAccessAllowed('read');
    }

    private static function writePrivateStatic(string $class, string $property, mixed $value): void
    {
        $ref = new \ReflectionProperty($class, $property);
        $ref->setAccessible(true);
        $ref->setValue(null, $value);
    }
}

}
