<?php

declare(strict_types=1);

namespace BlackCat\Config\Runtime {
    final class Config
    {
        private static ?object $repo = null;

        public static function initFromFirstAvailableJsonFileIfNeeded(): void
        {
            // no-op for tests
        }

        public static function repo(): object
        {
            if (self::$repo === null) {
                throw new \RuntimeException('Config is not initialized.');
            }
            return self::$repo;
        }

        public static function _setRepo(object $repo): void
        {
            self::$repo = $repo;
        }
    }
}

namespace BlackCat\Core\Tests\TrustKernel\AttackFlows {

    use BlackCat\Config\Runtime\Config;
    use BlackCat\Core\Database;
    use BlackCat\Core\Security\KeyManager;
    use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\IntegrityFixture;
    use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\ScenarioTransport;
    use BlackCat\Core\TrustKernel\TrustKernel;
    use BlackCat\Core\TrustKernel\TrustKernelBootstrap;
    use PHPUnit\Framework\TestCase;

    final class BootstrapAttackFlowsTest extends TestCase
    {
        protected function tearDown(): void
        {
            self::writePrivateStatic(KeyManager::class, 'accessGuardLocked', false);
            self::writePrivateStatic(KeyManager::class, 'accessGuard', null);

            self::writePrivateStatic(Database::class, 'writeGuardLocked', false);
            self::writePrivateStatic(Database::class, 'writeGuard', null);
            self::writePrivateStatic(Database::class, 'pdoAccessGuardLocked', false);
            self::writePrivateStatic(Database::class, 'pdoAccessGuard', null);
        }

        public function testBootIfConfiguredReturnsNullWhenTrustIsNotConfigured(): void
        {
            Config::_setRepo(new FakeRepo([]));

            $kernel = TrustKernelBootstrap::bootIfConfiguredFromBlackCatConfig();
            self::assertNull($kernel);
        }

        public function testBootFromBlackCatConfigOrFailThrowsWhenTrustIsNotConfigured(): void
        {
            Config::_setRepo(new FakeRepo([]));

            $this->expectException(\RuntimeException::class);
            TrustKernelBootstrap::bootFromBlackCatConfigOrFail();
        }

        public function testBootIfConfiguredThrowsOnInvalidTrustConfig(): void
        {
            Config::_setRepo(new FakeRepo([
                'trust.web3' => 'bad',
            ]));

            $this->expectException(\RuntimeException::class);
            TrustKernelBootstrap::bootIfConfiguredFromBlackCatConfig();
        }

        public function testBootFromBlackCatConfigOrFailBootsWithoutRpcCalls(): void
        {
            $fixture = IntegrityFixture::create(['app.txt' => 'ok']);

            $repo = new FakeRepo([
                'trust.web3' => [],
                'trust.web3.chain_id' => 4207,
                'trust.web3.rpc_endpoints' => ['https://a'],
                'trust.web3.rpc_quorum' => 1,
                'trust.web3.max_stale_sec' => 3,
                'trust.web3.mode' => 'root_uri',
                'trust.web3.timeout_sec' => 5,
                'trust.web3.contracts.instance_controller' => '0x1111111111111111111111111111111111111111',
                'trust.integrity.root_dir' => $fixture->rootDir,
                'trust.integrity.manifest' => $fixture->manifestPath,
            ]);
            Config::_setRepo($repo);

            $transport = new ScenarioTransport(static function (string $url, array $req, int $timeout, int $callIndex): string {
                throw new \RuntimeException('RPC should not be called during boot.');
            });

            try {
                $kernel = TrustKernelBootstrap::bootFromBlackCatConfigOrFail(null, $transport);
                self::assertInstanceOf(TrustKernel::class, $kernel);
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

    final class FakeRepo
    {
        /**
         * @param array<string,mixed> $data
         */
        public function __construct(
            private readonly array $data,
        ) {
        }

        public function get(string $key, mixed $default = null): mixed
        {
            return $this->data[$key] ?? $default;
        }

        public function requireString(string $key): string
        {
            $v = $this->get($key);
            if (!is_string($v) || trim($v) === '') {
                throw new \RuntimeException('Missing required string: ' . $key);
            }
            return $v;
        }

        public function requireInt(string $key): int
        {
            $v = $this->get($key);
            if (is_int($v)) {
                return $v;
            }
            if (is_string($v) && ctype_digit(trim($v))) {
                return (int) trim($v);
            }
            throw new \RuntimeException('Missing required int: ' . $key);
        }

        public function resolvePath(string $path): string
        {
            return $path;
        }

        public function sourcePath(): string
        {
            return '/etc/blackcat/config.json';
        }
    }
}
