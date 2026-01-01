<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel\AttackFlows;

use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\Abi;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\IntegrityFixture;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\ScenarioTransport;
use BlackCat\Core\Tests\TrustKernel\AttackFlows\Support\TestLogger;
use BlackCat\Core\TrustKernel\CanonicalJson;
use BlackCat\Core\TrustKernel\TrustKernel;
use BlackCat\Core\TrustKernel\TrustKernelConfig;
use PHPUnit\Framework\TestCase;

final class PolicyV4AttestationsAttackFlowsTest extends TestCase
{
    public function testPolicyV4StrictRejectsMismatchedComposerLockAttestation(): void
    {
        $composerLock = json_encode([
            'packages' => [
                ['name' => 'acme/demo', 'version' => '1.0.0'],
            ],
            'content-hash' => 'demo',
        ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        if (!is_string($composerLock)) {
            throw new \RuntimeException('Unable to encode composer.lock fixture.');
        }

        $fixture = IntegrityFixture::create([
            'app.txt' => 'ok',
            'composer.lock' => $composerLock,
        ]);

        $instanceController = '0x1111111111111111111111111111111111111111';

        $imageDigestPath = $fixture->rootDir . DIRECTORY_SEPARATOR . 'image.digest';
        file_put_contents($imageDigestPath, 'sha256:' . str_repeat('ab', 32) . "\n");

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

        $canonical = CanonicalJson::sha256Bytes32($runtimeConfig);

        $runtimeConfigPath = $fixture->rootDir . DIRECTORY_SEPARATOR . 'config.runtime.json';
        $json = json_encode($runtimeConfig, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        if (!is_string($json) || @file_put_contents($runtimeConfigPath, $json) === false) {
            throw new \RuntimeException('Unable to write runtime config fixture file.');
        }

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
            runtimeConfigCanonicalSha256: $canonical,
            runtimeConfigSourcePath: $runtimeConfigPath,
            imageDigestFilePath: $imageDigestPath,
        );

        $runtimeKey = strtolower($cfg->runtimeConfigAttestationKey);
        $runtimeAttestationCall = '0x940992a3' . substr($runtimeKey, 2);
        $runtimeLockedCall = '0xa93a4e86' . substr($runtimeKey, 2);

        $composerKey = strtolower($cfg->composerLockAttestationKeyV1);
        $composerAttestationCall = '0x940992a3' . substr($composerKey, 2);
        $composerLockedCall = '0xa93a4e86' . substr($composerKey, 2);

        $phpKey = strtolower($cfg->phpFingerprintAttestationKeyV2);
        $phpAttestationCall = '0x940992a3' . substr($phpKey, 2);
        $phpLockedCall = '0xa93a4e86' . substr($phpKey, 2);

        $imageKey = strtolower($cfg->imageDigestAttestationKeyV1);
        $imageAttestationCall = '0x940992a3' . substr($imageKey, 2);
        $imageLockedCall = '0xa93a4e86' . substr($imageKey, 2);

        $extensions = get_loaded_extensions();
        sort($extensions, SORT_STRING);
        $extMap = [];
        foreach ($extensions as $ext) {
            if (!is_string($ext) || $ext === '') {
                continue;
            }
            $v = phpversion($ext);
            $extMap[$ext] = is_string($v) && trim($v) !== '' ? trim($v) : null;
        }
        $expectedPhp = CanonicalJson::sha256Bytes32([
            'schema_version' => 2,
            'type' => 'blackcat.php.fingerprint',
            'php_version' => PHP_VERSION,
            'extensions' => $extMap,
        ]);

        $expectedImage = '0x' . str_repeat('ab', 32);

        $transport = new ScenarioTransport(static function (string $url, array $req, int $timeoutSec, int $callIndex) use (
            $cfg,
            $fixture,
            $instanceController,
            $runtimeAttestationCall,
            $runtimeLockedCall,
            $composerAttestationCall,
            $composerLockedCall,
            $phpAttestationCall,
            $phpLockedCall,
            $imageAttestationCall,
            $imageLockedCall,
            $canonical,
            $expectedPhp,
            $expectedImage,
        ): string {
            unset($timeoutSec, $callIndex);
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
                        activePolicyHash: $cfg->policyHashV4Strict,
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

                if ($to === strtolower($instanceController) && $data === $runtimeAttestationCall) {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => $canonical], JSON_THROW_ON_ERROR);
                }
                if ($to === strtolower($instanceController) && $data === $runtimeLockedCall) {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::boolResult(true)], JSON_THROW_ON_ERROR);
                }

                if ($to === strtolower($instanceController) && $data === $composerAttestationCall) {
                    // mismatched composer.lock value
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => '0x' . str_repeat('11', 32)], JSON_THROW_ON_ERROR);
                }
                if ($to === strtolower($instanceController) && $data === $composerLockedCall) {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::boolResult(true)], JSON_THROW_ON_ERROR);
                }

                if ($to === strtolower($instanceController) && $data === $phpAttestationCall) {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => $expectedPhp], JSON_THROW_ON_ERROR);
                }
                if ($to === strtolower($instanceController) && $data === $phpLockedCall) {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::boolResult(true)], JSON_THROW_ON_ERROR);
                }

                if ($to === strtolower($instanceController) && $data === $imageAttestationCall) {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => $expectedImage], JSON_THROW_ON_ERROR);
                }
                if ($to === strtolower($instanceController) && $data === $imageLockedCall) {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => Abi::boolResult(true)], JSON_THROW_ON_ERROR);
                }
            }

            throw new \RuntimeException('Unhandled RPC call in test.');
        });

        $logger = new TestLogger();
        $kernel = new TrustKernel($cfg, $logger, $transport);

        try {
            $status = $kernel->check();

            self::assertFalse($status->trustedNow);
            self::assertFalse($status->readAllowed);
            self::assertFalse($status->writeAllowed);
            self::assertTrue(in_array('composer_lock_commitment_mismatch', $status->errorCodes, true));
        } finally {
            $fixture->cleanup();
            @unlink($runtimeConfigPath);
            @unlink($imageDigestPath);
        }
    }
}
