<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel;

use BlackCat\Core\TrustKernel\ReleaseRegistryReader;
use BlackCat\Core\TrustKernel\Web3RpcQuorumClient;
use BlackCat\Core\TrustKernel\Web3TransportInterface;
use PHPUnit\Framework\TestCase;

final class ReleaseRegistryReaderTest extends TestCase
{
    public function testIsTrustedRootTrue(): void
    {
        $expectedDataPrefix = '0x3cb692b8' . str_repeat('aa', 32);
        $transport = new class($expectedDataPrefix) implements Web3TransportInterface {
            public function __construct(private readonly string $expectedDataPrefix) {}

            public function postJson(string $url, string $jsonBody, int $timeoutSec): string
            {
                $req = json_decode($jsonBody, true);
                $method = is_array($req) ? ($req['method'] ?? null) : null;

                if ($method === 'eth_chainId') {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => '0x106f'], JSON_THROW_ON_ERROR);
                }

                if ($method === 'eth_call') {
                    $params = is_array($req) ? ($req['params'] ?? null) : null;
                    $data = is_array($params) && isset($params[0]['data']) ? (string) $params[0]['data'] : '';
                    if (!str_starts_with(strtolower($data), strtolower($this->expectedDataPrefix))) {
                        throw new \RuntimeException('unexpected data: ' . $data);
                    }
                    return json_encode(
                        ['jsonrpc' => '2.0', 'id' => 1, 'result' => '0x' . str_repeat('0', 63) . '1'],
                        JSON_THROW_ON_ERROR
                    );
                }

                throw new \RuntimeException('unexpected method');
            }
        };

        $rpc = new Web3RpcQuorumClient(['https://a'], 4207, 1, $transport, 5);
        $reader = new ReleaseRegistryReader($rpc);

        self::assertTrue(
            $reader->isTrustedRoot(
                '0x1111111111111111111111111111111111111111',
                '0x' . str_repeat('aa', 32),
            )
        );
    }

    public function testIsTrustedRootFalse(): void
    {
        $transport = new class implements Web3TransportInterface {
            public function postJson(string $url, string $jsonBody, int $timeoutSec): string
            {
                $req = json_decode($jsonBody, true);
                $method = is_array($req) ? ($req['method'] ?? null) : null;

                if ($method === 'eth_chainId') {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => '0x106f'], JSON_THROW_ON_ERROR);
                }

                if ($method === 'eth_call') {
                    return json_encode(
                        ['jsonrpc' => '2.0', 'id' => 1, 'result' => '0x' . str_repeat('0', 64)],
                        JSON_THROW_ON_ERROR
                    );
                }

                throw new \RuntimeException('unexpected method');
            }
        };

        $rpc = new Web3RpcQuorumClient(['https://a'], 4207, 1, $transport, 5);
        $reader = new ReleaseRegistryReader($rpc);

        self::assertFalse(
            $reader->isTrustedRoot(
                '0x1111111111111111111111111111111111111111',
                '0x' . str_repeat('aa', 32),
            )
        );
    }
}

