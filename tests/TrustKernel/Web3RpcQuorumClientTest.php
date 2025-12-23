<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel;

use BlackCat\Core\TrustKernel\Web3RpcQuorumClient;
use BlackCat\Core\TrustKernel\Web3TransportInterface;
use PHPUnit\Framework\TestCase;

final class Web3RpcQuorumClientTest extends TestCase
{
    public function testEthCallQuorumRequiresAgreement(): void
    {
        $snapshotHex = '0x' . str_repeat('00', 32 * 12);

        $transport = new class($snapshotHex) implements Web3TransportInterface {
            public function __construct(private readonly string $snapshotHex) {}

            public function postJson(string $url, string $jsonBody, int $timeoutSec): string
            {
                $req = json_decode($jsonBody, true);
                $method = is_array($req) ? ($req['method'] ?? null) : null;

                if ($method === 'eth_chainId') {
                    return json_encode([
                        'jsonrpc' => '2.0',
                        'id' => 1,
                        'result' => $url === 'https://bad' ? '0x1' : '0x106f', // 4207
                    ], JSON_THROW_ON_ERROR);
                }

                if ($method === 'eth_call') {
                    return json_encode([
                        'jsonrpc' => '2.0',
                        'id' => 1,
                        'result' => $this->snapshotHex,
                    ], JSON_THROW_ON_ERROR);
                }

                throw new \RuntimeException('unexpected method');
            }
        };

        $client = new Web3RpcQuorumClient(
            ['https://a', 'https://b', 'https://bad'],
            4207,
            2,
            $transport,
            5,
        );

        $res = $client->ethCallQuorum('0x1111111111111111111111111111111111111111', '0x9711715a');
        self::assertSame(strtolower($snapshotHex), $res);
    }
}

