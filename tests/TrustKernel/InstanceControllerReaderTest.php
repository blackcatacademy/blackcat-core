<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel;

use BlackCat\Core\TrustKernel\InstanceControllerReader;
use BlackCat\Core\TrustKernel\Web3RpcQuorumClient;
use BlackCat\Core\TrustKernel\Web3TransportInterface;
use PHPUnit\Framework\TestCase;

final class InstanceControllerReaderTest extends TestCase
{
    public function testSnapshotDecode(): void
    {
        $word = static function (string $hex): string {
            $hex = strtolower(ltrim($hex, '0x'));
            if ($hex === '') {
                $hex = '0';
            }
            if (!ctype_xdigit($hex)) {
                throw new \InvalidArgumentException('hex');
            }
            return str_pad($hex, 64, '0', STR_PAD_LEFT);
        };

        $u64 = static function (int $n): string {
            return str_repeat('0', 48) . str_pad(dechex($n), 16, '0', STR_PAD_LEFT);
        };

        $payload = implode('', [
            $word('01'), // version
            $word('00'), // paused=false
            str_repeat('aa', 32),
            str_repeat('bb', 32),
            str_repeat('cc', 32),
            str_repeat('00', 32),
            str_repeat('00', 32),
            str_repeat('00', 32),
            $u64(11),
            $u64(22),
            $u64(33),
            $u64(44),
        ]);

        $snapshotHex = '0x' . $payload;

        $transport = new class($snapshotHex) implements Web3TransportInterface {
            public function __construct(private readonly string $snapshotHex) {}

            public function postJson(string $url, string $jsonBody, int $timeoutSec): string
            {
                $req = json_decode($jsonBody, true);
                $method = is_array($req) ? ($req['method'] ?? null) : null;

                if ($method === 'eth_chainId') {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => '0x106f'], JSON_THROW_ON_ERROR);
                }

                if ($method === 'eth_call') {
                    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'result' => $this->snapshotHex], JSON_THROW_ON_ERROR);
                }

                throw new \RuntimeException('unexpected method');
            }
        };

        $rpc = new Web3RpcQuorumClient(['https://a'], 4207, 1, $transport, 5);
        $reader = new InstanceControllerReader($rpc);
        $snap = $reader->snapshot('0x1111111111111111111111111111111111111111');

        self::assertSame(1, $snap->version);
        self::assertFalse($snap->paused);
        self::assertSame('0x' . str_repeat('aa', 32), $snap->activeRoot);
        self::assertSame('0x' . str_repeat('bb', 32), $snap->activeUriHash);
        self::assertSame('0x' . str_repeat('cc', 32), $snap->activePolicyHash);
        self::assertSame(11, $snap->pendingCreatedAt);
        self::assertSame(22, $snap->pendingTtlSec);
        self::assertSame(33, $snap->genesisAt);
        self::assertSame(44, $snap->lastUpgradeAt);
    }
}
