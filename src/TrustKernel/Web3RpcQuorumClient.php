<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class Web3RpcQuorumClient
{
    /** @var list<string> */
    private array $endpoints;

    /** @var array<string,int> */
    private array $chainIdCache = [];

    private Web3TransportInterface $transport;

    public function __construct(
        array $endpoints,
        private readonly int $expectedChainId,
        private readonly int $quorum,
        ?Web3TransportInterface $transport = null,
        private readonly int $timeoutSec = 5,
    ) {
        $normalized = [];
        foreach ($endpoints as $endpoint) {
            if (!is_string($endpoint)) {
                throw new \InvalidArgumentException('RPC endpoints must be strings.');
            }
            $endpoint = trim($endpoint);
            if ($endpoint === '' || str_contains($endpoint, "\0")) {
                throw new \InvalidArgumentException('RPC endpoint is invalid.');
            }
            $normalized[] = $endpoint;
        }
        $normalized = array_values(array_unique($normalized));
        if ($normalized === []) {
            throw new \InvalidArgumentException('At least one RPC endpoint is required.');
        }

        if ($expectedChainId <= 0) {
            throw new \InvalidArgumentException('Invalid expectedChainId.');
        }

        $max = count($normalized);
        if ($quorum < 1 || $quorum > $max) {
            throw new \InvalidArgumentException('Invalid quorum (expected 1..' . $max . ').');
        }

        $this->endpoints = $normalized;
        $this->transport = $transport ?? new DefaultWeb3Transport();
    }

    public function ethCallQuorum(string $to, string $data, string $blockTag = 'latest'): string
    {
        $to = self::normalizeEvmAddress($to);
        $data = trim($data);
        if ($data === '' || !str_starts_with($data, '0x') || str_contains($data, "\0")) {
            throw new \InvalidArgumentException('Invalid eth_call data.');
        }

        $params = [
            [
                'to' => $to,
                'data' => strtolower($data),
            ],
            $blockTag,
        ];

        /** @var string $result */
        $result = $this->callQuorum('eth_call', $params, static function (mixed $result): string {
            if (!is_string($result) || $result === '' || !str_starts_with($result, '0x')) {
                throw new \RuntimeException('Invalid eth_call result type/value.');
            }
            return strtolower($result);
        });

        return $result;
    }

    public function ethGetCodeQuorum(string $address, string $blockTag = 'latest'): string
    {
        $address = self::normalizeEvmAddress($address);

        $params = [
            $address,
            $blockTag,
        ];

        /** @var string $result */
        $result = $this->callQuorum('eth_getCode', $params, static function (mixed $result): string {
            if (!is_string($result) || !str_starts_with($result, '0x')) {
                throw new \RuntimeException('Invalid eth_getCode result type/value.');
            }
            return strtolower($result);
        });

        return $result;
    }

    /**
     * @param array<int,mixed> $params
     * @param callable(mixed):string $normalize
     */
    private function callQuorum(string $method, array $params, callable $normalize): string
    {
        $eligible = [];
        $errors = [];

        foreach ($this->endpoints as $endpoint) {
            try {
                $chainId = $this->chainIdForEndpoint($endpoint);
                if ($chainId !== $this->expectedChainId) {
                    $errors[] = $endpoint . ': unexpected chain_id ' . $chainId;
                    continue;
                }
                $eligible[] = $endpoint;
            } catch (\Throwable $e) {
                $errors[] = $endpoint . ': chain_id error: ' . $e->getMessage();
                continue;
            }
        }

        if (count($eligible) < $this->quorum) {
            throw new \RuntimeException('RPC quorum not met (eligible endpoints < quorum). ' . implode(' | ', $errors));
        }

        /** @var array<string,int> $counts */
        $counts = [];
        /** @var array<string,string> $firstEndpointByResult */
        $firstEndpointByResult = [];

        foreach ($eligible as $endpoint) {
            try {
                $payload = [
                    'jsonrpc' => '2.0',
                    'id' => 1,
                    'method' => $method,
                    'params' => $params,
                ];
                $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

                $raw = $this->transport->postJson($endpoint, $json, $this->timeoutSec);
                $decoded = json_decode($raw, true);
                if (!is_array($decoded)) {
                    throw new \RuntimeException('Invalid JSON-RPC response (not an object).');
                }
                if (array_key_exists('error', $decoded)) {
                    $err = $decoded['error'];
                    $msg = is_array($err) && isset($err['message']) && is_string($err['message'])
                        ? $err['message']
                        : 'unknown error';
                    throw new \RuntimeException('RPC error: ' . $msg);
                }

                $resultRaw = $decoded['result'] ?? null;
                $result = $normalize($resultRaw);

                $counts[$result] = ($counts[$result] ?? 0) + 1;
                $firstEndpointByResult[$result] ??= $endpoint;

                if ($counts[$result] >= $this->quorum) {
                    return $result;
                }
            } catch (\Throwable $e) {
                $errors[] = $endpoint . ': ' . $e->getMessage();
                continue;
            }
        }

        // Best-effort: report the most common disagreeing value.
        arsort($counts);
        $top = array_key_first($counts);
        if (is_string($top)) {
            $agree = $counts[$top] ?? 0;
            $ep = $firstEndpointByResult[$top] ?? '?';
            throw new \RuntimeException(
                'RPC quorum not met (best=' . $agree . ' via ' . $ep . '). ' . implode(' | ', $errors)
            );
        }

        throw new \RuntimeException('RPC quorum not met. ' . implode(' | ', $errors));
    }

    private function chainIdForEndpoint(string $endpoint): int
    {
        if (isset($this->chainIdCache[$endpoint])) {
            return $this->chainIdCache[$endpoint];
        }

        $payload = [
            'jsonrpc' => '2.0',
            'id' => 1,
            'method' => 'eth_chainId',
            'params' => [],
        ];
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $raw = $this->transport->postJson($endpoint, $json, $this->timeoutSec);
        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            throw new \RuntimeException('Invalid chainId response (not JSON object).');
        }

        $resultRaw = $decoded['result'] ?? null;
        if (!is_string($resultRaw) || $resultRaw === '' || !str_starts_with($resultRaw, '0x')) {
            throw new \RuntimeException('Invalid chainId response result.');
        }

        $chainId = hexdec(substr($resultRaw, 2));
        if (!is_int($chainId) || $chainId <= 0) {
            throw new \RuntimeException('Invalid chainId value.');
        }

        $this->chainIdCache[$endpoint] = $chainId;
        return $chainId;
    }

    private static function normalizeEvmAddress(string $address): string
    {
        $address = trim($address);
        if ($address === '' || str_contains($address, "\0")) {
            throw new \InvalidArgumentException('Invalid EVM address.');
        }

        if (!preg_match('/^0x[a-fA-F0-9]{40}$/', $address)) {
            throw new \InvalidArgumentException('Invalid EVM address.');
        }

        $address = '0x' . strtolower(substr($address, 2));
        if ($address === '0x0000000000000000000000000000000000000000') {
            throw new \InvalidArgumentException('Invalid EVM address (zero).');
        }

        return $address;
    }
}
