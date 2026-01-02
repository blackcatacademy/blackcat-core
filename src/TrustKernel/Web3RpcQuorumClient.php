<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class Web3RpcQuorumClient
{
    /** @var list<string> */
    private array $endpoints;

    /** @var array<string,int> */
    private array $chainIdCache = [];

    /** @var array<string,array{at:int,value:string}> */
    private array $resultCache = [];

    private Web3TransportInterface $transport;

    public function __construct(
        array $endpoints,
        private readonly int $expectedChainId,
        private readonly int $quorum,
        ?Web3TransportInterface $transport = null,
        private readonly int $timeoutSec = 5,
        private readonly int $cacheTtlSec = 0,
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
        $baseTransport = $transport ?? new DefaultWeb3Transport();
        $this->transport = AllowlistedWeb3Transport::fromRpcEndpoints($baseTransport, $this->endpoints);

        if ($this->cacheTtlSec < 0 || $this->cacheTtlSec > 60) {
            throw new \InvalidArgumentException('Invalid cacheTtlSec (expected 0..60).');
        }
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

    /**
     * Batch eth_call with per-call quorum (reduces HTTP round-trips).
     *
     * @param list<array{to:string,data:string,block_tag?:string}> $calls
     * @return list<string> Normalized lowercase "0x..." results (same order as input).
     */
    public function ethCallBatchQuorum(array $calls, string $defaultBlockTag = 'latest'): array
    {
        if ($calls === []) {
            throw new \InvalidArgumentException('ethCallBatchQuorum requires at least one call.');
        }

        $defaultBlockTag = trim($defaultBlockTag);
        if ($defaultBlockTag === '' || str_contains($defaultBlockTag, "\0")) {
            throw new \InvalidArgumentException('Invalid default blockTag.');
        }

        $normalizedCalls = [];
        foreach ($calls as $i => $call) {
            if (!is_array($call)) {
                throw new \InvalidArgumentException('Invalid batch call at index ' . $i . ' (expected array).');
            }

            $toRaw = $call['to'] ?? null;
            $dataRaw = $call['data'] ?? null;
            $blockTagRaw = $call['block_tag'] ?? $defaultBlockTag;

            if (!is_string($toRaw) || !is_string($dataRaw) || !is_string($blockTagRaw)) {
                throw new \InvalidArgumentException('Invalid batch call types at index ' . $i . '.');
            }

            $to = self::normalizeEvmAddress($toRaw);
            $data = trim($dataRaw);
            if ($data === '' || !str_starts_with($data, '0x') || str_contains($data, "\0")) {
                throw new \InvalidArgumentException('Invalid eth_call data at index ' . $i . '.');
            }

            $blockTag = trim($blockTagRaw);
            if ($blockTag === '' || str_contains($blockTag, "\0")) {
                throw new \InvalidArgumentException('Invalid blockTag at index ' . $i . '.');
            }

            $normalizedCalls[] = [
                'to' => $to,
                'data' => strtolower($data),
                'block_tag' => $blockTag,
            ];
        }

        $errors = [];
        /** @var list<array{endpoint:string,results:list<string>}> $endpointResults */
        $endpointResults = [];
        $callCount = count($normalizedCalls);

        foreach ($this->endpoints as $endpoint) {
            try {
                /** @var array<int,string|null> $results */
                $results = array_fill(0, $callCount, null);

                $maxBatchSize = self::maxJsonRpcBatchSize($endpoint);
                if ($maxBatchSize < 2) {
                    $maxBatchSize = 2;
                }

                /** @var list<array{offset:int,include_chain_id:bool,calls:list<array{to:string,data:string,block_tag:string}>}> $chunks */
                $chunks = [];
                $offset = 0;
                $first = true;
                while ($offset < $callCount) {
                    $maxEthCalls = $first ? ($maxBatchSize - 1) : $maxBatchSize;

                    /** @var list<array{to:string,data:string,block_tag:string}> $slice */
                    $slice = array_slice($normalizedCalls, $offset, $maxEthCalls);
                    if ($slice === []) {
                        break;
                    }

                    $chunks[] = [
                        'offset' => $offset,
                        'include_chain_id' => $first,
                        'calls' => $slice,
                    ];
                    $offset += count($slice);
                    $first = false;
                }

                foreach ($chunks as $chunk) {
                    $batch = [];

                    if ($chunk['include_chain_id']) {
                        $batch[] = [
                            'jsonrpc' => '2.0',
                            'id' => 1,
                            'method' => 'eth_chainId',
                            'params' => [],
                        ];
                    }

                    foreach ($chunk['calls'] as $i => $call) {
                        $globalIndex = $chunk['offset'] + $i;
                        $id = 2 + $globalIndex;
                        $batch[] = [
                            'jsonrpc' => '2.0',
                            'id' => $id,
                            'method' => 'eth_call',
                            'params' => [
                                [
                                    'to' => $call['to'],
                                    'data' => $call['data'],
                                ],
                                $call['block_tag'],
                            ],
                        ];
                    }

                    $json = json_encode($batch, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

                    $raw = $this->transport->postJson($endpoint, $json, $this->timeoutSec);
                    $decoded = json_decode($raw, true);
                    if (!is_array($decoded)) {
                        throw new \RuntimeException('Invalid JSON-RPC batch response.');
                    }

                    // Some servers may return an object for a 1-element batch; normalize to list.
                    if (isset($decoded['jsonrpc']) && isset($decoded['id'])) {
                        $decoded = [$decoded];
                    }

                    /** @var array<int,array<string,mixed>> $decoded */
                    $byId = [];
                    foreach ($decoded as $item) {
                        if (!is_array($item)) {
                            continue;
                        }
                        $idRaw = $item['id'] ?? null;
                        if (is_int($idRaw)) {
                            $id = $idRaw;
                        } elseif (is_string($idRaw) && ctype_digit($idRaw)) {
                            $id = (int) $idRaw;
                        } else {
                            continue;
                        }
                        $byId[$id] = $item;
                    }

                    if ($chunk['include_chain_id']) {
                        $chainItem = $byId[1] ?? null;
                        if (!is_array($chainItem)) {
                            throw new \RuntimeException('Missing eth_chainId in batch response.');
                        }
                        if (array_key_exists('error', $chainItem)) {
                            throw new \RuntimeException('eth_chainId failed.');
                        }
                        $chainHex = $chainItem['result'] ?? null;
                        if (!is_string($chainHex) || $chainHex === '' || !str_starts_with($chainHex, '0x')) {
                            throw new \RuntimeException('Invalid eth_chainId result.');
                        }
                        $chainId = (int) hexdec(substr($chainHex, 2));
                        if ($chainId <= 0) {
                            throw new \RuntimeException('Invalid eth_chainId value.');
                        }
                        if ($chainId !== $this->expectedChainId) {
                            $errors[] = $endpoint . ': unexpected chain_id ' . $chainId;
                            continue 2;
                        }

                        // Prime chainId cache so subsequent per-request calls don't re-fetch it.
                        $this->chainIdCache[$endpoint] = $chainId;
                    }

                    foreach ($chunk['calls'] as $i => $_call) {
                        $globalIndex = $chunk['offset'] + $i;
                        $id = 2 + $globalIndex;
                        $item = $byId[$id] ?? null;
                        if (!is_array($item)) {
                            throw new \RuntimeException('Missing batch item id=' . $id . '.');
                        }
                        if (array_key_exists('error', $item)) {
                            $err = $item['error'];
                            $msg = is_array($err) && isset($err['message']) && is_string($err['message'])
                                ? $err['message']
                                : 'unknown error';
                            throw new \RuntimeException('RPC error (id=' . $id . '): ' . $msg);
                        }

                        $resultRaw = $item['result'] ?? null;
                        if (!is_string($resultRaw) || $resultRaw === '' || !str_starts_with($resultRaw, '0x')) {
                            throw new \RuntimeException('Invalid eth_call result (id=' . $id . ').');
                        }

                        $results[$globalIndex] = strtolower($resultRaw);
                    }
                }

                $final = [];
                for ($i = 0; $i < $callCount; $i++) {
                    $val = $results[$i] ?? null;
                    if (!is_string($val) || $val === '') {
                        throw new \RuntimeException('Missing batch result index=' . $i . '.');
                    }
                    $final[] = $val;
                }

                $endpointResults[] = [
                    'endpoint' => $endpoint,
                    'results' => $final,
                ];
            } catch (\Throwable $e) {
                // Compatibility: not all RPC gateways (or test transports) support JSON-RPC batch payloads.
                // Fall back to sequential eth_call requests on this endpoint.
                try {
                    $final = $this->ethCallSequentialOnEndpoint($endpoint, $normalizedCalls);
                    $endpointResults[] = [
                        'endpoint' => $endpoint,
                        'results' => $final,
                    ];
                    continue;
                } catch (\Throwable $e2) {
                    $errors[] = $endpoint . ': batch failed: ' . $e->getMessage() . '; fallback failed: ' . $e2->getMessage();
                    continue;
                }
            }
        }

        if (count($endpointResults) < $this->quorum) {
            throw new \RuntimeException('RPC quorum not met (eligible endpoints < quorum). ' . implode(' | ', $errors));
        }

        $out = [];
        for ($i = 0; $i < $callCount; $i++) {
            /** @var array<string,int> $counts */
            $counts = [];
            /** @var array<string,string> $firstEndpointByResult */
            $firstEndpointByResult = [];

            foreach ($endpointResults as $er) {
                $endpoint = $er['endpoint'];
                $results = $er['results'];
                $val = $results[$i] ?? null;
                if (!is_string($val)) {
                    $errors[] = $endpoint . ': missing batch result index=' . $i;
                    continue;
                }

                $counts[$val] = ($counts[$val] ?? 0) + 1;
                $firstEndpointByResult[$val] ??= $endpoint;
            }

            foreach ($counts as $val => $count) {
                if ($count >= $this->quorum) {
                    $out[] = $val;
                    continue 2;
                }
            }

            // Best-effort: report the most common disagreeing value.
            arsort($counts);
            $top = array_key_first($counts);
            if (is_string($top)) {
                $agree = $counts[$top] ?? 0;
                $ep = $firstEndpointByResult[$top] ?? '?';
                throw new \RuntimeException(
                    'RPC quorum not met for batch item index=' . $i . ' (best=' . $agree . ' via ' . $ep . '). ' . implode(' | ', $errors)
                );
            }

            throw new \RuntimeException('RPC quorum not met for batch item index=' . $i . '. ' . implode(' | ', $errors));
        }

        return $out;
    }

    /**
     * Sequential fallback for JSON-RPC batch-incompatible endpoints.
     *
     * @param list<array{to:string,data:string,block_tag:string}> $calls
     * @return list<string>
     */
    private function ethCallSequentialOnEndpoint(string $endpoint, array $calls): array
    {
        $chainId = $this->chainIdForEndpoint($endpoint);
        if ($chainId !== $this->expectedChainId) {
            throw new \RuntimeException('unexpected chain_id ' . $chainId);
        }

        $out = [];
        foreach ($calls as $i => $call) {
            $payload = [
                'jsonrpc' => '2.0',
                'id' => $i + 1,
                'method' => 'eth_call',
                'params' => [
                    [
                        'to' => $call['to'],
                        'data' => $call['data'],
                    ],
                    $call['block_tag'],
                ],
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
            if (!is_string($resultRaw) || $resultRaw === '' || !str_starts_with($resultRaw, '0x')) {
                throw new \RuntimeException('Invalid eth_call result type/value.');
            }

            $out[] = strtolower($resultRaw);
        }

        return $out;
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

    public function ethGetBalanceQuorum(string $address, string $blockTag = 'latest'): string
    {
        $address = self::normalizeEvmAddress($address);

        $params = [
            $address,
            $blockTag,
        ];

        /** @var string $result */
        $result = $this->callQuorum('eth_getBalance', $params, static function (mixed $result): string {
            if (!is_string($result) || $result === '' || !str_starts_with($result, '0x') || str_contains($result, "\0")) {
                throw new \RuntimeException('Invalid eth_getBalance result type/value.');
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
        $cacheKey = null;
        if ($this->cacheTtlSec > 0) {
            $cacheKey = hash('sha256', $method . "\0" . json_encode($params));
            $cached = $this->resultCache[$cacheKey] ?? null;
            if (is_array($cached) && isset($cached['at'], $cached['value']) && is_int($cached['at']) && is_string($cached['value'])) {
                if ((time() - $cached['at']) <= $this->cacheTtlSec) {
                    return $cached['value'];
                }
                unset($this->resultCache[$cacheKey]);
            }
        }

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
                    if ($cacheKey !== null) {
                        $this->resultCache[$cacheKey] = [
                            'at' => time(),
                            'value' => $result,
                        ];
                    }
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

    /**
     * Some public RPC gateways enforce strict JSON-RPC batch element limits.
     *
     * Example: edgenscan.io currently enforces max batch size 5.
     */
    private static function maxJsonRpcBatchSize(string $endpointUrl): int
    {
        $parts = parse_url($endpointUrl);
        $host = is_array($parts) ? ($parts['host'] ?? null) : null;
        $host = is_string($host) ? strtolower(trim($host)) : '';

        if ($host === 'edgenscan.io') {
            return 5;
        }

        return 1000;
    }
}
