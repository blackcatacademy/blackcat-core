<?php

declare(strict_types=1);

namespace BlackCat\Core\Tests\TrustKernel\AttackFlows\Support;

use BlackCat\Core\TrustKernel\Web3TransportInterface;

final class ScenarioTransport implements Web3TransportInterface
{
    /** @var list<array{url:string,req:array<string,mixed>,timeout:int}> */
    public array $calls = [];

    /**
     * @param \Closure(string,array<string,mixed>,int,int):string $handler (url, req, timeout, callIndex)
     */
    public function __construct(
        private readonly \Closure $handler,
    ) {
    }

    public function postJson(string $url, string $jsonBody, int $timeoutSec): string
    {
        /** @var mixed $decoded */
        $decoded = json_decode($jsonBody, true);
        if (!is_array($decoded)) {
            throw new \RuntimeException('ScenarioTransport: invalid request JSON.');
        }

        /** @var array<string,mixed> $req */
        $req = $decoded;
        $this->calls[] = [
            'url' => $url,
            'req' => $req,
            'timeout' => $timeoutSec,
        ];

        $callIndex = count($this->calls);
        return ($this->handler)($url, $req, $timeoutSec, $callIndex);
    }
}

