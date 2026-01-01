<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

/**
 * Defense-in-depth egress guard for Web3 RPC requests.
 *
 * Only allows outgoing requests to RPC hosts derived from the configured endpoint list.
 * This prevents accidental SSRF if a URL ever becomes influenced by untrusted input.
 */
final class AllowlistedWeb3Transport implements Web3TransportInterface
{
    /** @var array<string,true> */
    private array $allowedHostsMap = [];

    /**
     * @param list<string> $allowedHosts
     */
    public function __construct(
        private readonly Web3TransportInterface $inner,
        array $allowedHosts,
    ) {
        $map = [];
        foreach ($allowedHosts as $host) {
            if (!is_string($host)) {
                continue;
            }
            $host = strtolower(trim($host));
            if ($host === '' || str_contains($host, "\0")) {
                continue;
            }
            $map[$host] = true;
        }

        if ($map === []) {
            throw new \InvalidArgumentException('RPC host allowlist is empty.');
        }

        $this->allowedHostsMap = $map;
    }

    /**
     * @param list<string> $rpcEndpoints
     */
    public static function fromRpcEndpoints(Web3TransportInterface $inner, array $rpcEndpoints): self
    {
        $hosts = [];
        foreach ($rpcEndpoints as $i => $url) {
            if (!is_string($url)) {
                throw new \InvalidArgumentException('RPC endpoint must be a string.');
            }
            $url = trim($url);
            if ($url === '' || str_contains($url, "\0")) {
                throw new \InvalidArgumentException('RPC endpoint is invalid.');
            }

            $parts = parse_url($url);
            if (!is_array($parts)) {
                throw new \InvalidArgumentException('RPC endpoint URL is invalid: #' . $i);
            }
            $host = $parts['host'] ?? null;
            if (!is_string($host) || $host === '') {
                throw new \InvalidArgumentException('RPC endpoint URL must include a host: #' . $i);
            }

            $hosts[] = strtolower($host);
        }

        return new self($inner, $hosts);
    }

    public function postJson(string $url, string $jsonBody, int $timeoutSec): string
    {
        $parts = parse_url($url);
        if (!is_array($parts)) {
            throw new \InvalidArgumentException('Invalid RPC URL.');
        }
        $host = $parts['host'] ?? null;
        if (!is_string($host) || $host === '') {
            throw new \InvalidArgumentException('RPC URL must include a host.');
        }
        $host = strtolower($host);

        if (!isset($this->allowedHostsMap[$host])) {
            throw new \InvalidArgumentException('RPC host not allowlisted: ' . $host);
        }

        return $this->inner->postJson($url, $jsonBody, $timeoutSec);
    }
}

