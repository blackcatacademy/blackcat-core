<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use BlackCat\Core\TrustKernel\InstanceControllerReader;
use BlackCat\Core\TrustKernel\Web3RpcQuorumClient;

/**
 * Live RPC smoke test for the Trust Kernel contracts.
 *
 * This is intentionally a standalone script (NOT a PHPUnit test):
 * - it talks to a real chain,
 * - it is meant to be run manually before/after deployments.
 *
 * Example (Edgen, Chain ID 4207):
 *   docker run --rm -u 1000:1000 -v "$PWD":/app -w /app/blackcat-core composer:2.7 \
 *     php scripts/trust-kernel-rpc-smoke.php \
 *       --rpc https://rpc.layeredge.io \
 *       --chain-id 4207 \
 *       --quorum 1 \
 *       --controller 0x...
 */

/**
 * @return never
 */
function usage(string $error = ''): void
{
    if ($error !== '') {
        fwrite(STDERR, $error . PHP_EOL . PHP_EOL);
    }

    $msg = <<<TXT
Usage:
  php scripts/trust-kernel-rpc-smoke.php --rpc <url[,url2...]> --chain-id <id> --controller <0x...> [--quorum <n>] [--timeout <sec>]

Options:
  --rpc         Comma-separated RPC endpoint list (https://...).
  --chain-id    Expected chain id (decimal).
  --controller  InstanceController address (clone or implementation).
  --quorum      Quorum count (default: 1).
  --timeout     RPC timeout seconds (default: 5).
TXT;

    fwrite(STDERR, $msg . PHP_EOL);
    exit(2);
}

/** @var array<string,string|false> $opts */
$opts = getopt('', [
    'rpc:',
    'chain-id:',
    'controller:',
    'quorum:',
    'timeout:',
]);

$rpcRaw = $opts['rpc'] ?? null;
$chainIdRaw = $opts['chain-id'] ?? null;
$controller = $opts['controller'] ?? null;

if (!is_string($rpcRaw) || trim($rpcRaw) === '') {
    usage('Missing --rpc');
}
if (!is_string($chainIdRaw) || trim($chainIdRaw) === '' || !ctype_digit(trim($chainIdRaw))) {
    usage('Missing/invalid --chain-id');
}
if (!is_string($controller) || trim($controller) === '') {
    usage('Missing --controller');
}

$endpoints = array_values(array_filter(array_map('trim', explode(',', $rpcRaw)), static fn (string $v): bool => $v !== ''));
$chainId = (int) trim($chainIdRaw);
$quorum = isset($opts['quorum']) && is_string($opts['quorum']) && ctype_digit(trim($opts['quorum']))
    ? (int) trim($opts['quorum'])
    : 1;
$timeout = isset($opts['timeout']) && is_string($opts['timeout']) && ctype_digit(trim($opts['timeout']))
    ? (int) trim($opts['timeout'])
    : 5;

if ($chainId <= 0) {
    usage('Invalid --chain-id (expected > 0).');
}
if ($quorum <= 0) {
    usage('Invalid --quorum (expected > 0).');
}
if ($timeout < 1 || $timeout > 60) {
    usage('Invalid --timeout (expected 1..60).');
}

$rpc = new Web3RpcQuorumClient(
    endpoints: $endpoints,
    expectedChainId: $chainId,
    quorum: $quorum,
    transport: null,
    timeoutSec: $timeout,
);

$code = $rpc->ethGetCodeQuorum($controller, 'latest');
$reader = new InstanceControllerReader($rpc);
$snapshot = $reader->snapshot($controller);
$releaseRegistry = $reader->releaseRegistry($controller);

$out = [
    'chain_id' => $chainId,
    'rpc_endpoints' => $endpoints,
    'rpc_quorum' => $quorum,
    'timeout_sec' => $timeout,
    'instance_controller' => strtolower(trim($controller)),
    'eth_getCode' => [
        'len_bytes' => (int) ((strlen($code) > 2 ? (strlen($code) - 2) : 0) / 2),
        'is_empty' => $code === '0x' || $code === '0x0',
    ],
    'snapshot' => [
        'version' => $snapshot->version,
        'paused' => $snapshot->paused,
        'activeRoot' => $snapshot->activeRoot,
        'activeUriHash' => $snapshot->activeUriHash,
        'activePolicyHash' => $snapshot->activePolicyHash,
        'pendingRoot' => $snapshot->pendingRoot,
        'pendingUriHash' => $snapshot->pendingUriHash,
        'pendingPolicyHash' => $snapshot->pendingPolicyHash,
        'pendingCreatedAt' => $snapshot->pendingCreatedAt,
        'pendingTtlSec' => $snapshot->pendingTtlSec,
        'genesisAt' => $snapshot->genesisAt,
        'lastUpgradeAt' => $snapshot->lastUpgradeAt,
    ],
    'release_registry' => $releaseRegistry,
];

echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
