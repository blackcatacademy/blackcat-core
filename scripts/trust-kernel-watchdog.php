#!/usr/bin/env php
<?php

declare(strict_types=1);

$autoload = __DIR__ . '/../vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
}

use BlackCat\Core\Kernel\KernelBootstrap;
use BlackCat\Core\TrustKernel\TrustKernelStatus;

/**
 * Local Trust Watchdog (minimal reference implementation).
 *
 * It:
 * - boots the Trust Kernel from `blackcat-config` runtime config,
 * - polls trust state periodically,
 * - prints JSON-lines events,
 * - optionally writes "recommended action" events into an outbox directory.
 *
 * This script is intended as a kernel-only building block. The recommended long-term home
 * for a full Watchdog (daemon + remote sentinel) is a separate optional repo.
 */

$options = getopt('', [
    'interval:',
    'once',
    'pretty',
    'exit-on-untrusted',
    'outbox-dir:',
    'tag:',
    'help',
]);
if ($options === false || isset($options['help'])) {
    fwrite(STDERR, "Usage:\n");
    fwrite(STDERR, "  trust-kernel-watchdog.php [--interval=5] [--once] [--exit-on-untrusted] [--outbox-dir=/path] [--tag=name]\n");
    exit(0);
}

$interval = (int)($options['interval'] ?? 5);
if ($interval < 1 || $interval > 3600) {
    fwrite(STDERR, "Invalid --interval (expected 1..3600)\n");
    exit(1);
}

$pretty = isset($options['pretty']);
$exitOnUntrusted = isset($options['exit-on-untrusted']);
$once = isset($options['once']);

$tag = $options['tag'] ?? null;
if ($tag !== null) {
    if (!is_string($tag)) {
        fwrite(STDERR, "Invalid --tag\n");
        exit(1);
    }
    $tag = trim($tag);
    if ($tag === '' || str_contains($tag, "\0")) {
        fwrite(STDERR, "Invalid --tag value\n");
        exit(1);
    }
}

$outboxDir = $options['outbox-dir'] ?? null;
if ($outboxDir !== null) {
    if (!is_string($outboxDir)) {
        fwrite(STDERR, "Invalid --outbox-dir\n");
        exit(1);
    }
    $outboxDir = rtrim(trim($outboxDir), "/\\");
    if ($outboxDir === '' || str_contains($outboxDir, "\0")) {
        fwrite(STDERR, "Invalid --outbox-dir value\n");
        exit(1);
    }
    if (!is_dir($outboxDir)) {
        fwrite(STDERR, "Outbox dir does not exist: {$outboxDir}\n");
        exit(1);
    }
    if (is_link($outboxDir)) {
        fwrite(STDERR, "Outbox dir must not be a symlink: {$outboxDir}\n");
        exit(1);
    }
    if (!is_writable($outboxDir)) {
        fwrite(STDERR, "Outbox dir is not writable: {$outboxDir}\n");
        exit(1);
    }
}

$jsonFlags = JSON_UNESCAPED_SLASHES;
if ($pretty) {
    $jsonFlags |= JSON_PRETTY_PRINT;
}

$kernel = KernelBootstrap::bootOrFail();

/**
 * @return list<array{type:string,severity:string,reason_codes:list<string>}>
 */
$recommendActions = static function (TrustKernelStatus $status): array {
    if ($status->trustedNow) {
        return [];
    }

    $codes = $status->errorCodes;

    $critical = [
        'integrity_root_mismatch',
        'integrity_missing_file',
        'integrity_symlink_file',
        'integrity_hash_mismatch',
        'integrity_unexpected_file',
        'integrity_stat_failed',
        'integrity_hash_failed',
        'integrity_check_failed',
        'uri_hash_mismatch',
        'uri_hash_missing',
        'policy_hash_mismatch',
        'runtime_config_commitment_missing',
        'runtime_config_commitment_mismatch',
        'runtime_config_commitment_unlocked',
        'controller_no_code',
        'controller_impl_no_code',
    ];

    $hits = array_values(array_intersect($codes, $critical));
    if ($hits !== []) {
        return [
            [
                'type' => 'onchain.pause',
                'severity' => 'critical',
                'reason_codes' => $hits,
            ],
            [
                'type' => 'onchain.report_incident',
                'severity' => 'critical',
                'reason_codes' => $hits,
            ],
        ];
    }

    // Default: alert-only (e.g., RPC outage, transient issues).
    return [
        [
            'type' => 'alert',
            'severity' => 'high',
            'reason_codes' => $codes,
        ],
    ];
};

$writeOutbox = static function (string $dir, array $event, ?string $tag) use ($jsonFlags): void {
    $json = json_encode($event, $jsonFlags);
    if (!is_string($json)) {
        throw new \RuntimeException('Unable to encode outbox JSON.');
    }

    $name = 'trust-watchdog.' . gmdate('Ymd\\THis\\Z') . '.' . bin2hex(random_bytes(6));
    if ($tag !== null) {
        $name .= '.' . preg_replace('~[^a-zA-Z0-9_.-]+~', '_', $tag);
    }
    $path = $dir . DIRECTORY_SEPARATOR . $name . '.json';

    $fp = @fopen($path, 'xb');
    if ($fp === false) {
        throw new \RuntimeException('Unable to create outbox file: ' . $path);
    }

    try {
        $bytes = fwrite($fp, $json . "\n");
        if ($bytes === false) {
            throw new \RuntimeException('Unable to write outbox file: ' . $path);
        }
    } finally {
        fclose($fp);
    }
};

while (true) {
    $status = $kernel->check();
    $actions = $recommendActions($status);

    $event = [
        'event' => 'trust_watchdog_tick',
        'ts' => time(),
        'status' => $status,
        'recommended_actions' => $actions,
    ];

    $line = json_encode($event, $jsonFlags);
    if (!is_string($line)) {
        throw new \RuntimeException('Unable to encode status JSON.');
    }
    echo $line . PHP_EOL;

    if ($outboxDir !== null && !$status->trustedNow && $actions !== []) {
        $writeOutbox($outboxDir, [
            'event' => 'trust_watchdog_action',
            'ts' => time(),
            'status' => $status,
            'recommended_actions' => $actions,
        ], $tag);
    }

    if ($once) {
        exit($status->trustedNow ? 0 : 2);
    }

    if ($exitOnUntrusted && !$status->trustedNow) {
        exit(2);
    }

    sleep($interval);
}
