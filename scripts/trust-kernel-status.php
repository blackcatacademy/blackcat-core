#!/usr/bin/env php
<?php

declare(strict_types=1);

$autoload = __DIR__ . '/../vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
}

use BlackCat\Core\Kernel\KernelBootstrap;

/**
 * Minimal health check for the Trust Kernel using runtime config from blackcat-config.
 *
 * Exit codes:
 * - 0: trusted
 * - 2: untrusted
 * - 1: bootstrap/runtime error
 */

$options = getopt('', ['pretty', 'allow-untrusted', 'help']);
if ($options === false || isset($options['help'])) {
    fwrite(STDERR, "Usage:\n");
    fwrite(STDERR, "  trust-kernel-status.php [--pretty] [--allow-untrusted]\n\n");
    fwrite(STDERR, "Notes:\n");
    fwrite(STDERR, "  - Requires blackcat-config runtime config + trust.web3.\n");
    fwrite(STDERR, "  - In prod, trust failures should be treated as hard-fail.\n");
    exit(0);
}

$jsonFlags = JSON_UNESCAPED_SLASHES;
if (isset($options['pretty'])) {
    $jsonFlags |= JSON_PRETTY_PRINT;
}

try {
    $kernel = KernelBootstrap::bootOrFail();
    $status = $kernel->check();

    $json = json_encode($status, $jsonFlags);
    if (!is_string($json)) {
        throw new \RuntimeException('Unable to encode status JSON.');
    }
    echo $json . PHP_EOL;

    if (!$status->trustedNow && !isset($options['allow-untrusted'])) {
        exit(2);
    }

    exit(0);
} catch (\Throwable $e) {
    fwrite(STDERR, $e->getMessage() . PHP_EOL);
    exit(1);
}

