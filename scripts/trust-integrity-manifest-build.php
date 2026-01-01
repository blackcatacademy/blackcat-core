#!/usr/bin/env php
<?php

declare(strict_types=1);

$autoload = __DIR__ . '/../vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
}

use BlackCat\Core\TrustKernel\IntegrityManifestBuilder;

/**
 * Build a v1 integrity manifest + print the computed root/uriHash for on-chain commits.
 *
 * Example:
 *   php scripts/trust-integrity-manifest-build.php --root=/srv/app --out=/etc/blackcat/integrity.manifest.json --uri=https://example.com/release/1.0.0
 */

$options = getopt('', ['root:', 'out:', 'uri::', 'pretty', 'help']);
if ($options === false || isset($options['help'])) {
    fwrite(STDERR, "Usage:\n");
    fwrite(STDERR, "  trust-integrity-manifest-build.php --root=/abs/path [--out=/abs/path] [--uri=https://...] [--pretty]\n");
    exit(0);
}

$root = $options['root'] ?? null;
if (!is_string($root) || trim($root) === '') {
    fwrite(STDERR, "Missing required --root\n");
    exit(1);
}

$out = $options['out'] ?? null;
if ($out !== null && (!is_string($out) || trim($out) === '')) {
    fwrite(STDERR, "Invalid --out\n");
    exit(1);
}

$uri = $options['uri'] ?? null;
if ($uri !== null && (!is_string($uri) || trim($uri) === '')) {
    fwrite(STDERR, "Invalid --uri\n");
    exit(1);
}

$jsonFlags = JSON_UNESCAPED_SLASHES;
if (isset($options['pretty'])) {
    $jsonFlags |= JSON_PRETTY_PRINT;
}

try {
    $res = IntegrityManifestBuilder::build($root, $uri);
    $manifest = $res['manifest'];

    if ($out !== null) {
        $dir = dirname($out);
        if ($dir === '' || $dir === '.' || $dir === DIRECTORY_SEPARATOR) {
            throw new \RuntimeException('Invalid manifest output path: ' . $out);
        }
        if (!is_dir($dir)) {
            throw new \RuntimeException('Manifest output directory does not exist: ' . $dir);
        }
        if (is_link($dir)) {
            throw new \RuntimeException('Manifest output directory must not be a symlink: ' . $dir);
        }

        $json = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (!is_string($json)) {
            throw new \RuntimeException('Unable to encode manifest JSON.');
        }
        if (@file_put_contents($out, $json . "\n") === false) {
            throw new \RuntimeException('Unable to write manifest: ' . $out);
        }
    }

    $summary = [
        'ok' => true,
        'manifest_path' => $out,
        'root' => $res['root'],
        'uri_hash' => $res['uri_hash'],
        'files_count' => $res['files_count'],
    ];
    $json = json_encode($summary, $jsonFlags);
    if (!is_string($json)) {
        throw new \RuntimeException('Unable to encode output JSON.');
    }
    echo $json . PHP_EOL;
    exit(0);
} catch (\Throwable $e) {
    $err = [
        'ok' => false,
        'error' => $e->getMessage(),
    ];
    $json = json_encode($err, $jsonFlags);
    if (is_string($json)) {
        echo $json . PHP_EOL;
    } else {
        fwrite(STDERR, $e->getMessage() . PHP_EOL);
    }
    exit(2);
}

