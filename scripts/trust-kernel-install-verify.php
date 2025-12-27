#!/usr/bin/env php
<?php

declare(strict_types=1);

$autoload = __DIR__ . '/../vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
}

use BlackCat\Core\Kernel\KernelBootstrap;

/**
 * Post-install verification for “cheap hosting” deployments.
 *
 * Checks:
 * - TrustKernel status (on-chain + local integrity)
 * - optional bypass scan (raw PDO, direct *.key reads) via blackcat-config security scanner
 * - filesystem permission sanity under trust.integrity.root_dir (best-effort)
 *
 * Exit codes:
 * - 0: OK
 * - 2: verification failed (untrusted / violations)
 * - 1: runtime error (missing config, invalid config, etc.)
 */

$options = getopt('', [
    'pretty',
    'allow-untrusted',
    'allow-warn',
    'help',
]);
if ($options === false || isset($options['help'])) {
    fwrite(STDERR, "Usage:\n");
    fwrite(STDERR, "  trust-kernel-install-verify.php [--pretty] [--allow-untrusted] [--allow-warn]\n");
    exit(0);
}

$jsonFlags = JSON_UNESCAPED_SLASHES;
if (isset($options['pretty'])) {
    $jsonFlags |= JSON_PRETTY_PRINT;
}

$out = [
    'ok' => false,
    'status' => null,
    'checks' => [],
];

try {
    $kernel = KernelBootstrap::bootOrFail();
    $status = $kernel->check();
    $out['status'] = $status;

    $failed = false;

    if (!$status->trustedNow && !isset($options['allow-untrusted'])) {
        $failed = true;
    }
    if ($status->enforcement !== 'strict' && !isset($options['allow-warn'])) {
        $failed = true;
    }

    // Try to load runtime config repo (for extra checks). This is best-effort and must not break core validation.
    $repo = null;
    $configClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'Config']);
    if (class_exists($configClass) && is_callable([$configClass, 'repo'])) {
        $method = 'repo';
        /** @var object $repo */
        $repo = $configClass::$method();
    }

    // 1) Bypass scan (CI / audit helper)
    $scanClass = implode('\\', ['BlackCat', 'Config', 'Security', 'SourceCodePolicyScanner']);
    if (class_exists($scanClass) && is_callable([$scanClass, 'scan'])) {
        $root = null;
        if ($repo !== null && method_exists($repo, 'requireString') && method_exists($repo, 'resolvePath')) {
            try {
                /** @var string $rootRel */
                $rootRel = $repo->requireString('trust.integrity.root_dir');
                /** @var string $rootAbs */
                $rootAbs = $repo->resolvePath($rootRel);
                $root = $rootAbs;
            } catch (\Throwable) {
                $root = null;
            }
        }
        $root ??= (string) (getcwd() ?: '.');

        try {
            /** @var array{violations?:mixed} $res */
            $res = $scanClass::scan($root);
            $violations = $res['violations'] ?? [];
            $out['checks']['bypass_scan'] = [
                'root' => $root,
                'violations' => $violations,
            ];
            if (is_array($violations) && $violations !== []) {
                $failed = true;
            }
        } catch (\Throwable $e) {
            $out['checks']['bypass_scan'] = [
                'root' => $root,
                'error' => $e->getMessage(),
            ];
        }
    } else {
        $out['checks']['bypass_scan'] = [
            'skipped' => true,
            'reason' => 'blackcat-config SourceCodePolicyScanner not available.',
        ];
    }

    // 2) Permission sanity under integrity root (best-effort, POSIX only)
    $integrityRoot = null;
    if ($repo !== null && method_exists($repo, 'requireString') && method_exists($repo, 'resolvePath')) {
        try {
            /** @var string $rootRel */
            $rootRel = $repo->requireString('trust.integrity.root_dir');
            /** @var string $rootAbs */
            $rootAbs = $repo->resolvePath($rootRel);
            $integrityRoot = $rootAbs;
        } catch (\Throwable) {
            $integrityRoot = null;
        }
    }

    if ($integrityRoot !== null && DIRECTORY_SEPARATOR !== '\\') {
        $findings = [];
        $maxFindings = 50;

        $dirIt = new \RecursiveDirectoryIterator($integrityRoot, \FilesystemIterator::SKIP_DOTS);
        $it = new \RecursiveIteratorIterator($dirIt);

        /** @var \SplFileInfo $file */
        foreach ($it as $file) {
            if (count($findings) >= $maxFindings) {
                break;
            }

            $path = $file->getPathname();
            if ($file->isLink()) {
                $findings[] = [
                    'type' => 'symlink',
                    'path' => $path,
                ];
                $failed = true;
                continue;
            }

            $perms = @fileperms($path);
            if (!is_int($perms)) {
                continue;
            }
            $mode = $perms & 0777;

            $groupWritable = ($mode & 0o020) !== 0;
            $worldWritable = ($mode & 0o002) !== 0;
            if ($groupWritable || $worldWritable) {
                $findings[] = [
                    'type' => 'writable',
                    'path' => $path,
                    'mode' => sprintf('%o', $mode),
                ];
                $failed = true;
            }
        }

        $out['checks']['integrity_root_permissions'] = [
            'root' => $integrityRoot,
            'max_findings' => $maxFindings,
            'findings' => $findings,
        ];
    } else {
        $out['checks']['integrity_root_permissions'] = [
            'skipped' => true,
            'reason' => $integrityRoot === null ? 'Integrity root not available.' : 'POSIX permissions not available on Windows.',
        ];
    }

    $out['ok'] = !$failed;
    $json = json_encode($out, $jsonFlags);
    if (!is_string($json)) {
        throw new \RuntimeException('Unable to encode JSON output.');
    }
    echo $json . PHP_EOL;
    exit($out['ok'] ? 0 : 2);
} catch (\Throwable $e) {
    $out['ok'] = false;
    $out['error'] = $e->getMessage();
    $json = json_encode($out, $jsonFlags);
    if (is_string($json)) {
        echo $json . PHP_EOL;
    } else {
        fwrite(STDERR, $e->getMessage() . PHP_EOL);
    }
    exit(1);
}

