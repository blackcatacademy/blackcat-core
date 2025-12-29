<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

use Psr\Log\LoggerInterface;

final class TrustKernelBootstrap
{
    private static ?Web3TransportInterface $defaultTransport = null;
    private static ?TrustKernel $cachedKernel = null;
    private static bool $runtimeGateChecked = false;

    /**
     * Default transport used when boot methods are called with `$transport=null`.
     *
     * Intended mainly for tests / controlled environments.
     */
    public static function setDefaultTransport(?Web3TransportInterface $transport): void
    {
        self::$defaultTransport = $transport;
        self::reset();
    }

    /**
     * Reset cached kernel instance (intended for tests).
     *
     * In production, the TrustKernel should be booted once per process and then reused.
     */
    public static function reset(): void
    {
        self::$cachedKernel = null;
    }

    /**
     * Strict bootstrap for applications.
     *
     * - Returns `null` when no runtime config is available, or when `trust.web3` is not configured.
     * - Throws on any initialization/config error (fail-closed).
     */
    public static function bootIfConfiguredFromBlackCatConfig(
        ?LoggerInterface $logger = null,
        ?Web3TransportInterface $transport = null,
    ): ?TrustKernel
    {
        if (self::$cachedKernel !== null) {
            return self::$cachedKernel;
        }

        $configClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'Config']);
        if (!class_exists($configClass)) {
            return null;
        }

        $isInitialized = false;
        if (is_callable([$configClass, 'isInitialized'])) {
            $method = 'isInitialized';
            $isInitialized = (bool) $configClass::$method();
        }

        if (!$isInitialized) {
            $bootstrapClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'ConfigBootstrap']);
            if (class_exists($bootstrapClass) && is_callable([$bootstrapClass, 'scanFirstAvailableJsonFile'])) {
                $scanMethod = 'scanFirstAvailableJsonFile';
                /** @var mixed $scan */
                $scan = $bootstrapClass::$scanMethod();

                $selected = is_array($scan) ? ($scan['selected'] ?? null) : null;
                $rejected = is_array($scan) ? ($scan['rejected'] ?? null) : null;
                $repoObj = is_array($scan) ? ($scan['repo'] ?? null) : null;

                if (!is_string($selected) || trim($selected) === '') {
                    if (is_array($rejected) && $rejected !== []) {
                        $lines = [];
                        foreach ($rejected as $path => $reason) {
                            if (!is_string($path) || !is_string($reason)) {
                                continue;
                            }
                            $lines[] = sprintf('- %s: %s', $path, $reason);
                        }

                        throw new \RuntimeException(sprintf(
                            "No usable runtime config file found.\nRejected files:\n%s",
                            $lines !== [] ? implode("\n", $lines) : '(unknown)',
                        ));
                    }

                    return null;
                }

                // Prefer using the already-loaded repository (avoids a second read).
                if (is_object($repoObj) && is_callable([$configClass, 'initIfNeeded'])) {
                    $initMethod = 'initIfNeeded';
                    $configClass::$initMethod($repoObj);
                } elseif (is_callable([$configClass, 'initFromJsonFileIfNeeded'])) {
                    $initMethod = 'initFromJsonFileIfNeeded';
                    $configClass::$initMethod($selected);
                } elseif (is_callable([$configClass, 'initFromFirstAvailableJsonFileIfNeeded'])) {
                    // Legacy fallback.
                    $initMethod = 'initFromFirstAvailableJsonFileIfNeeded';
                    $configClass::$initMethod();
                }
            } elseif (is_callable([$configClass, 'tryInitFromFirstAvailableJsonFile'])) {
                $method = 'tryInitFromFirstAvailableJsonFile';
                $configClass::$method();
            } elseif (is_callable([$configClass, 'initFromFirstAvailableJsonFileIfNeeded'])) {
                // Legacy fallback.
                $method = 'initFromFirstAvailableJsonFileIfNeeded';
                $configClass::$method();
            }
        }

        if (is_callable([$configClass, 'isInitialized'])) {
            $method = 'isInitialized';
            if (!(bool) $configClass::$method()) {
                return null;
            }
        }

        if (!is_callable([$configClass, 'repo'])) {
            throw new \RuntimeException('blackcat-config runtime repo is not available.');
        }

        $repoMethod = 'repo';
        /** @var mixed $repoRaw */
        $repoRaw = $configClass::$repoMethod();
        if (!is_object($repoRaw)) {
            throw new \RuntimeException('blackcat-config runtime repo must be an object.');
        }

        $repo = new BlackCatConfigRepositoryAdapter($repoRaw);
        $cfg = TrustKernelConfig::fromRuntimeConfig($repo);
        if ($cfg === null) {
            return null;
        }

        $kernel = new TrustKernel($cfg, $logger, $transport ?? self::$defaultTransport);
        $kernel->installGuards();

        self::$cachedKernel = $kernel;
        return $kernel;
    }

    /**
     * Production bootstrap for "trust-required" deployments.
     *
     * Always throws if the trust-kernel cannot be booted (fail-closed).
     */
    public static function bootFromBlackCatConfigOrFail(
        ?LoggerInterface $logger = null,
        ?Web3TransportInterface $transport = null,
    ): TrustKernel
    {
        $configClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'Config']);
        if (!class_exists($configClass)) {
            throw new \RuntimeException('blackcat-config is not installed.');
        }

        $kernel = self::bootIfConfiguredFromBlackCatConfig($logger, $transport);
        if ($kernel === null) {
            throw new \RuntimeException('TrustKernel is not configured (missing runtime config or trust.web3).');
        }

        self::enforceBootstrapRuntimeGate($logger);

        return $kernel;
    }

    public static function tryBootFromBlackCatConfig(?LoggerInterface $logger = null): ?TrustKernel
    {
        $configClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'Config']);
        if (!class_exists($configClass)) {
            return null;
        }

        try {
            return self::bootIfConfiguredFromBlackCatConfig($logger, self::$defaultTransport);
        } catch (\Throwable $e) {
            $logger?->warning('[trust-kernel] unable to boot: ' . $e->getMessage());
            return null;
        }
    }

    private static function enforceBootstrapRuntimeGate(?LoggerInterface $logger = null): void
    {
        if (self::$runtimeGateChecked) {
            return;
        }
        self::$runtimeGateChecked = true;

        // Only enforce for HTTP runtimes (boot should not break CLI tooling or background jobs).
        if (PHP_SAPI === 'cli' || !isset($_SERVER['REQUEST_METHOD'])) {
            return;
        }

        $configClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'Config']);
        $doctorClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'RuntimeDoctor']);

        if (
            !class_exists($configClass)
            || !class_exists($doctorClass)
            || !is_callable([$configClass, 'isInitialized'])
            || !is_callable([$configClass, 'repo'])
            || !is_callable([$doctorClass, 'inspect'])
        ) {
            return;
        }

        $isInitialized = 'isInitialized';
        if (!(bool) $configClass::$isInitialized()) {
            return;
        }

        $repoMethod = 'repo';
        /** @var mixed $repo */
        $repo = $configClass::$repoMethod();
        if (!is_object($repo) || !method_exists($repo, 'get')) {
            return;
        }

        $get = 'get';
        $enforcementRaw = $repo->$get('trust.enforcement', 'strict');
        $enforcement = is_string($enforcementRaw) ? strtolower(trim($enforcementRaw)) : 'strict';
        if (!in_array($enforcement, ['strict', 'warn'], true)) {
            $enforcement = 'strict';
        }

        try {
            /** @var mixed $report */
            $report = $doctorClass::inspect($repo);
            $findings = is_array($report) ? ($report['findings'] ?? null) : null;

            if (!is_array($findings)) {
                return;
            }

            $fatalStrict = [
                'php_allow_url_include_enabled' => true,
                'php_phar_readonly_disabled' => true,
                'php_open_basedir_unset' => true,
                'php_disable_functions_empty' => true,
                'php_disable_functions_missing_dangerous' => true,
                'php_display_errors_enabled' => true,
                'php_enable_dl_enabled' => true,
                'php_auto_prepend_file_set' => true,
                'php_auto_append_file_set' => true,
                'php_cgi_fix_pathinfo_enabled' => true,
                'php_no_transport_for_web3' => true,
            ];

            /** @var list<string> $fatalCodes */
            $fatalCodes = [];
            /** @var list<string> $warnLines */
            $warnLines = [];

            foreach ($findings as $f) {
                if (!is_array($f)) {
                    continue;
                }
                $code = $f['code'] ?? null;
                if (!is_string($code) || $code === '' || str_contains($code, "\0") || !str_starts_with($code, 'php_')) {
                    continue;
                }

                $severity = $f['severity'] ?? 'warn';
                if (!is_string($severity) || !in_array($severity, ['info', 'warn', 'error'], true)) {
                    $severity = 'warn';
                }

                $message = $f['message'] ?? '';
                if (!is_string($message) || str_contains($message, "\0")) {
                    $message = '';
                }

                $isFatal = ($severity === 'error') || isset($fatalStrict[$code]);
                if ($isFatal) {
                    $fatalCodes[] = $code;
                }

                $line = '[trust-kernel] runtime doctor: ' . $code;
                if (trim($message) !== '') {
                    $line .= ' - ' . trim($message);
                }
                $warnLines[] = $line;
            }

            if ($warnLines !== []) {
                foreach ($warnLines as $line) {
                    $logger?->warning($line);
                    @error_log($line);
                }
            }

            if ($enforcement === 'strict' && $fatalCodes !== []) {
                $fatalCodes = array_values(array_unique($fatalCodes));
                sort($fatalCodes, SORT_STRING);
                throw new \RuntimeException(
                    'Runtime hardening gate failed (php.ini posture). Fix these findings: ' . implode(', ', $fatalCodes)
                );
            }
        } catch (\Throwable $e) {
            if ($enforcement === 'strict') {
                throw $e;
            }

            $logger?->warning('[trust-kernel] runtime hardening gate skipped (warn mode): ' . $e->getMessage());
            @error_log('[trust-kernel] runtime hardening gate skipped (warn mode): ' . $e->getMessage());
        }
    }
}
