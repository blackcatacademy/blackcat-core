<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

use Psr\Log\LoggerInterface;

final class TrustKernelBootstrap
{
    private static ?Web3TransportInterface $defaultTransport = null;
    private static ?TrustKernel $cachedKernel = null;

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

        // Fail-closed: ensure a request-context process does not proceed with an unsafe / untrusted state.
        //
        // This intentionally runs the full `check()` once during bootstrap to:
        // - derive enforcement from the on-chain policy hash (NOT from runtime config),
        // - apply runtime hardening gate (RuntimeDoctor / PhpRuntimeInspector) in HTTP contexts,
        // - prime the per-request cache (avoid duplicate RPC on first guarded operation).
        //
        // In non-request contexts (CLI/worker), do not force an RPC call at bootstrap time.
        if (PHP_SAPI !== 'cli' && isset($_SERVER['REQUEST_METHOD'])) {
            $status = $kernel->check();
            if ($status->enforcement === 'strict' && !$status->readAllowed) {
                $msg = 'TrustKernel denied read on bootstrap.';
                if ($status->errors !== []) {
                    $msg .= ' (' . implode(' | ', $status->errors) . ')';
                }
                throw new \RuntimeException($msg);
            }
        }

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

}
