<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

use Psr\Log\LoggerInterface;

final class TrustKernelBootstrap
{
    /**
     * Strict bootstrap for applications.
     *
     * - Returns `null` only when `trust.web3` is not configured.
     * - Throws on any initialization/config error (fail-closed).
     */
    public static function bootIfConfiguredFromBlackCatConfig(
        ?LoggerInterface $logger = null,
        ?Web3TransportInterface $transport = null,
    ): ?TrustKernel
    {
        $configClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'Config']);
        if (!class_exists($configClass)) {
            return null;
        }

        if (is_callable([$configClass, 'initFromFirstAvailableJsonFileIfNeeded'])) {
            $method = 'initFromFirstAvailableJsonFileIfNeeded';
            $configClass::$method();
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

        $kernel = new TrustKernel($cfg, $logger, $transport);
        $kernel->installGuards();
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
            throw new \RuntimeException('TrustKernel is not configured (missing trust.web3).');
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
            if (is_callable([$configClass, 'initFromFirstAvailableJsonFileIfNeeded'])) {
                $method = 'initFromFirstAvailableJsonFileIfNeeded';
                $configClass::$method();
            }
        } catch (\Throwable $e) {
            $logger?->warning('[trust-kernel] unable to init runtime config: ' . $e->getMessage());
            return null;
        }

        if (!is_callable([$configClass, 'repo'])) {
            return null;
        }

        try {
            $repoMethod = 'repo';
            /** @var mixed $repoRaw */
            $repoRaw = $configClass::$repoMethod();
            if (!is_object($repoRaw)) {
                return null;
            }

            $repo = new BlackCatConfigRepositoryAdapter($repoRaw);
            $cfg = TrustKernelConfig::fromRuntimeConfig($repo);
            if ($cfg === null) {
                return null;
            }

            $kernel = new TrustKernel($cfg, $logger);
            $kernel->installGuards();
            return $kernel;
        } catch (\Throwable $e) {
            $logger?->warning('[trust-kernel] unable to boot: ' . $e->getMessage());
            return null;
        }
    }
}
