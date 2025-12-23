<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

use Psr\Log\LoggerInterface;

final class TrustKernelBootstrap
{
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
