<?php

declare(strict_types=1);

namespace BlackCat\Core\Kernel;

use BlackCat\Core\TrustKernel\TrustKernel;
use BlackCat\Core\TrustKernel\TrustKernelBootstrap;
use BlackCat\Core\TrustKernel\Web3TransportInterface;
use Psr\Log\LoggerInterface;

/**
 * Kernel bootstrap entrypoint (recommended).
 *
 * Goal:
 * - initialize runtime config (via blackcat-config, strict-by-default),
 * - boot the Trust Kernel (Web3 authority + integrity),
 * - install global guards before any application logic runs.
 *
 * This is designed for kernel-only deployments where `blackcat-core` + `blackcat-config`
 * are the minimum required security foundation.
 */
final class KernelBootstrap
{
    /**
     * Production bootstrap for kernel-only deployments.
     *
     * Fail-closed:
     * - throws if runtime config is missing/invalid
     * - throws if `trust.web3` is not configured
     * - installs guards for secrets + DB writes
     */
    public static function bootOrFail(
        ?LoggerInterface $logger = null,
        ?Web3TransportInterface $transport = null,
    ): TrustKernel {
        return TrustKernelBootstrap::bootFromBlackCatConfigOrFail($logger, $transport);
    }

    /**
     * Optional bootstrap for libraries and non-trust-required stacks.
     *
     * Returns `null` only when `trust.web3` is not configured.
     * Throws on invalid runtime config (fail-closed).
     */
    public static function bootIfConfigured(
        ?LoggerInterface $logger = null,
        ?Web3TransportInterface $transport = null,
    ): ?TrustKernel {
        return TrustKernelBootstrap::bootIfConfiguredFromBlackCatConfig($logger, $transport);
    }
}

