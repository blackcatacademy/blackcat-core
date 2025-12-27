<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

use Psr\Log\LoggerInterface;
use BlackCat\Core\Database;
use BlackCat\Core\Security\KeyManager;

final class TrustKernel
{
    private Web3RpcQuorumClient $rpc;
    private InstanceControllerReader $controller;
    private ReleaseRegistryReader $releaseRegistry;
    private LocalIntegrityVerifier $integrity;

    private ?IntegrityManifestV1 $manifest = null;
    private ?int $manifestMtime = null;

    private ?TrustKernelStatus $lastStatus = null;
    private ?int $lastStatusAt = null;

    private ?TrustKernelStatus $lastOkStatus = null;
    private ?int $lastOkAt = null;

    /** @var 'strict'|'warn' */
    private string $effectiveEnforcement = 'strict';
    private bool $warnBannerEmitted = false;

    public function __construct(
        private readonly TrustKernelConfig $config,
        private readonly ?LoggerInterface $logger = null,
        ?Web3TransportInterface $transport = null,
    ) {
        $this->rpc = new Web3RpcQuorumClient(
            $config->rpcEndpoints,
            $config->chainId,
            $config->rpcQuorum,
            $transport,
            $config->rpcTimeoutSec,
        );
        $this->controller = new InstanceControllerReader($this->rpc);
        $this->releaseRegistry = new ReleaseRegistryReader($this->rpc);
        $this->integrity = new LocalIntegrityVerifier($config->integrityRootDir);
    }

    public function installGuards(): void
    {
        $alreadyLocked = KeyManager::isAccessGuardLocked()
            || Database::isWriteGuardLocked()
            || Database::isPdoAccessGuardLocked();

        if ($alreadyLocked) {
            if (
                KeyManager::isAccessGuardLocked()
                && Database::isWriteGuardLocked()
                && Database::isPdoAccessGuardLocked()
            ) {
                return;
            }
            throw new TrustKernelException('Kernel guards are partially locked; restart the process.');
        }

        KeyManager::setAccessGuard(function (string $operation): void {
            if ($operation === 'write') {
                $this->assertWriteAllowed('secrets.write');
                return;
            }
            $this->assertReadAllowed('secrets.read');
        });

        Database::setWriteGuard(function (string $sql): void {
            $this->assertWriteAllowed('db.write');
        });

        // Prevent bypass: raw PDO access would skip kernel guards (SQL comment guard, write guard, etc.).
        Database::setPdoAccessGuard(function (string $context): void {
            $this->denyBypass($context);
        });

        // Hard lock: prevent runtime code from disabling guards after bootstrap.
        KeyManager::lockAccessGuard();
        Database::lockWriteGuard();
        Database::lockPdoAccessGuard();
    }

    public function check(): TrustKernelStatus
    {
        $now = time();
        if ($this->lastStatus !== null && $this->lastStatusAt !== null && ($now - $this->lastStatusAt) < 1) {
            return $this->lastStatus;
        }

        $errors = [];
        $rpcOkNow = false;
        $snapshot = null;
        $computedRoot = null;
        $paused = false;
        $trustedNow = false;

        try {
            $snapshot = $this->controller->snapshot($this->config->instanceController);
            $rpcOkNow = true;
        } catch (\Throwable $e) {
            $errors[] = $e->getMessage();
            $rpcOkNow = false;
        }

        if ($rpcOkNow && $snapshot !== null) {
            if ($snapshot->version !== 1) {
                $errors[] = 'Unsupported instance controller snapshot version.';
            }

            $paused = $snapshot->paused;
            if ($paused) {
                $errors[] = 'Instance controller is paused.';
            }

            $activePolicyHash = Bytes32::normalizeHex($snapshot->activePolicyHash);
            $policyOk = false;
            /** @var 'strict'|'warn' $derivedEnforcement */
            $derivedEnforcement = 'strict';
            if (hash_equals(Bytes32::normalizeHex($this->config->policyHashV1), $activePolicyHash)) {
                $policyOk = true;
                $derivedEnforcement = 'strict';
            } elseif (hash_equals(Bytes32::normalizeHex($this->config->policyHashV2Strict), $activePolicyHash)) {
                $policyOk = true;
                $derivedEnforcement = 'strict';
            } elseif (hash_equals(Bytes32::normalizeHex($this->config->policyHashV2Warn), $activePolicyHash)) {
                $policyOk = true;
                $derivedEnforcement = 'warn';
            }

            if (!$policyOk) {
                $errors[] = 'Policy hash mismatch.';
                // If the policy hash is unknown, do not allow any non-strict behavior even in dev.
                $this->effectiveEnforcement = 'strict';
            } else {
                $this->effectiveEnforcement = $derivedEnforcement;
            }

            try {
                $manifest = $this->loadManifestIfNeeded();
                $computedRoot = $this->integrity->computeAndVerifyRoot($manifest);

                $activeRoot = Bytes32::normalizeHex($snapshot->activeRoot);
                $computedRootNorm = Bytes32::normalizeHex($computedRoot);
                if (!hash_equals($activeRoot, $computedRootNorm)) {
                    $errors[] = 'Integrity root mismatch.';
                }

                $uriHash = $manifest->uriHashBytes32();
                if ($uriHash !== null) {
                    $expectedUriHash = Bytes32::normalizeHex($uriHash);
                    $activeUriHash = Bytes32::normalizeHex($snapshot->activeUriHash);
                    if (!hash_equals($expectedUriHash, $activeUriHash)) {
                        $errors[] = 'URI hash mismatch.';
                    }
                }
            } catch (\Throwable $e) {
                $errors[] = $e->getMessage();
            }

            // ReleaseRegistry trust check:
            // - the source of truth is the on-chain pointer stored in the InstanceController
            // - runtime config may additionally *pin* the expected registry address (optional)
            try {
                $rrOnController = strtolower($this->controller->releaseRegistry($this->config->instanceController));
                $rrConfigured = $this->config->releaseRegistry !== null ? strtolower(trim($this->config->releaseRegistry)) : null;

                if ($rrConfigured !== null && $rrConfigured !== $rrOnController) {
                    $errors[] = 'ReleaseRegistry mismatch between config and InstanceController.';
                }

                if ($rrOnController !== '0x0000000000000000000000000000000000000000') {
                    $activeRoot = Bytes32::normalizeHex($snapshot->activeRoot);
                    if (!$this->releaseRegistry->isTrustedRoot($rrOnController, $activeRoot)) {
                        $errors[] = 'Active root is not trusted in ReleaseRegistry.';
                    }
                }
            } catch (\Throwable $e) {
                $errors[] = 'ReleaseRegistry check failed: ' . $e->getMessage();
            }

            // Optional sanity check: if the InstanceController is an EIP-1167 clone, ensure it points to a live implementation.
            try {
                $code = $this->rpc->ethGetCodeQuorum($this->config->instanceController, 'latest');
                $proxyImpl = self::tryParseEip1167Implementation($code);
                if ($proxyImpl !== null) {
                    $implCode = $this->rpc->ethGetCodeQuorum($proxyImpl, 'latest');
                    if ($implCode === '0x' || $implCode === '0x0') {
                        $errors[] = 'InstanceController EIP-1167 implementation has no code.';
                    }
                } else {
                    if ($code === '0x' || $code === '0x0') {
                        $errors[] = 'InstanceController has no code.';
                    }
                }
            } catch (\Throwable $e) {
                $errors[] = 'InstanceController code sanity check failed: ' . $e->getMessage();
            }

            $trustedNow = $errors === [];
            if ($trustedNow) {
                $this->lastOkAt = $now;
            }
        }

        $readAllowed = false;
        $writeAllowed = false;

        if ($trustedNow) {
            $readAllowed = true;
            $writeAllowed = true;
        } else {
            // Only allow stale reads when the failure is RPC-related and we have a recent OK state.
            if (
                !$rpcOkNow
                && $this->lastOkAt !== null
                && ($now - $this->lastOkAt) <= $this->config->maxStaleSec
                && $this->lastOkStatus?->paused === false
            ) {
                // Still re-check local integrity against the last known good on-chain root to prevent
                // "RPC outage + local tamper" from becoming a read bypass.
                try {
                    $manifest = $this->loadManifestIfNeeded();
                    $freshRoot = $this->integrity->computeAndVerifyRoot($manifest);
                    $lastOkRoot = $this->lastOkStatus->snapshot?->activeRoot;
                    $lastOkUriHash = $this->lastOkStatus->snapshot?->activeUriHash;

                    $rootOk = is_string($lastOkRoot)
                        && hash_equals(Bytes32::normalizeHex($lastOkRoot), Bytes32::normalizeHex($freshRoot));

                    $uriOk = true;
                    $manifestUriHash = $manifest->uriHashBytes32();
                    if ($manifestUriHash !== null && is_string($lastOkUriHash)) {
                        $uriOk = hash_equals(Bytes32::normalizeHex($manifestUriHash), Bytes32::normalizeHex($lastOkUriHash));
                    }

                    if ($rootOk && $uriOk) {
                        $readAllowed = true;
                    }
                } catch (\Throwable $e) {
                    $errors[] = 'Stale-mode integrity recheck failed: ' . $e->getMessage();
                }
            }
        }

        $status = new TrustKernelStatus(
            $trustedNow,
            $readAllowed,
            $writeAllowed,
            $rpcOkNow,
            $paused,
            $snapshot,
            $computedRoot,
            $now,
            $this->lastOkAt,
            $errors,
        );

        $this->lastStatus = $status;
        $this->lastStatusAt = $now;
        if ($trustedNow) {
            $this->lastOkStatus = $status;
        }

        return $status;
    }

    public function assertReadAllowed(string $context = 'read'): void
    {
        $status = $this->check();
        if ($status->readAllowed) {
            return;
        }

        $this->enforceOrWarn($context, $status);
    }

    public function assertWriteAllowed(string $context = 'write'): void
    {
        $status = $this->check();
        if ($status->writeAllowed) {
            return;
        }

        $this->enforceOrWarn($context, $status);
    }

    private function enforceOrWarn(string $context, TrustKernelStatus $status): void
    {
        $msg = '[trust-kernel] denied: ' . $context;
        if ($status->errors !== []) {
            $msg .= ' (' . implode(' | ', $status->errors) . ')';
        }

        if ($this->effectiveEnforcement === 'warn') {
            if (!$this->warnBannerEmitted) {
                $this->warnBannerEmitted = true;
                $this->logger?->warning('[trust-kernel] WARNING MODE enabled. Do not use this policy in production.');
            }
            $this->logger?->warning($msg);
            return;
        }

        $this->logger?->error($msg);
        throw new TrustKernelException($msg);
    }

    private function denyBypass(string $context): void
    {
        // Ensure enforcement is derived from the on-chain policy hash (strict vs warn).
        $this->check();

        $msg = '[trust-kernel] bypass denied: ' . $context;

        if ($this->effectiveEnforcement === 'warn') {
            if (!$this->warnBannerEmitted) {
                $this->warnBannerEmitted = true;
                $this->logger?->warning('[trust-kernel] WARNING MODE enabled. Do not use this policy in production.');
            }
            $this->logger?->warning($msg);
            return;
        }

        $this->logger?->error($msg);
        throw new TrustKernelException($msg);
    }

    private function loadManifestIfNeeded(): IntegrityManifestV1
    {
        $path = $this->config->integrityManifestPath;
        clearstatcache(true, $path);

        $mtime = @filemtime($path);
        if (!is_int($mtime) || $mtime <= 0) {
            throw new \RuntimeException('Unable to stat integrity manifest: ' . $path);
        }

        if ($this->manifest !== null && $this->manifestMtime === $mtime) {
            return $this->manifest;
        }

        $manifest = IntegrityManifestV1::fromJsonFile($path);
        $this->manifest = $manifest;
        $this->manifestMtime = $mtime;
        return $manifest;
    }

    private static function tryParseEip1167Implementation(string $codeHex): ?string
    {
        $codeHex = strtolower(trim($codeHex));
        if ($codeHex === '' || !str_starts_with($codeHex, '0x')) {
            return null;
        }

        $payload = substr($codeHex, 2);
        if ($payload === '') {
            return null;
        }

        // EIP-1167 runtime: 0x363d3d373d3d3d363d73<20-byte-impl>5af43d82803e903d91602b57fd5bf3
        $prefix = '363d3d373d3d3d363d73';
        $suffix = '5af43d82803e903d91602b57fd5bf3';

        if (strlen($payload) !== (strlen($prefix) + 40 + strlen($suffix))) {
            return null;
        }
        if (!str_starts_with($payload, $prefix) || !str_ends_with($payload, $suffix)) {
            return null;
        }

        $impl = substr($payload, strlen($prefix), 40);
        if (!is_string($impl) || strlen($impl) !== 40 || !ctype_xdigit($impl)) {
            return null;
        }

        $addr = '0x' . $impl;
        if ($addr === '0x0000000000000000000000000000000000000000') {
            return null;
        }

        return $addr;
    }
}
