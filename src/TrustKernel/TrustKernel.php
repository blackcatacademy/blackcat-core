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
                if (!KeyManager::hasAccessGuard() || !Database::hasWriteGuard() || !Database::hasPdoAccessGuard()) {
                    throw new TrustKernelException('Kernel guards are locked but missing; restart the process.');
                }
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
        $errorCodes = [];

        $addError = static function (string $code, string $message) use (&$errors, &$errorCodes): void {
            $errorCodes[] = $code;
            $errors[] = $message;
        };
        $rpcOkNow = false;
        $snapshot = null;
        $computedRoot = null;
        $paused = false;
        $trustedNow = false;

        try {
            $snapshot = $this->controller->snapshot($this->config->instanceController);
            $rpcOkNow = true;
        } catch (\Throwable $e) {
            $addError('rpc_error', $e->getMessage());
            $rpcOkNow = false;
        }

        if ($rpcOkNow && $snapshot !== null) {
            if ($snapshot->version !== 1) {
                $addError('unsupported_snapshot_version', 'Unsupported instance controller snapshot version.');
            }

            $paused = $snapshot->paused;
            if ($paused) {
                $addError('paused', 'Instance controller is paused.');
            }

            $activePolicyHash = Bytes32::normalizeHex($snapshot->activePolicyHash);
            $policyOk = false;
            /** @var 'strict'|'warn' $derivedEnforcement */
            $derivedEnforcement = 'strict';
            $requiresRuntimeConfigAttestation = false;
            if (hash_equals(Bytes32::normalizeHex($this->config->policyHashV1), $activePolicyHash)) {
                $policyOk = true;
                $derivedEnforcement = 'strict';
            } elseif (hash_equals(Bytes32::normalizeHex($this->config->policyHashV2Strict), $activePolicyHash)) {
                $policyOk = true;
                $derivedEnforcement = 'strict';
            } elseif (hash_equals(Bytes32::normalizeHex($this->config->policyHashV2Warn), $activePolicyHash)) {
                $policyOk = true;
                $derivedEnforcement = 'warn';
            } elseif (hash_equals(Bytes32::normalizeHex($this->config->policyHashV3Strict), $activePolicyHash)) {
                $policyOk = true;
                $derivedEnforcement = 'strict';
                $requiresRuntimeConfigAttestation = true;
            } elseif (hash_equals(Bytes32::normalizeHex($this->config->policyHashV3Warn), $activePolicyHash)) {
                $policyOk = true;
                $derivedEnforcement = 'warn';
                $requiresRuntimeConfigAttestation = true;
            }

            if (!$policyOk) {
                $addError('policy_hash_mismatch', 'Policy hash mismatch.');
                // If the policy hash is unknown, do not allow any non-strict behavior even in dev.
                $this->effectiveEnforcement = 'strict';
            } else {
                $this->effectiveEnforcement = $derivedEnforcement;
            }

            try {
                $manifest = $this->loadManifestIfNeeded();
                $computedRoot = $this->config->mode === 'full'
                    ? $this->integrity->computeAndVerifyRootStrict($manifest)
                    : $this->integrity->computeAndVerifyRoot($manifest);

                $activeRoot = Bytes32::normalizeHex($snapshot->activeRoot);
                $computedRootNorm = Bytes32::normalizeHex($computedRoot);
                if (!hash_equals($activeRoot, $computedRootNorm)) {
                    $addError('integrity_root_mismatch', 'Integrity root mismatch.');
                }

                $activeUriHash = Bytes32::normalizeHex($snapshot->activeUriHash);
                $manifestUriHash = $manifest->uriHashBytes32();
                $zero = '0x' . str_repeat('00', 32);

                // URI hash is part of the on-chain snapshot. If the chain commits to a non-zero URI hash,
                // the local manifest must provide a matching `uri` (do NOT allow skipping by removing it).
                if ($activeUriHash === $zero) {
                    if ($manifestUriHash !== null) {
                        $addError('uri_hash_mismatch', 'URI hash mismatch.');
                    }
                } else {
                    if ($manifestUriHash === null) {
                        $addError('uri_hash_missing', 'URI hash is missing from integrity manifest.');
                    } else {
                        $expectedUriHash = Bytes32::normalizeHex($manifestUriHash);
                        if (!hash_equals($expectedUriHash, $activeUriHash)) {
                            $addError('uri_hash_mismatch', 'URI hash mismatch.');
                        }
                    }
                }
            } catch (IntegrityViolationException $e) {
                $addError($e->violationCode, $e->getMessage());
            } catch (\Throwable $e) {
                $addError('integrity_check_failed', $e->getMessage());
            }

            // Optional hardening (policy v3): bind runtime config to on-chain attestation.
            if ($requiresRuntimeConfigAttestation) {
                try {
                    $expected = $this->config->runtimeConfigCanonicalSha256;
                    if ($expected === null) {
                        $addError('runtime_config_commitment_missing', 'Runtime config commitment is not available (missing sourcePath).');
                    } else {
                        $key = Bytes32::normalizeHex($this->config->runtimeConfigAttestationKey);
                        $expectedNorm = Bytes32::normalizeHex($expected);
                        $onChain = Bytes32::normalizeHex($this->controller->attestation($this->config->instanceController, $key));

                        if (!hash_equals($expectedNorm, $onChain)) {
                            $addError('runtime_config_commitment_mismatch', 'Runtime config commitment mismatch.');
                        }

                        if (!$this->controller->attestationLocked($this->config->instanceController, $key)) {
                            $addError('runtime_config_commitment_unlocked', 'Runtime config commitment key is not locked.');
                        }
                    }
                } catch (\Throwable $e) {
                    $addError('runtime_config_attestation_failed', 'Runtime config attestation check failed: ' . $e->getMessage());
                }
            }

            // ReleaseRegistry trust check:
            // - the source of truth is the on-chain pointer stored in the InstanceController
            // - runtime config may additionally *pin* the expected registry address (optional)
            try {
                $rrOnController = strtolower($this->controller->releaseRegistry($this->config->instanceController));
                $rrConfigured = $this->config->releaseRegistry !== null ? strtolower(trim($this->config->releaseRegistry)) : null;

                if ($rrConfigured !== null && $rrConfigured !== $rrOnController) {
                    $addError('release_registry_mismatch', 'ReleaseRegistry mismatch between config and InstanceController.');
                }

                if ($rrOnController !== '0x0000000000000000000000000000000000000000') {
                    $activeRoot = Bytes32::normalizeHex($snapshot->activeRoot);
                    if (!$this->releaseRegistry->isTrustedRoot($rrOnController, $activeRoot)) {
                        $addError('untrusted_release_root', 'Active root is not trusted in ReleaseRegistry.');
                    }
                }
            } catch (\Throwable $e) {
                $addError('release_registry_check_failed', 'ReleaseRegistry check failed: ' . $e->getMessage());
            }

            // Optional sanity check: if the InstanceController is an EIP-1167 clone, ensure it points to a live implementation.
            try {
                $code = $this->rpc->ethGetCodeQuorum($this->config->instanceController, 'latest');
                $proxyImpl = self::tryParseEip1167Implementation($code);
                if ($proxyImpl !== null) {
                    $implCode = $this->rpc->ethGetCodeQuorum($proxyImpl, 'latest');
                    if ($implCode === '0x' || $implCode === '0x0') {
                        $addError('controller_impl_no_code', 'InstanceController EIP-1167 implementation has no code.');
                    }
                } else {
                    if ($code === '0x' || $code === '0x0') {
                        $addError('controller_no_code', 'InstanceController has no code.');
                    }
                }
            } catch (\Throwable $e) {
                $addError('controller_code_sanity_failed', 'InstanceController code sanity check failed: ' . $e->getMessage());
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
                        $freshRoot = $this->config->mode === 'full'
                            ? $this->integrity->computeAndVerifyRootStrict($manifest)
                            : $this->integrity->computeAndVerifyRoot($manifest);
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
                    $addError('stale_integrity_recheck_failed', 'Stale-mode integrity recheck failed: ' . $e->getMessage());
                }
            }
        }

        $status = new TrustKernelStatus(
            $this->effectiveEnforcement,
            $this->config->mode,
            $this->config->maxStaleSec,
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
            $errorCodes,
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

        if ($this->effectiveEnforcement === 'warn' && !$this->warnBannerEmitted) {
            $this->warnBannerEmitted = true;
            $this->logger?->warning('[trust-kernel] WARNING MODE enabled. Do not use this policy in production.');
        }

        // Emergency stop is absolute, regardless of warn/strict mode.
        if ($status->paused) {
            $this->logger?->error('[trust-kernel] PAUSED: ' . $msg);
            throw new TrustKernelException('[trust-kernel] PAUSED: ' . $msg);
        }

        if ($this->effectiveEnforcement === 'warn') {
            $this->logger?->warning($msg);
            return;
        }

        $this->logger?->error($msg);
        throw new TrustKernelException($msg);
    }

    private function denyBypass(string $context): void
    {
        $msg = '[trust-kernel] bypass denied: ' . $context;
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
