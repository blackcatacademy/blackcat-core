<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

use Psr\Log\LoggerInterface;
use BlackCat\Core\Database;
use BlackCat\Core\Security\KeyManager;

final class TrustKernel
{
    private const LAST_OK_STATE_FILENAME = 'trust.last_ok.v1.json';

    private Web3RpcQuorumClient $rpc;
    private InstanceControllerReader $controller;
    private ReleaseRegistryReader $releaseRegistry;
    private LocalIntegrityVerifier $integrity;

    private ?IntegrityManifestV1 $manifest = null;
    private ?int $manifestMtime = null;

    private ?TrustKernelStatus $lastStatus = null;
    private ?int $lastStatusAt = null;
    private ?string $lastStatusRequestId = null;

    private ?TrustKernelStatus $lastOkStatus = null;
    private ?int $lastOkAt = null;

    private ?string $lastOkRuntimeConfigSha256 = null;

    private ?string $lastOkStatePath = null;
    private ?int $lastOkStateMtime = null;

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

        $sourcePath = $config->runtimeConfigSourcePath;
        if (is_string($sourcePath) && $sourcePath !== '') {
            $dir = dirname($sourcePath);
            if ($dir !== '' && $dir !== '.' && !str_contains($dir, "\0")) {
                $this->lastOkStatePath = $dir . DIRECTORY_SEPARATOR . self::LAST_OK_STATE_FILENAME;
            }
        }
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
        $requestId = self::currentRequestId();

        // Cache within the same HTTP request only.
        // Do not cache across requests (even within the same second) to avoid "1s stale trust" windows
        // in long-lived PHP-FPM workers.
        if ($requestId !== null && $this->lastStatus !== null && $this->lastStatusRequestId === $requestId) {
            return $this->lastStatus;
        }

        // Fallback: allow a tiny cache window for non-request contexts (CLI/worker) to reduce RPC churn.
        if ($requestId === null && $this->lastStatus !== null && $this->lastStatusAt !== null && ($now - $this->lastStatusAt) < 1) {
            return $this->lastStatus;
        }

        $this->hydrateLastOkFromDiskIfAvailable();

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

            // Strict deployments must not rely on a single RPC endpoint.
            // With quorum=1, a single compromised/malicious endpoint can lie about on-chain state.
            $endpointCount = count($this->config->rpcEndpoints);
            if ($this->effectiveEnforcement === 'strict' && ($endpointCount < 2 || $this->config->rpcQuorum < 2)) {
                $addError('rpc_quorum_insecure', 'Strict mode requires at least 2 RPC endpoints and quorum >= 2.');
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
                    $sourcePath = $this->config->runtimeConfigSourcePath;

                    if ($expected === null || $sourcePath === null) {
                        $addError('runtime_config_commitment_missing', 'Runtime config commitment is not available (missing sourcePath).');
                    } else {
                        $key = Bytes32::normalizeHex($this->config->runtimeConfigAttestationKey);
                        $expectedNorm = Bytes32::normalizeHex($expected);

                        // Detect runtime config tamper: the on-disk file must remain equal to the config used for boot.
                        clearstatcache(true, $sourcePath);
                        $rawNow = @file_get_contents($sourcePath);
                        if ($rawNow === false) {
                            $addError('runtime_config_source_unreadable', 'Runtime config file is not readable: ' . $sourcePath);
                        } else {
                            try {
                                /** @var mixed $decodedNow */
                                $decodedNow = json_decode($rawNow, true, 512, JSON_THROW_ON_ERROR);
                                if (!is_array($decodedNow)) {
                                    $addError('runtime_config_source_invalid', 'Runtime config JSON must decode to an object/array: ' . $sourcePath);
                                } else {
                                    /** @var array<string,mixed> $decodedNow */
                                    $current = CanonicalJson::sha256Bytes32($decodedNow);
                                    if (!hash_equals($expectedNorm, Bytes32::normalizeHex($current))) {
                                        $addError('runtime_config_source_changed', 'Runtime config file differs from the booted config (restart required).');
                                    }
                                }
                            } catch (\JsonException $e) {
                                $addError('runtime_config_source_invalid', 'Runtime config file JSON is invalid: ' . $sourcePath . ' (' . $e->getMessage() . ')');
                            }
                        }

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

                    $runtimeConfigOk = true;
                    $lastOkPolicyHash = $this->lastOkStatus->snapshot?->activePolicyHash;
                    if (is_string($lastOkPolicyHash)) {
                        $policyNorm = Bytes32::normalizeHex($lastOkPolicyHash);
                        $v3Strict = Bytes32::normalizeHex($this->config->policyHashV3Strict);
                        $v3Warn = Bytes32::normalizeHex($this->config->policyHashV3Warn);
                        $requiresV3 = hash_equals($v3Strict, $policyNorm) || hash_equals($v3Warn, $policyNorm);
                        if ($requiresV3) {
                            $expectedCfgSha = $this->lastOkRuntimeConfigSha256;
                            $sourcePath = $this->config->runtimeConfigSourcePath;
                            if ($expectedCfgSha === null || !is_string($sourcePath) || $sourcePath === '' || !is_file($sourcePath)) {
                                $runtimeConfigOk = false;
                                $addError('stale_runtime_config_missing', 'Stale-mode runtime config commitment is not available.');
                            } else {
                                clearstatcache(true, $sourcePath);
                                $rawNow = @file_get_contents($sourcePath);
                                if ($rawNow === false) {
                                    $runtimeConfigOk = false;
                                    $addError('stale_runtime_config_unreadable', 'Stale-mode runtime config file is not readable: ' . $sourcePath);
                                } else {
                                    try {
                                        /** @var mixed $decodedNow */
                                        $decodedNow = json_decode($rawNow, true, 512, JSON_THROW_ON_ERROR);
                                        if (!is_array($decodedNow)) {
                                            $runtimeConfigOk = false;
                                            $addError('stale_runtime_config_invalid', 'Stale-mode runtime config JSON must decode to an object/array: ' . $sourcePath);
                                        } else {
                                            /** @var array<string,mixed> $decodedNow */
                                            $currentCfgSha = CanonicalJson::sha256Bytes32($decodedNow);
                                            $runtimeConfigOk = hash_equals(Bytes32::normalizeHex($expectedCfgSha), Bytes32::normalizeHex($currentCfgSha));
                                            if (!$runtimeConfigOk) {
                                                $addError('stale_runtime_config_mismatch', 'Stale-mode runtime config commitment mismatch.');
                                            }
                                        }
                                    } catch (\JsonException $e) {
                                        $runtimeConfigOk = false;
                                        $addError('stale_runtime_config_invalid', 'Stale-mode runtime config JSON is invalid: ' . $sourcePath . ' (' . $e->getMessage() . ')');
                                    }
                                }
                            }
                        }
                    }

                    if ($rootOk && $uriOk && $runtimeConfigOk) {
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
        $this->lastStatusRequestId = $requestId;
        if ($trustedNow) {
            $this->lastOkStatus = $status;
            $this->persistLastOkToDiskBestEffort($status);
        }

        return $status;
    }

    private static function currentRequestId(): ?string
    {
        // Only treat this as a "request context" when the runtime is actually serving HTTP.
        // In CLI processes `REQUEST_TIME_FLOAT` exists too, but it is constant for the whole process.
        if (!isset($_SERVER['REQUEST_METHOD'])) {
            return null;
        }

        $rt = $_SERVER['REQUEST_TIME_FLOAT'] ?? null;

        if (is_int($rt) || is_float($rt)) {
            return sprintf('%.6f', (float) $rt);
        }

        if (is_string($rt)) {
            $trimmed = trim($rt);
            if ($trimmed !== '' && is_numeric($trimmed)) {
                return sprintf('%.6f', (float) $trimmed);
            }
        }

        return null;
    }

    private function hydrateLastOkFromDiskIfAvailable(): void
    {
        $path = $this->lastOkStatePath;
        if ($path === null) {
            return;
        }

        clearstatcache(true, $path);
        if (!is_file($path)) {
            return;
        }

        $mtime = @filemtime($path);
        if (!is_int($mtime)) {
            return;
        }
        if ($this->lastOkStateMtime !== null && $this->lastOkStateMtime === $mtime) {
            return;
        }

        // Only consume a persisted "last OK" snapshot if the current runtime cannot modify it.
        // This prevents an attacker with runtime code execution from forging a stale-trust bypass by
        // writing a fake snapshot to disk.
        //
        // Note: root can always write, so treat uid=0 as "privileged writer" (safe to read).
        $euid = null;
        if (\function_exists('posix_geteuid')) {
            $euid = @posix_geteuid();
        }

        $dir = dirname($path);
        if (
            $this->effectiveEnforcement === 'strict'
            && (!is_int($euid) || $euid !== 0)
        ) {
            if (!is_int($euid)) {
                $this->lastOkStateMtime = $mtime;
                return;
            }

            // Reject when the runtime can modify the file or its directory.
            if (is_writable($path) || ($dir !== '' && is_writable($dir))) {
                $this->lastOkStateMtime = $mtime;
                return;
            }

            // Reject symlinks (swap attacks).
            if (is_link($path) || ($dir !== '' && is_link($dir))) {
                $this->lastOkStateMtime = $mtime;
                return;
            }

            // Reject if the runtime user owns the file or directory: even if currently read-only,
            // the owner can chmod it back and forge a stale-trust bypass.
            $ownerFile = @fileowner($path);
            $ownerDir = $dir !== '' ? @fileowner($dir) : false;
            if (!is_int($ownerFile) || $ownerFile === $euid) {
                $this->lastOkStateMtime = $mtime;
                return;
            }
            if ($dir !== '' && (!is_int($ownerDir) || $ownerDir === $euid)) {
                $this->lastOkStateMtime = $mtime;
                return;
            }

            // Reject world/group-writable files or directories.
            $permsFile = @fileperms($path);
            if (is_int($permsFile) && (($permsFile & 0o022) !== 0)) {
                $this->lastOkStateMtime = $mtime;
                return;
            }
            $permsDir = $dir !== '' ? @fileperms($dir) : false;
            if (is_int($permsDir) && (($permsDir & 0o022) !== 0)) {
                $this->lastOkStateMtime = $mtime;
                return;
            }
        }

        $raw = @file_get_contents($path);
        if ($raw === false) {
            $this->lastOkStateMtime = $mtime;
            return;
        }

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            $this->lastOkStateMtime = $mtime;
            return;
        }

        if (!is_array($decoded)) {
            $this->lastOkStateMtime = $mtime;
            return;
        }

        $version = $decoded['version'] ?? null;
        $chainId = $decoded['chain_id'] ?? null;
        $controller = $decoded['instance_controller'] ?? null;
        $lastOkAt = $decoded['last_ok_at'] ?? null;
        $runtimeConfigSha256 = $decoded['runtime_config_sha256'] ?? null;
        $snapshotRaw = $decoded['snapshot'] ?? null;

        if (!is_int($version) || $version !== 1) {
            $this->lastOkStateMtime = $mtime;
            return;
        }
        if (!is_int($chainId) || $chainId !== $this->config->chainId) {
            $this->lastOkStateMtime = $mtime;
            return;
        }
        if (!is_string($controller) || strtolower(trim($controller)) !== strtolower($this->config->instanceController)) {
            $this->lastOkStateMtime = $mtime;
            return;
        }
        if (!is_int($lastOkAt) || $lastOkAt <= 0) {
            $this->lastOkStateMtime = $mtime;
            return;
        }
        if (!is_array($snapshotRaw)) {
            $this->lastOkStateMtime = $mtime;
            return;
        }

        try {
            $snapshot = new InstanceControllerSnapshot(
                version: (int) ($snapshotRaw['version'] ?? 0),
                paused: (bool) ($snapshotRaw['paused'] ?? false),
                activeRoot: (string) ($snapshotRaw['active_root'] ?? ''),
                activeUriHash: (string) ($snapshotRaw['active_uri_hash'] ?? ''),
                activePolicyHash: (string) ($snapshotRaw['active_policy_hash'] ?? ''),
                pendingRoot: (string) ($snapshotRaw['pending_root'] ?? ''),
                pendingUriHash: (string) ($snapshotRaw['pending_uri_hash'] ?? ''),
                pendingPolicyHash: (string) ($snapshotRaw['pending_policy_hash'] ?? ''),
                pendingCreatedAt: (int) ($snapshotRaw['pending_created_at'] ?? 0),
                pendingTtlSec: (int) ($snapshotRaw['pending_ttl_sec'] ?? 0),
                genesisAt: (int) ($snapshotRaw['genesis_at'] ?? 0),
                lastUpgradeAt: (int) ($snapshotRaw['last_upgrade_at'] ?? 0),
            );
        } catch (\Throwable) {
            $this->lastOkStateMtime = $mtime;
            return;
        }

        // Prefer the newest persisted snapshot (in case multiple sources update it).
        if ($this->lastOkAt === null || $lastOkAt > $this->lastOkAt) {
            $this->lastOkAt = $lastOkAt;
            $this->lastOkRuntimeConfigSha256 = null;
            if (is_string($runtimeConfigSha256) && $runtimeConfigSha256 !== '') {
                try {
                    $this->lastOkRuntimeConfigSha256 = Bytes32::normalizeHex($runtimeConfigSha256);
                } catch (\Throwable) {
                    $this->lastOkRuntimeConfigSha256 = null;
                }
            }
            $this->lastOkStatus = new TrustKernelStatus(
                enforcement: $this->effectiveEnforcement,
                mode: $this->config->mode,
                maxStaleSec: $this->config->maxStaleSec,
                trustedNow: true,
                readAllowed: true,
                writeAllowed: true,
                rpcOkNow: true,
                paused: $snapshot->paused,
                snapshot: $snapshot,
                computedRoot: null,
                checkedAt: $lastOkAt,
                lastOkAt: $lastOkAt,
                errors: [],
                errorCodes: [],
            );
        }

        $this->lastOkStateMtime = $mtime;
    }

    private function persistLastOkToDiskBestEffort(TrustKernelStatus $status): void
    {
        $path = $this->lastOkStatePath;
        if ($path === null) {
            return;
        }

        if (!$status->trustedNow || $status->snapshot === null || $this->lastOkAt === null) {
            return;
        }

        $payload = [
            'version' => 1,
            'chain_id' => $this->config->chainId,
            'instance_controller' => $this->config->instanceController,
            'last_ok_at' => $this->lastOkAt,
            'runtime_config_sha256' => $this->config->runtimeConfigCanonicalSha256,
            'snapshot' => $status->snapshot->toArray(),
        ];

        try {
            $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            $this->logger?->warning('[trust-kernel] unable to persist last-ok snapshot (json): ' . $e->getMessage());
            return;
        }

        $dir = dirname($path);
        $base = basename($path);
        $tmp = $dir . DIRECTORY_SEPARATOR . '.' . $base . '.' . bin2hex(random_bytes(6)) . '.tmp';

        try {
            if (@file_put_contents($tmp, $json . "\n") === false) {
                return;
            }
            @chmod($tmp, 0644);
            if (!@rename($tmp, $path)) {
                @unlink($tmp);
                return;
            }
            $this->lastOkStateMtime = @filemtime($path) ?: $this->lastOkStateMtime;
        } catch (\Throwable) {
            @unlink($tmp);
        }
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
