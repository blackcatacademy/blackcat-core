<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

use Psr\Log\LoggerInterface;
use BlackCat\Core\Database;
use BlackCat\Core\Security\KeyManager;
use BlackCat\Core\Security\PhpRuntimeInspector;

final class TrustKernel
{
    private const LAST_OK_STATE_FILENAME = 'trust.last_ok.v1.json';

    private Web3RpcQuorumClient $rpc;
    private InstanceControllerReader $controller;
    private ReleaseRegistryReader $releaseRegistry;
    private LocalIntegrityVerifier $integrity;

    private ?IntegrityManifestV1 $manifest = null;
    private ?int $manifestMtime = null;

    /** @var null|list<array{code:string,message:string}> Cached controller code sanity errors (null = not checked yet / transient failure). */
    private ?array $controllerCodeSanityCachedErrors = null;

    private ?string $phpFingerprintCachedSha256 = null;

    private ?string $composerLockCachedSha256 = null;
    private ?int $composerLockCachedMtime = null;
    private ?int $composerLockCachedSize = null;
    private ?int $composerLockCachedCtime = null;
    private ?int $composerLockCachedInode = null;

    private ?string $imageDigestCachedSha256 = null;
    private ?int $imageDigestCachedMtime = null;
    private ?int $imageDigestCachedSize = null;
    private ?int $imageDigestCachedCtime = null;
    private ?int $imageDigestCachedInode = null;

    private ?TrustKernelStatus $lastStatus = null;
    private ?int $lastStatusAt = null;
    private ?string $lastStatusRequestId = null;

    private ?TrustKernelStatus $lastOkStatus = null;
    private ?int $lastOkAt = null;

    private ?string $lastOkRuntimeConfigSha256 = null;
    private ?string $lastOkHttpAllowedHostsSha256 = null;
    private ?string $lastOkComposerLockSha256 = null;
    private ?string $lastOkPhpFingerprintSha256 = null;
    private ?string $lastOkImageDigestSha256 = null;

    private ?string $lastOkStatePath = null;
    private ?int $lastOkStateMtime = null;

    /** @var 'strict'|'warn' */
    private string $effectiveEnforcement = 'strict';
    private bool $warnBannerEmitted = false;
    private bool $phpHardeningWarnEmitted = false;
    private bool $runtimeDoctorWarnEmitted = false;

    private bool $runtimeDoctorPhpChecked = false;
    private bool $runtimeDoctorPhpAvailable = false;
    private ?string $runtimeDoctorPhpError = null;

    /** @var list<array{severity:'info'|'warn'|'error',code:string,message:string}> */
    private array $runtimeDoctorPhpFindings = [];

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

    public function instanceControllerAddress(): string
    {
        return $this->config->instanceController;
    }

    public function installGuards(): void
    {
        $alreadyLocked = KeyManager::isAccessGuardLocked()
            || Database::isReadGuardLocked()
            || Database::isWriteGuardLocked()
            || Database::isPdoAccessGuardLocked();

        if ($alreadyLocked) {
            if (
                KeyManager::isAccessGuardLocked()
                && Database::isReadGuardLocked()
                && Database::isWriteGuardLocked()
                && Database::isPdoAccessGuardLocked()
            ) {
                if (!KeyManager::hasAccessGuard() || !Database::hasReadGuard() || !Database::hasWriteGuard() || !Database::hasPdoAccessGuard()) {
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

        Database::setReadGuard(function (string $sql): void {
            $this->assertReadAllowed('db.read');
        });

        // Prevent bypass: raw PDO access would skip kernel guards (SQL comment guard, write guard, etc.).
        Database::setPdoAccessGuard(function (string $context): void {
            $this->denyBypass($context);
        });

        // Hard lock: prevent runtime code from disabling guards after bootstrap.
        KeyManager::lockAccessGuard();
        Database::lockReadGuard();
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
        $integrityOk = true;
        $probeReleaseRegistry = null;
        /** @var array<string,array{value:string,locked:bool}> $probeAttestations */
        $probeAttestations = [];
        $computedComposerLockSha256 = null;
        $computedPhpFingerprintSha256 = null;
        $computedImageDigestSha256 = null;

        try {
            // First stage: fetch only snapshot + releaseRegistry pointer.
            // Attestation keys are probed later *only if required by the active policy* to keep
            // RPC surface minimal and avoid unnecessary calls in tests / legacy policies.
            $probe = $this->controller->kernelProbe($this->config->instanceController, []);
            $snapshot = $probe['snapshot'] ?? null;
            $probeReleaseRegistry = $probe['release_registry'] ?? null;
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
            $runtimeConfigAttestationKeyForCheck = null;
            $requiresHttpAllowedHostsAttestation = false;
            $requiresComposerLockAttestation = false;
            $requiresPhpFingerprintAttestation = false;
            $requiresImageDigestAttestation = false;
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
                $runtimeConfigAttestationKeyForCheck = $this->config->runtimeConfigAttestationKey;
            } elseif (hash_equals(Bytes32::normalizeHex($this->config->policyHashV3Warn), $activePolicyHash)) {
                $policyOk = true;
                $derivedEnforcement = 'warn';
                $requiresRuntimeConfigAttestation = true;
                $runtimeConfigAttestationKeyForCheck = $this->config->runtimeConfigAttestationKey;
            } elseif (hash_equals(Bytes32::normalizeHex($this->config->policyHashV3StrictV2), $activePolicyHash)) {
                $policyOk = true;
                $derivedEnforcement = 'strict';
                $requiresRuntimeConfigAttestation = true;
                $runtimeConfigAttestationKeyForCheck = $this->config->runtimeConfigAttestationKeyV2;
            } elseif (hash_equals(Bytes32::normalizeHex($this->config->policyHashV3WarnV2), $activePolicyHash)) {
                $policyOk = true;
                $derivedEnforcement = 'warn';
                $requiresRuntimeConfigAttestation = true;
                $runtimeConfigAttestationKeyForCheck = $this->config->runtimeConfigAttestationKeyV2;
            } elseif (hash_equals(Bytes32::normalizeHex($this->config->policyHashV4Strict), $activePolicyHash)) {
                $policyOk = true;
                $derivedEnforcement = 'strict';
                $requiresRuntimeConfigAttestation = true;
                $runtimeConfigAttestationKeyForCheck = $this->config->runtimeConfigAttestationKey;
                $requiresComposerLockAttestation = true;
                $requiresPhpFingerprintAttestation = true;
                $requiresImageDigestAttestation = true;
            } elseif (hash_equals(Bytes32::normalizeHex($this->config->policyHashV4Warn), $activePolicyHash)) {
                $policyOk = true;
                $derivedEnforcement = 'warn';
                $requiresRuntimeConfigAttestation = true;
                $runtimeConfigAttestationKeyForCheck = $this->config->runtimeConfigAttestationKey;
                $requiresComposerLockAttestation = true;
                $requiresPhpFingerprintAttestation = true;
                $requiresImageDigestAttestation = true;
            } elseif (hash_equals(Bytes32::normalizeHex($this->config->policyHashV4StrictV2), $activePolicyHash)) {
                $policyOk = true;
                $derivedEnforcement = 'strict';
                $requiresRuntimeConfigAttestation = true;
                $runtimeConfigAttestationKeyForCheck = $this->config->runtimeConfigAttestationKeyV2;
                $requiresComposerLockAttestation = true;
                $requiresPhpFingerprintAttestation = true;
                $requiresImageDigestAttestation = true;
            } elseif (hash_equals(Bytes32::normalizeHex($this->config->policyHashV4WarnV2), $activePolicyHash)) {
                $policyOk = true;
                $derivedEnforcement = 'warn';
                $requiresRuntimeConfigAttestation = true;
                $runtimeConfigAttestationKeyForCheck = $this->config->runtimeConfigAttestationKeyV2;
                $requiresComposerLockAttestation = true;
                $requiresPhpFingerprintAttestation = true;
                $requiresImageDigestAttestation = true;
            } elseif (hash_equals(Bytes32::normalizeHex($this->config->policyHashV5Strict), $activePolicyHash)) {
                $policyOk = true;
                $derivedEnforcement = 'strict';
                $requiresRuntimeConfigAttestation = true;
                $runtimeConfigAttestationKeyForCheck = $this->config->runtimeConfigAttestationKey;
                $requiresHttpAllowedHostsAttestation = true;
                $requiresComposerLockAttestation = true;
                $requiresPhpFingerprintAttestation = true;
                $requiresImageDigestAttestation = true;
            } elseif (hash_equals(Bytes32::normalizeHex($this->config->policyHashV5Warn), $activePolicyHash)) {
                $policyOk = true;
                $derivedEnforcement = 'warn';
                $requiresRuntimeConfigAttestation = true;
                $runtimeConfigAttestationKeyForCheck = $this->config->runtimeConfigAttestationKey;
                $requiresHttpAllowedHostsAttestation = true;
                $requiresComposerLockAttestation = true;
                $requiresPhpFingerprintAttestation = true;
                $requiresImageDigestAttestation = true;
            } elseif (hash_equals(Bytes32::normalizeHex($this->config->policyHashV5StrictV2), $activePolicyHash)) {
                $policyOk = true;
                $derivedEnforcement = 'strict';
                $requiresRuntimeConfigAttestation = true;
                $runtimeConfigAttestationKeyForCheck = $this->config->runtimeConfigAttestationKeyV2;
                $requiresHttpAllowedHostsAttestation = true;
                $requiresComposerLockAttestation = true;
                $requiresPhpFingerprintAttestation = true;
                $requiresImageDigestAttestation = true;
            } elseif (hash_equals(Bytes32::normalizeHex($this->config->policyHashV5WarnV2), $activePolicyHash)) {
                $policyOk = true;
                $derivedEnforcement = 'warn';
                $requiresRuntimeConfigAttestation = true;
                $runtimeConfigAttestationKeyForCheck = $this->config->runtimeConfigAttestationKeyV2;
                $requiresHttpAllowedHostsAttestation = true;
                $requiresComposerLockAttestation = true;
                $requiresPhpFingerprintAttestation = true;
                $requiresImageDigestAttestation = true;
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

            // PHP runtime hardening gate (strict-by-default).
            // In strict mode we fail-closed on insecure PHP/ini posture.
            // In warn mode we emit loud warnings but do not block.
            //
            // This is evaluated only for HTTP request contexts to avoid breaking CLI tooling/tests.
            if ($requestId !== null && PHP_SAPI !== 'cli') {
                $usedDoctor = false;

                // Prefer blackcat-config RuntimeDoctor when available (centralized runtime hardening checks).
                // Fallback to blackcat-core PhpRuntimeInspector when RuntimeDoctor is not installed.
                try {
                    $doctorFindings = $this->runtimeDoctorPhpFindingsOrNull();
                    if ($doctorFindings !== null) {
                        $usedDoctor = true;

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

                        foreach ($doctorFindings as $f) {
                            $code = $f['code'];
                            $severity = $f['severity'];
                            $message = $f['message'];

                            $isFatal = ($severity === 'error') || isset($fatalStrict[$code]);

                            if ($this->effectiveEnforcement === 'strict' && $isFatal) {
                                $addError('runtime_doctor_' . $code, 'Runtime hardening violation: ' . $code);
                                continue;
                            }

                            if ($this->effectiveEnforcement === 'warn') {
                                if ($isFatal || $severity !== 'info') {
                                    if (!$this->runtimeDoctorWarnEmitted) {
                                        $this->runtimeDoctorWarnEmitted = true;
                                        $this->logger?->warning('[trust-kernel] WARNING: Runtime hardening findings present (dev/warn policy). Do not use this policy in production.');
                                    }

                                    $line = '[trust-kernel] runtime hardening: ' . $code;
                                    if (trim($message) !== '') {
                                        $line .= ' - ' . trim($message);
                                    }
                                    $this->logger?->warning($line);
                                    @error_log($line);
                                }
                            }
                        }
                    }
                } catch (\Throwable $e) {
                    if ($this->effectiveEnforcement === 'strict') {
                        $addError('runtime_doctor_failed', 'Runtime doctor failed: ' . $e->getMessage());
                    } else {
                        $this->logger?->warning('[trust-kernel] runtime doctor failed: ' . $e->getMessage());
                        @error_log('[trust-kernel] runtime doctor failed: ' . $e->getMessage());
                    }
                }

                if (!$usedDoctor) {
                    $fatalStrict = [
                        // Explicitly required hardening controls:
                        'allow_url_include_enabled' => true,
                        'phar_readonly_disabled' => true,
                        'dangerous_functions_not_disabled' => true,
                        'open_basedir_unset' => true,
                        'cgi_fix_pathinfo_enabled' => true,
                        'enable_dl_enabled' => true,
                        'auto_prepend_file_set' => true,
                        'auto_append_file_set' => true,

                        // Web3 transport must exist.
                        'no_transport_for_web3' => true,
                    ];

                    try {
                        $report = PhpRuntimeInspector::inspect();
                        $findings = $report['findings'] ?? null;
                        if (is_array($findings)) {
                            foreach ($findings as $f) {
                                if (!is_array($f)) {
                                    continue;
                                }
                                $code = $f['code'] ?? null;
                                $severity = $f['severity'] ?? null;
                                $message = $f['message'] ?? null;

                                if (!is_string($code) || $code === '' || str_contains($code, "\0")) {
                                    continue;
                                }
                                if (!is_string($severity) || !in_array($severity, ['info', 'warn', 'error'], true)) {
                                    $severity = 'warn';
                                }

                                $isFatal = ($severity === 'error') || isset($fatalStrict[$code]);

                                if ($this->effectiveEnforcement === 'strict' && $isFatal) {
                                    $addError('php_runtime_' . $code, 'PHP runtime hardening violation: ' . $code);
                                    continue;
                                }

                                if ($this->effectiveEnforcement === 'warn') {
                                    if ($isFatal || $severity !== 'info') {
                                        if (!$this->phpHardeningWarnEmitted) {
                                            $this->phpHardeningWarnEmitted = true;
                                            $this->logger?->warning('[trust-kernel] WARNING: PHP hardening findings present (dev/warn policy). Do not use this policy in production.');
                                        }

                                        $line = '[trust-kernel] php hardening: ' . $code;
                                        if (is_string($message) && trim($message) !== '') {
                                            $line .= ' - ' . trim($message);
                                        }
                                        $this->logger?->warning($line);
                                        @error_log($line);
                                    }
                                }
                            }
                        }
                    } catch (\Throwable $e) {
                        if ($this->effectiveEnforcement === 'strict') {
                            $addError('php_runtime_inspect_failed', 'PHP runtime hardening inspection failed.');
                        } else {
                            $this->logger?->warning('[trust-kernel] php runtime inspect failed: ' . $e->getMessage());
                            @error_log('[trust-kernel] php runtime inspect failed: ' . $e->getMessage());
                        }
                    }
                }
            }

            try {
                $integrityOk = true;
                $manifest = $this->loadManifestIfNeeded();
                $computedRoot = $this->config->mode === 'full'
                    ? $this->integrity->computeAndVerifyRootStrict($manifest)
                    : $this->integrity->computeAndVerifyRoot($manifest);

                $activeRoot = Bytes32::normalizeHex($snapshot->activeRoot);
                $computedRootNorm = Bytes32::normalizeHex($computedRoot);
                if (!hash_equals($activeRoot, $computedRootNorm)) {
                    $integrityOk = false;
                    $addError('integrity_root_mismatch', 'Integrity root mismatch.');
                }

                $activeUriHash = Bytes32::normalizeHex($snapshot->activeUriHash);
                $manifestUriHash = $manifest->uriHashBytes32();
                $zero = '0x' . str_repeat('00', 32);

                // URI hash is part of the on-chain snapshot. If the chain commits to a non-zero URI hash,
                // the local manifest must provide a matching `uri` (do NOT allow skipping by removing it).
                if ($activeUriHash === $zero) {
                    if ($manifestUriHash !== null) {
                        $integrityOk = false;
                        $addError('uri_hash_mismatch', 'URI hash mismatch.');
                    }
                } else {
                    if ($manifestUriHash === null) {
                        $integrityOk = false;
                        $addError('uri_hash_missing', 'URI hash is missing from integrity manifest.');
                    } else {
                        $expectedUriHash = Bytes32::normalizeHex($manifestUriHash);
                        if (!hash_equals($expectedUriHash, $activeUriHash)) {
                            $integrityOk = false;
                            $addError('uri_hash_mismatch', 'URI hash mismatch.');
                        }
                    }
                }
            } catch (IntegrityViolationException $e) {
                $integrityOk = false;
                $addError($e->violationCode, $e->getMessage());
            } catch (\Throwable $e) {
                $integrityOk = false;
                $addError('integrity_check_failed', $e->getMessage());
            }

            // If local integrity is already broken (tamper or mismatch), skip further on-chain
            // provenance checks to reduce load and avoid turning integrity failures into an RPC DoS vector.
            if (!$integrityOk) {
                $trustedNow = false;
            } else {
            // Probe required policy attestations only after local integrity passed.
            $requiredAttestationKeys = [];
            if ($requiresRuntimeConfigAttestation) {
                $requiredAttestationKeys[] = $runtimeConfigAttestationKeyForCheck ?? $this->config->runtimeConfigAttestationKey;
            }
            if ($requiresHttpAllowedHostsAttestation) {
                $requiredAttestationKeys[] = $this->config->httpAllowedHostsAttestationKeyV1;
            }
            if ($requiresComposerLockAttestation) {
                $requiredAttestationKeys[] = $this->config->composerLockAttestationKeyV1;
            }
            if ($requiresPhpFingerprintAttestation) {
                $requiredAttestationKeys[] = $this->config->phpFingerprintAttestationKeyV2;
            }
            if ($requiresImageDigestAttestation) {
                $requiredAttestationKeys[] = $this->config->imageDigestAttestationKeyV1;
            }

            if ($requiredAttestationKeys !== []) {
                try {
                    $probe2 = $this->controller->kernelProbe($this->config->instanceController, $requiredAttestationKeys);
                    $att = $probe2['attestations'] ?? null;
                    if (is_array($att)) {
                        /** @var array<string,array{value:string,locked:bool}> $att */
                        $probeAttestations = $att;
                    }
                    $probeReleaseRegistry = is_string($probe2['release_registry'] ?? null) ? (string) $probe2['release_registry'] : $probeReleaseRegistry;
                } catch (\Throwable $e) {
                    $addError('rpc_error', $e->getMessage());
                    $rpcOkNow = false;
                }
            }

            // Optional hardening (policy v3): bind runtime config to on-chain attestation.
            if ($requiresRuntimeConfigAttestation) {
                try {
                    $expected = $this->config->runtimeConfigCanonicalSha256;
                    $sourcePath = $this->config->runtimeConfigSourcePath;

                    if ($expected === null || $sourcePath === null) {
                        $addError('runtime_config_commitment_missing', 'Runtime config commitment is not available (missing sourcePath).');
                    } else {
                        $keyRaw = $runtimeConfigAttestationKeyForCheck ?? $this->config->runtimeConfigAttestationKey;
                        $key = Bytes32::normalizeHex($keyRaw);
                        $expectedNorm = Bytes32::normalizeHex($expected);

                        // Detect runtime config tamper: the on-disk file must remain equal to the config used for boot.
                        $maxBytes = 8 * 1024 * 1024; // 8 MiB
                        $res = self::tryReadCanonicalJsonFileSha256Bytes32($sourcePath, $maxBytes);
                        if (!$res['ok']) {
                            $message = $res['message'];
                            if ($message === '') {
                                $message = 'Runtime config file could not be validated: ' . $sourcePath;
                            }
                            if ($res['error'] === 'symlink') {
                                $addError('runtime_config_source_symlink', 'Runtime config file must not be a symlink: ' . $sourcePath);
                            } elseif ($res['error'] === 'too_large') {
                                $addError('runtime_config_source_too_large', 'Runtime config file is too large: ' . $sourcePath);
                            } elseif ($res['error'] === 'invalid') {
                                $addError('runtime_config_source_invalid', 'Runtime config file JSON is invalid: ' . $sourcePath . ($message !== '' ? (' (' . $message . ')') : ''));
                            } elseif ($res['error'] === 'changed') {
                                $addError('runtime_config_source_changed', 'Runtime config file changed while reading (restart required).');
                            } else {
                                $addError('runtime_config_source_unreadable', 'Runtime config file is not readable: ' . $sourcePath);
                            }
                        } else {
                            $current = $res['sha'];
                            if (!hash_equals($expectedNorm, Bytes32::normalizeHex($current))) {
                                $addError('runtime_config_source_changed', 'Runtime config file differs from the booted config (restart required).');
                            }
                        }

                        $att = $probeAttestations[$key] ?? null;
                        if (!is_array($att) || !isset($att['value'], $att['locked']) || !is_string($att['value']) || !is_bool($att['locked'])) {
                            $addError('runtime_config_attestation_failed', 'Runtime config attestation value is not available.');
                        } else {
                            $onChain = Bytes32::normalizeHex($att['value']);

                            if (!hash_equals($expectedNorm, $onChain)) {
                                $addError('runtime_config_commitment_mismatch', 'Runtime config commitment mismatch.');
                            }

                            if (!$att['locked']) {
                                $addError('runtime_config_commitment_unlocked', 'Runtime config commitment key is not locked.');
                            }
                        }
                    }
                } catch (\Throwable $e) {
                    $addError('runtime_config_attestation_failed', 'Runtime config attestation check failed: ' . $e->getMessage());
                }
            }

            // Optional hardening (policy v5): bind http.allowed_hosts via on-chain attestation.
            if ($requiresHttpAllowedHostsAttestation) {
                try {
                    $expected = $this->config->httpAllowedHostsCanonicalSha256;
                    if ($expected === null) {
                        $addError('http_allowed_hosts_commitment_missing', 'HTTP allowed hosts commitment is not available.');
                    } else {
                        $key = Bytes32::normalizeHex($this->config->httpAllowedHostsAttestationKeyV1);
                        $expectedNorm = Bytes32::normalizeHex($expected);

                        $att = $probeAttestations[$key] ?? null;
                        if (!is_array($att) || !isset($att['value'], $att['locked']) || !is_string($att['value']) || !is_bool($att['locked'])) {
                            $addError('http_allowed_hosts_attestation_failed', 'HTTP allowed hosts attestation value is not available.');
                        } else {
                            $onChain = Bytes32::normalizeHex($att['value']);
                            if (!hash_equals($expectedNorm, $onChain)) {
                                $addError('http_allowed_hosts_commitment_mismatch', 'HTTP allowed hosts commitment mismatch.');
                            }
                            if (!$att['locked']) {
                                $addError('http_allowed_hosts_commitment_unlocked', 'HTTP allowed hosts commitment key is not locked.');
                            }
                        }
                    }
                } catch (\Throwable $e) {
                    $addError('http_allowed_hosts_attestation_failed', 'HTTP allowed hosts attestation check failed: ' . $e->getMessage());
                }
            }

            // Optional hardening (policy v4): bind additional provenance attestations.
            if ($requiresComposerLockAttestation || $requiresPhpFingerprintAttestation || $requiresImageDigestAttestation) {
                try {
                    if ($requiresComposerLockAttestation) {
                        $computedComposerLockSha256 = $this->computeComposerLockSha256Bytes32OrThrow();

                        $key = Bytes32::normalizeHex($this->config->composerLockAttestationKeyV1);
                        $att = $probeAttestations[$key] ?? null;
                        if (!is_array($att) || !isset($att['value'], $att['locked']) || !is_string($att['value']) || !is_bool($att['locked'])) {
                            $addError('composer_lock_attestation_failed', 'composer.lock attestation value is not available.');
                        } else {
                            $onChain = Bytes32::normalizeHex($att['value']);
                            if (!hash_equals(Bytes32::normalizeHex($computedComposerLockSha256), $onChain)) {
                                $addError('composer_lock_commitment_mismatch', 'composer.lock commitment mismatch.');
                            }
                            if (!$att['locked']) {
                                $addError('composer_lock_commitment_unlocked', 'composer.lock commitment key is not locked.');
                            }
                        }
                    }

                    if ($requiresPhpFingerprintAttestation) {
                        $computedPhpFingerprintSha256 = $this->computePhpFingerprintSha256Bytes32();

                        $key = Bytes32::normalizeHex($this->config->phpFingerprintAttestationKeyV2);
                        $att = $probeAttestations[$key] ?? null;
                        if (!is_array($att) || !isset($att['value'], $att['locked']) || !is_string($att['value']) || !is_bool($att['locked'])) {
                            $addError('php_fingerprint_attestation_failed', 'PHP fingerprint attestation value is not available.');
                        } else {
                            $onChain = Bytes32::normalizeHex($att['value']);
                            if (!hash_equals(Bytes32::normalizeHex($computedPhpFingerprintSha256), $onChain)) {
                                $addError('php_fingerprint_commitment_mismatch', 'PHP fingerprint commitment mismatch.');
                            }
                            if (!$att['locked']) {
                                $addError('php_fingerprint_commitment_unlocked', 'PHP fingerprint commitment key is not locked.');
                            }
                        }
                    }

                    if ($requiresImageDigestAttestation) {
                        $computedImageDigestSha256 = $this->readImageDigestSha256Bytes32OrThrow();

                        $key = Bytes32::normalizeHex($this->config->imageDigestAttestationKeyV1);
                        $att = $probeAttestations[$key] ?? null;
                        if (!is_array($att) || !isset($att['value'], $att['locked']) || !is_string($att['value']) || !is_bool($att['locked'])) {
                            $addError('image_digest_attestation_failed', 'Image digest attestation value is not available.');
                        } else {
                            $onChain = Bytes32::normalizeHex($att['value']);
                            if (!hash_equals(Bytes32::normalizeHex($computedImageDigestSha256), $onChain)) {
                                $addError('image_digest_commitment_mismatch', 'Image digest commitment mismatch.');
                            }
                            if (!$att['locked']) {
                                $addError('image_digest_commitment_unlocked', 'Image digest commitment key is not locked.');
                            }
                        }
                    }
                } catch (\Throwable $e) {
                    $addError('policy_v4_attestation_failed', 'Policy v4 attestation check failed: ' . $e->getMessage());
                }
            }

            // ReleaseRegistry trust check:
            // - the source of truth is the on-chain pointer stored in the InstanceController
            // - runtime config may additionally *pin* the expected registry address (optional)
            try {
                $rrOnController = is_string($probeReleaseRegistry) ? strtolower($probeReleaseRegistry) : strtolower($this->controller->releaseRegistry($this->config->instanceController));
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
            // Run this only in non-request contexts (CLI runner) to avoid per-request RPC overhead.
            if ($requestId === null) {
                $this->checkControllerCodeSanityCached($addError);
            }

            $trustedNow = $errors === [];
            if ($trustedNow) {
                $this->lastOkAt = $now;
            }
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
                    $extraOk = true;

                    $requiresRuntimeConfig = false;
                    $requiresV4Extra = false;
                    $requiresHttpAllowedHosts = false;

                    $lastOkPolicyHash = $this->lastOkStatus->snapshot?->activePolicyHash;
                    if (is_string($lastOkPolicyHash) && trim($lastOkPolicyHash) !== '') {
                        $policyNorm = Bytes32::normalizeHex($lastOkPolicyHash);

                        $v3 = [
                            Bytes32::normalizeHex($this->config->policyHashV3Strict),
                            Bytes32::normalizeHex($this->config->policyHashV3Warn),
                            Bytes32::normalizeHex($this->config->policyHashV3StrictV2),
                            Bytes32::normalizeHex($this->config->policyHashV3WarnV2),
                        ];
                        foreach ($v3 as $h) {
                            if (hash_equals($h, $policyNorm)) {
                                $requiresRuntimeConfig = true;
                                break;
                            }
                        }

                        $v4 = [
                            Bytes32::normalizeHex($this->config->policyHashV4Strict),
                            Bytes32::normalizeHex($this->config->policyHashV4Warn),
                            Bytes32::normalizeHex($this->config->policyHashV4StrictV2),
                            Bytes32::normalizeHex($this->config->policyHashV4WarnV2),
                        ];
                        foreach ($v4 as $h) {
                            if (hash_equals($h, $policyNorm)) {
                                $requiresRuntimeConfig = true;
                                $requiresV4Extra = true;
                                break;
                            }
                        }

                        $v5 = [
                            Bytes32::normalizeHex($this->config->policyHashV5Strict),
                            Bytes32::normalizeHex($this->config->policyHashV5Warn),
                            Bytes32::normalizeHex($this->config->policyHashV5StrictV2),
                            Bytes32::normalizeHex($this->config->policyHashV5WarnV2),
                        ];
                        foreach ($v5 as $h) {
                            if (hash_equals($h, $policyNorm)) {
                                $requiresRuntimeConfig = true;
                                $requiresV4Extra = true;
                                $requiresHttpAllowedHosts = true;
                                break;
                            }
                        }
                    }

                    if ($requiresRuntimeConfig) {
                        $expectedCfgSha = $this->lastOkRuntimeConfigSha256;
                        $sourcePath = $this->config->runtimeConfigSourcePath;
                        if ($expectedCfgSha === null || !is_string($sourcePath) || $sourcePath === '' || !is_file($sourcePath)) {
                            $runtimeConfigOk = false;
                            $addError('stale_runtime_config_missing', 'Stale-mode runtime config commitment is not available.');
                        } else {
                            $maxBytes = 8 * 1024 * 1024; // 8 MiB
                            $res = self::tryReadCanonicalJsonFileSha256Bytes32($sourcePath, $maxBytes);
                            if (!$res['ok']) {
                                $runtimeConfigOk = false;
                                if ($res['error'] === 'symlink') {
                                    $addError('stale_runtime_config_symlink', 'Stale-mode runtime config file must not be a symlink: ' . $sourcePath);
                                } elseif ($res['error'] === 'too_large') {
                                    $addError('stale_runtime_config_too_large', 'Stale-mode runtime config file is too large: ' . $sourcePath);
                                } elseif ($res['error'] === 'invalid') {
                                    $addError('stale_runtime_config_invalid', 'Stale-mode runtime config JSON is invalid: ' . $sourcePath);
                                } else {
                                    $addError('stale_runtime_config_unreadable', 'Stale-mode runtime config file is not readable: ' . $sourcePath);
                                }
                            } else {
                                $currentCfgSha = $res['sha'];
                                $runtimeConfigOk = hash_equals(Bytes32::normalizeHex($expectedCfgSha), Bytes32::normalizeHex($currentCfgSha));
                                if (!$runtimeConfigOk) {
                                    $addError('stale_runtime_config_mismatch', 'Stale-mode runtime config commitment mismatch.');
                                }
                            }
                        }
                    }

                    if ($requiresV4Extra) {
                        $expectedComposer = $this->lastOkComposerLockSha256;
                        if ($expectedComposer === null) {
                            $extraOk = false;
                            $addError('stale_composer_lock_missing', 'Stale-mode composer.lock commitment is not available.');
                        } else {
                            try {
                                $current = $this->computeComposerLockSha256Bytes32OrThrow();
                                if (!hash_equals(Bytes32::normalizeHex($expectedComposer), Bytes32::normalizeHex($current))) {
                                    $extraOk = false;
                                    $addError('stale_composer_lock_mismatch', 'Stale-mode composer.lock commitment mismatch.');
                                }
                            } catch (\Throwable $e) {
                                $extraOk = false;
                                $addError('stale_composer_lock_failed', 'Stale-mode composer.lock check failed: ' . $e->getMessage());
                            }
                        }

                        $expectedPhp = $this->lastOkPhpFingerprintSha256;
                        if ($expectedPhp === null) {
                            $extraOk = false;
                            $addError('stale_php_fingerprint_missing', 'Stale-mode PHP fingerprint commitment is not available.');
                        } else {
                            try {
                                $current = $this->computePhpFingerprintSha256Bytes32();
                                if (!hash_equals(Bytes32::normalizeHex($expectedPhp), Bytes32::normalizeHex($current))) {
                                    $extraOk = false;
                                    $addError('stale_php_fingerprint_mismatch', 'Stale-mode PHP fingerprint commitment mismatch.');
                                }
                            } catch (\Throwable $e) {
                                $extraOk = false;
                                $addError('stale_php_fingerprint_failed', 'Stale-mode PHP fingerprint check failed: ' . $e->getMessage());
                            }
                        }

                        $expectedImage = $this->lastOkImageDigestSha256;
                        if ($expectedImage === null) {
                            $extraOk = false;
                            $addError('stale_image_digest_missing', 'Stale-mode image digest commitment is not available.');
                        } else {
                            try {
                                $current = $this->readImageDigestSha256Bytes32OrThrow();
                                if (!hash_equals(Bytes32::normalizeHex($expectedImage), Bytes32::normalizeHex($current))) {
                                    $extraOk = false;
                                    $addError('stale_image_digest_mismatch', 'Stale-mode image digest commitment mismatch.');
                                }
                            } catch (\Throwable $e) {
                                $extraOk = false;
                                $addError('stale_image_digest_failed', 'Stale-mode image digest check failed: ' . $e->getMessage());
                            }
                        }
                    }

                    if ($requiresHttpAllowedHosts) {
                        $expectedHosts = $this->lastOkHttpAllowedHostsSha256;
                        if ($expectedHosts === null) {
                            $extraOk = false;
                            $addError('stale_http_allowed_hosts_missing', 'Stale-mode HTTP allowed hosts commitment is not available.');
                        } else {
                            try {
                                $current = $this->config->httpAllowedHostsCanonicalSha256;
                                if ($current === null || !hash_equals(Bytes32::normalizeHex($expectedHosts), Bytes32::normalizeHex($current))) {
                                    $extraOk = false;
                                    $addError('stale_http_allowed_hosts_mismatch', 'Stale-mode HTTP allowed hosts commitment mismatch.');
                                }
                            } catch (\Throwable $e) {
                                $extraOk = false;
                                $addError('stale_http_allowed_hosts_failed', 'Stale-mode HTTP allowed hosts check failed: ' . $e->getMessage());
                            }
                        }
                    }

                    if ($rootOk && $uriOk && $runtimeConfigOk && $extraOk) {
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
            $this->lastOkRuntimeConfigSha256 = null;
            if (is_string($this->config->runtimeConfigCanonicalSha256) && $this->config->runtimeConfigCanonicalSha256 !== '') {
                try {
                    $this->lastOkRuntimeConfigSha256 = Bytes32::normalizeHex($this->config->runtimeConfigCanonicalSha256);
                } catch (\Throwable) {
                    $this->lastOkRuntimeConfigSha256 = null;
                }
            }

            $this->lastOkComposerLockSha256 = is_string($computedComposerLockSha256) ? Bytes32::normalizeHex($computedComposerLockSha256) : null;
            $this->lastOkPhpFingerprintSha256 = is_string($computedPhpFingerprintSha256) ? Bytes32::normalizeHex($computedPhpFingerprintSha256) : null;
            $this->lastOkImageDigestSha256 = is_string($computedImageDigestSha256) ? Bytes32::normalizeHex($computedImageDigestSha256) : null;
            $this->lastOkHttpAllowedHostsSha256 = is_string($this->config->httpAllowedHostsCanonicalSha256) && $this->config->httpAllowedHostsCanonicalSha256 !== ''
                ? Bytes32::normalizeHex($this->config->httpAllowedHostsCanonicalSha256)
                : null;

            $this->persistLastOkToDiskBestEffort($status);
        }

        return $status;
    }

    /**
     * Perform (and cache) InstanceController code sanity checks.
     *
     * The controller code is immutable; after a successful read, cache the resulting errors list:
     * - []  => OK, do not call RPC again for this check
     * - [..] => persistent failure, report without repeated RPC
     *
     * On transient RPC failures, do not cache so the next check can retry.
     *
     * @param callable(string,string):void $addError
     */
    private function checkControllerCodeSanityCached(callable $addError): void
    {
        if ($this->controllerCodeSanityCachedErrors !== null) {
            foreach ($this->controllerCodeSanityCachedErrors as $err) {
                $addError($err['code'], $err['message']);
            }
            return;
        }

        try {
            $errors = [];

            $code = $this->rpc->ethGetCodeQuorum($this->config->instanceController, 'latest');
            $proxyImpl = self::tryParseEip1167Implementation($code);
            if ($proxyImpl !== null) {
                $implCode = $this->rpc->ethGetCodeQuorum($proxyImpl, 'latest');
                if ($implCode === '0x' || $implCode === '0x0') {
                    $errors[] = [
                        'code' => 'controller_impl_no_code',
                        'message' => 'InstanceController EIP-1167 implementation has no code.',
                    ];
                }
            } else {
                if ($code === '0x' || $code === '0x0') {
                    $errors[] = [
                        'code' => 'controller_no_code',
                        'message' => 'InstanceController has no code.',
                    ];
                }
            }

            // Cache only after a successful RPC read.
            $this->controllerCodeSanityCachedErrors = $errors;

            foreach ($errors as $err) {
                $addError($err['code'], $err['message']);
            }
        } catch (\Throwable $e) {
            $addError('controller_code_sanity_failed', 'InstanceController code sanity check failed: ' . $e->getMessage());
        }
    }

    private function computeComposerLockSha256Bytes32OrThrow(): string
    {
        $rootDir = $this->config->integrityRootDir;
        $rootDir = rtrim(trim($rootDir), "/\\");
        if ($rootDir === '' || str_contains($rootDir, "\0")) {
            throw new TrustKernelException('Integrity root dir is invalid.');
        }

        $path = $rootDir . DIRECTORY_SEPARATOR . 'composer.lock';
        if (self::isSymlinkPath($path)) {
            throw new TrustKernelException('composer.lock must not be a symlink.');
        }

        $metaCacheKey = self::tryReadFileCacheMeta($path);
        if (
            $this->composerLockCachedSha256 !== null
            && $this->composerLockCachedMtime !== null
            && $this->composerLockCachedSize !== null
            && $this->composerLockCachedCtime !== null
            && $this->composerLockCachedInode !== null
            && $metaCacheKey !== null
        ) {
            if (
                $metaCacheKey['mtime'] === $this->composerLockCachedMtime
                && $metaCacheKey['size'] === $this->composerLockCachedSize
                && $metaCacheKey['ctime'] === $this->composerLockCachedCtime
                && $metaCacheKey['inode'] === $this->composerLockCachedInode
            ) {
                return $this->composerLockCachedSha256;
            }
        }

        if (!is_file($path) || !is_readable($path)) {
            throw new TrustKernelException('composer.lock is not readable: ' . $path);
        }

        $maxBytes = 8 * 1024 * 1024;
        $attempts = 0;
        while (true) {
            $attempts++;

            $metaBefore = self::tryReadFileCacheMeta($path);
            if ($metaBefore !== null && $metaBefore['size'] > $maxBytes) {
                throw new TrustKernelException('composer.lock is too large.');
            }

            $size = @filesize($path);
            if (is_int($size) && $size > $maxBytes) {
                throw new TrustKernelException('composer.lock is too large.');
            }

            $raw = @file_get_contents($path, false, null, 0, $maxBytes + 1);
            if (!is_string($raw)) {
                throw new TrustKernelException('Unable to read composer.lock.');
            }
            if (strlen($raw) > $maxBytes) {
                throw new TrustKernelException('composer.lock is too large.');
            }

            try {
                /** @var mixed $decoded */
                $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
            } catch (\JsonException $e) {
                throw new TrustKernelException('composer.lock JSON is invalid.', 0, $e);
            }

            if (!is_array($decoded)) {
                throw new TrustKernelException('composer.lock JSON must decode to an object/array.');
            }

            /** @var array<string,mixed> $decoded */
            $sha = CanonicalJson::sha256Bytes32($decoded);

            $metaAfter = self::tryReadFileCacheMeta($path);
            if ($metaBefore !== null && $metaAfter !== null) {
                if ($metaBefore !== $metaAfter) {
                    if ($attempts < 2) {
                        continue;
                    }
                    throw new TrustKernelException('composer.lock changed while reading.');
                }

                $this->composerLockCachedSha256 = $sha;
                $this->composerLockCachedMtime = $metaAfter['mtime'];
                $this->composerLockCachedSize = $metaAfter['size'];
                $this->composerLockCachedCtime = $metaAfter['ctime'];
                $this->composerLockCachedInode = $metaAfter['inode'];
                return $sha;
            }

            // If we cannot stat reliably, do not keep a weak cache.
            $this->composerLockCachedSha256 = null;
            $this->composerLockCachedMtime = null;
            $this->composerLockCachedSize = null;
            $this->composerLockCachedCtime = null;
            $this->composerLockCachedInode = null;

            // Best-effort TOCTOU detection even without stat(): re-read and compare the derived hash.
            $raw2 = @file_get_contents($path, false, null, 0, $maxBytes + 1);
            if (!is_string($raw2) || strlen($raw2) > $maxBytes) {
                throw new TrustKernelException('Unable to re-read composer.lock.');
            }

            try {
                /** @var mixed $decoded2 */
                $decoded2 = json_decode($raw2, true, 512, JSON_THROW_ON_ERROR);
            } catch (\JsonException $e) {
                throw new TrustKernelException('composer.lock JSON is invalid (re-read).', 0, $e);
            }

            if (!is_array($decoded2)) {
                throw new TrustKernelException('composer.lock JSON must decode to an object/array (re-read).');
            }

            /** @var array<string,mixed> $decoded2 */
            $sha2 = CanonicalJson::sha256Bytes32($decoded2);
            if (!hash_equals($sha, $sha2)) {
                throw new TrustKernelException('composer.lock changed while reading.');
            }
            return $sha;
        }
    }

    private function computePhpFingerprintSha256Bytes32(): string
    {
        if ($this->phpFingerprintCachedSha256 !== null) {
            return $this->phpFingerprintCachedSha256;
        }

        $extensions = get_loaded_extensions();
        sort($extensions, SORT_STRING);

        $map = [];
        foreach ($extensions as $ext) {
            if (!is_string($ext) || $ext === '') {
                continue;
            }
            $version = phpversion($ext);
            $map[$ext] = is_string($version) && trim($version) !== '' ? trim($version) : null;
        }

        $sha = CanonicalJson::sha256Bytes32([
            'schema_version' => 2,
            'type' => 'blackcat.php.fingerprint',
            'php_version' => PHP_VERSION,
            'extensions' => $map,
        ]);
        $this->phpFingerprintCachedSha256 = $sha;
        return $sha;
    }

    private function readImageDigestSha256Bytes32OrThrow(): string
    {
        $path = $this->config->imageDigestFilePath ?? '/etc/blackcat/image.digest';
        $path = trim($path);
        if ($path === '' || str_contains($path, "\0")) {
            throw new TrustKernelException('Image digest file path is invalid.');
        }

        if (self::isSymlinkPath($path)) {
            throw new TrustKernelException('Image digest file must not be a symlink.');
        }

        $metaCacheKey = self::tryReadFileCacheMeta($path);
        if (
            $this->imageDigestCachedSha256 !== null
            && $this->imageDigestCachedMtime !== null
            && $this->imageDigestCachedSize !== null
            && $this->imageDigestCachedCtime !== null
            && $this->imageDigestCachedInode !== null
            && $metaCacheKey !== null
        ) {
            if (
                $metaCacheKey['mtime'] === $this->imageDigestCachedMtime
                && $metaCacheKey['size'] === $this->imageDigestCachedSize
                && $metaCacheKey['ctime'] === $this->imageDigestCachedCtime
                && $metaCacheKey['inode'] === $this->imageDigestCachedInode
            ) {
                return $this->imageDigestCachedSha256;
            }
        }

        if (!is_file($path) || !is_readable($path)) {
            throw new TrustKernelException('Image digest file is not readable: ' . $path);
        }

        $maxBytes = 4096;
        $attempts = 0;
        while (true) {
            $attempts++;

            $metaBefore = self::tryReadFileCacheMeta($path);
            if ($metaBefore !== null && $metaBefore['size'] > $maxBytes) {
                throw new TrustKernelException('Image digest file is too large.');
            }

            $size = @filesize($path);
            if (is_int($size) && $size > $maxBytes) {
                throw new TrustKernelException('Image digest file is too large.');
            }

            $raw = @file_get_contents($path, false, null, 0, $maxBytes + 1);
            if (!is_string($raw)) {
                throw new TrustKernelException('Unable to read image digest file.');
            }
            if (strlen($raw) > $maxBytes) {
                throw new TrustKernelException('Image digest file is too large.');
            }

            $digest = trim($raw);
            if ($digest === '' || str_contains($digest, "\0")) {
                throw new TrustKernelException('Image digest file is empty/invalid.');
            }

            if (str_starts_with($digest, 'sha256:')) {
                $digest = substr($digest, 7);
            }
            if (str_starts_with($digest, '0x') || str_starts_with($digest, '0X')) {
                $digest = substr($digest, 2);
            }
            $digest = trim($digest);
            if (!preg_match('/^[a-fA-F0-9]{64}$/', $digest)) {
                throw new TrustKernelException('Image digest must be 32 bytes of hex (sha256).');
            }

            $out = '0x' . strtolower($digest);

            $metaAfter = self::tryReadFileCacheMeta($path);
            if ($metaBefore !== null && $metaAfter !== null) {
                if ($metaBefore !== $metaAfter) {
                    if ($attempts < 2) {
                        continue;
                    }
                    throw new TrustKernelException('Image digest file changed while reading.');
                }

                $this->imageDigestCachedSha256 = $out;
                $this->imageDigestCachedMtime = $metaAfter['mtime'];
                $this->imageDigestCachedSize = $metaAfter['size'];
                $this->imageDigestCachedCtime = $metaAfter['ctime'];
                $this->imageDigestCachedInode = $metaAfter['inode'];
                return $out;
            }

            // Fail safe: if we cannot stat reliably, do not keep a weak cache.
            $this->imageDigestCachedSha256 = null;
            $this->imageDigestCachedMtime = null;
            $this->imageDigestCachedSize = null;
            $this->imageDigestCachedCtime = null;
            $this->imageDigestCachedInode = null;

            // Best-effort TOCTOU detection even without stat(): re-read and compare.
            $raw2 = @file_get_contents($path, false, null, 0, $maxBytes + 1);
            if (!is_string($raw2) || strlen($raw2) > $maxBytes) {
                throw new TrustKernelException('Unable to re-read image digest file.');
            }

            $digest2 = trim($raw2);
            if (str_starts_with($digest2, 'sha256:')) {
                $digest2 = substr($digest2, 7);
            }
            if (str_starts_with($digest2, '0x') || str_starts_with($digest2, '0X')) {
                $digest2 = substr($digest2, 2);
            }
            $digest2 = trim($digest2);
            if (!preg_match('/^[a-fA-F0-9]{64}$/', $digest2)) {
                throw new TrustKernelException('Image digest must be 32 bytes of hex (sha256).');
            }

            $out2 = '0x' . strtolower($digest2);
            if (!hash_equals($out, $out2)) {
                throw new TrustKernelException('Image digest file changed while reading.');
            }
            return $out;
        }
    }

    /**
     * Read and canonicalize a local JSON file and return sha256 (bytes32), with basic TOCTOU hardening.
     *
     * @return array{ok:true,sha:string}|array{ok:false,error:'symlink'|'too_large'|'unreadable'|'invalid'|'changed',message:string}
     */
    private static function tryReadCanonicalJsonFileSha256Bytes32(string $path, int $maxBytes): array
    {
        if ($maxBytes < 0) {
            return [
                'ok' => false,
                'error' => 'unreadable',
                'message' => 'invalid maxBytes',
            ];
        }

        $path = trim($path);
        if ($path === '' || str_contains($path, "\0")) {
            return [
                'ok' => false,
                'error' => 'unreadable',
                'message' => 'invalid path',
            ];
        }

        if (self::isSymlinkPath($path)) {
            return [
                'ok' => false,
                'error' => 'symlink',
                'message' => 'symlink',
            ];
        }

        clearstatcache(true, $path);
        if (!is_file($path) || !is_readable($path)) {
            return [
                'ok' => false,
                'error' => 'unreadable',
                'message' => 'not readable',
            ];
        }

        $attempts = 0;
        while (true) {
            $attempts++;

            $metaBefore = self::tryReadFileCacheMeta($path);
            if ($metaBefore !== null && $metaBefore['size'] > $maxBytes) {
                return [
                    'ok' => false,
                    'error' => 'too_large',
                    'message' => 'too large',
                ];
            }

            $size = @filesize($path);
            if (is_int($size) && $size > $maxBytes) {
                return [
                    'ok' => false,
                    'error' => 'too_large',
                    'message' => 'too large',
                ];
            }

            $raw = @file_get_contents($path, false, null, 0, $maxBytes + 1);
            if (!is_string($raw)) {
                return [
                    'ok' => false,
                    'error' => 'unreadable',
                    'message' => 'read failed',
                ];
            }
            if (strlen($raw) > $maxBytes) {
                return [
                    'ok' => false,
                    'error' => 'too_large',
                    'message' => 'too large',
                ];
            }

            try {
                /** @var mixed $decoded */
                $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
            } catch (\JsonException $e) {
                return [
                    'ok' => false,
                    'error' => 'invalid',
                    'message' => $e->getMessage(),
                ];
            }

            if (!is_array($decoded)) {
                return [
                    'ok' => false,
                    'error' => 'invalid',
                    'message' => 'JSON must decode to an object/array',
                ];
            }

            /** @var array<string,mixed> $decoded */
            $sha = CanonicalJson::sha256Bytes32($decoded);

            $metaAfter = self::tryReadFileCacheMeta($path);
            if ($metaBefore !== null && $metaAfter !== null) {
                if ($metaBefore !== $metaAfter) {
                    if ($attempts < 2) {
                        continue;
                    }
                    return [
                        'ok' => false,
                        'error' => 'changed',
                        'message' => 'file changed while reading',
                    ];
                }

                return [
                    'ok' => true,
                    'sha' => $sha,
                ];
            }

            // Fail safe: if we cannot stat reliably, do best-effort TOCTOU detection by re-reading and comparing hash.
            $raw2 = @file_get_contents($path, false, null, 0, $maxBytes + 1);
            if (!is_string($raw2) || strlen($raw2) > $maxBytes) {
                return [
                    'ok' => false,
                    'error' => 'unreadable',
                    'message' => 'unable to re-read file',
                ];
            }

            try {
                /** @var mixed $decoded2 */
                $decoded2 = json_decode($raw2, true, 512, JSON_THROW_ON_ERROR);
            } catch (\JsonException $e) {
                return [
                    'ok' => false,
                    'error' => 'invalid',
                    'message' => $e->getMessage(),
                ];
            }

            if (!is_array($decoded2)) {
                return [
                    'ok' => false,
                    'error' => 'invalid',
                    'message' => 'JSON must decode to an object/array',
                ];
            }

            /** @var array<string,mixed> $decoded2 */
            $sha2 = CanonicalJson::sha256Bytes32($decoded2);
            if (!hash_equals($sha, $sha2)) {
                return [
                    'ok' => false,
                    'error' => 'changed',
                    'message' => 'file changed while reading',
                ];
            }

            return [
                'ok' => true,
                'sha' => $sha,
            ];
        }
    }

    /**
     * Returns a strong-ish cache key for a security-critical file.
     *
     * Rationale:
     * - `mtime`/`size` alone can be forged by an attacker with filesystem access (e.g. edit + touch -r).
     * - `ctime` is not user-settable on typical Unix filesystems and changes on content changes.
     * - `inode` changes on atomic replace/rename.
     *
     * If these fields are not available/reliable, we return null and the caller must not keep a weak cache.
     *
     * @return array{mtime:int,size:int,ctime:int,inode:int}|null
     */
    private static function tryReadFileCacheMeta(string $path): ?array
    {
        // On Windows `filectime()`/stat('ctime') is typically the creation time, not an inode-change time,
        // so it is not a reliable tamper signal. Fail safe: disable file-based caching on Windows.
        static $isWindows = null;
        if (!is_bool($isWindows)) {
            $isWindows = stripos((string) php_uname('s'), 'windows') !== false;
        }
        if ($isWindows) {
            return null;
        }

        clearstatcache(true, $path);
        $st = @stat($path);
        if (!is_array($st)) {
            return null;
        }

        $mtime = $st['mtime'] ?? null;
        $size = $st['size'] ?? null;
        $ctime = $st['ctime'] ?? null;
        $inode = $st['ino'] ?? null;

        if (!is_int($mtime) || !is_int($size) || !is_int($ctime) || !is_int($inode)) {
            return null;
        }

        if ($mtime <= 0 || $ctime <= 0 || $inode <= 0 || $size < 0) {
            return null;
        }

        return [
            'mtime' => $mtime,
            'size' => $size,
            'ctime' => $ctime,
            'inode' => $inode,
        ];
    }

    private static function isSymlinkPath(string $path): bool
    {
        clearstatcache(true, $path);
        $st = @lstat($path);
        if (!is_array($st)) {
            return false;
        }

        $mode = $st['mode'] ?? null;
        if (!is_int($mode)) {
            return false;
        }

        // POSIX S_IFMT = 0170000, S_IFLNK = 0120000.
        return (($mode & 0170000) === 0120000);
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

    /**
     * RuntimeDoctor findings filtered to PHP hardening (`php_*`).
     *
     * This is intentionally optional to keep blackcat-core usable without blackcat-config installed.
     *
     * @return list<array{severity:'info'|'warn'|'error',code:string,message:string}>|null
     */
    private function runtimeDoctorPhpFindingsOrNull(): ?array
    {
        if ($this->runtimeDoctorPhpChecked) {
            if (!$this->runtimeDoctorPhpAvailable) {
                return null;
            }

            if ($this->runtimeDoctorPhpError !== null) {
                throw new TrustKernelException('Runtime doctor failed: ' . $this->runtimeDoctorPhpError);
            }

            return $this->runtimeDoctorPhpFindings;
        }

        $this->runtimeDoctorPhpChecked = true;

        $configClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'Config']);
        $doctorClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'RuntimeDoctor']);

        if (
            !class_exists($configClass)
            || !class_exists($doctorClass)
            || !is_callable([$configClass, 'isInitialized'])
            || !is_callable([$configClass, 'repo'])
            || !is_callable([$doctorClass, 'inspect'])
        ) {
            $this->runtimeDoctorPhpAvailable = false;
            return null;
        }

        $isInitialized = 'isInitialized';
        if (!(bool) $configClass::$isInitialized()) {
            $this->runtimeDoctorPhpAvailable = false;
            return null;
        }

        $repoMethod = 'repo';
        /** @var mixed $repo */
        $repo = $configClass::$repoMethod();
        if (!is_object($repo)) {
            $this->runtimeDoctorPhpAvailable = false;
            return null;
        }

        try {
            /** @var mixed $report */
            $report = $doctorClass::inspect($repo);
            $findingsRaw = is_array($report) ? ($report['findings'] ?? null) : null;

            /** @var list<array{severity:'info'|'warn'|'error',code:string,message:string}> $phpFindings */
            $phpFindings = [];

            if (is_array($findingsRaw)) {
                foreach ($findingsRaw as $f) {
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

                    $phpFindings[] = [
                        'severity' => $severity,
                        'code' => $code,
                        'message' => $message,
                    ];
                }
            }

            $this->runtimeDoctorPhpAvailable = true;
            $this->runtimeDoctorPhpFindings = $phpFindings;
            return $this->runtimeDoctorPhpFindings;
        } catch (\Throwable $e) {
            $msg = $e->getMessage();
            if (str_contains($msg, "\0")) {
                $msg = '';
            }
            $this->runtimeDoctorPhpAvailable = true;
            $this->runtimeDoctorPhpError = $msg;
            throw $e;
        }
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

        $maxBytes = 64 * 1024;
        $size = @filesize($path);
        if (is_int($size) && $size > $maxBytes) {
            $this->lastOkStateMtime = $mtime;
            return;
        }

        $raw = @file_get_contents($path, false, null, 0, $maxBytes + 1);
        if (!is_string($raw) || strlen($raw) > $maxBytes) {
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
        $httpAllowedHostsSha256 = $decoded['http_allowed_hosts_sha256'] ?? null;
        $composerLockSha256 = $decoded['composer_lock_sha256'] ?? null;
        $phpFingerprintSha256 = $decoded['php_fingerprint_sha256'] ?? null;
        $imageDigestSha256 = $decoded['image_digest_sha256'] ?? null;
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

            $this->lastOkComposerLockSha256 = null;
            if (is_string($composerLockSha256) && $composerLockSha256 !== '') {
                try {
                    $this->lastOkComposerLockSha256 = Bytes32::normalizeHex($composerLockSha256);
                } catch (\Throwable) {
                    $this->lastOkComposerLockSha256 = null;
                }
            }

            $this->lastOkPhpFingerprintSha256 = null;
            if (is_string($phpFingerprintSha256) && $phpFingerprintSha256 !== '') {
                try {
                    $this->lastOkPhpFingerprintSha256 = Bytes32::normalizeHex($phpFingerprintSha256);
                } catch (\Throwable) {
                    $this->lastOkPhpFingerprintSha256 = null;
                }
            }

            $this->lastOkImageDigestSha256 = null;
            if (is_string($imageDigestSha256) && $imageDigestSha256 !== '') {
                try {
                    $this->lastOkImageDigestSha256 = Bytes32::normalizeHex($imageDigestSha256);
                } catch (\Throwable) {
                    $this->lastOkImageDigestSha256 = null;
                }
            }

            $this->lastOkHttpAllowedHostsSha256 = null;
            if (is_string($httpAllowedHostsSha256) && $httpAllowedHostsSha256 !== '') {
                try {
                    $this->lastOkHttpAllowedHostsSha256 = Bytes32::normalizeHex($httpAllowedHostsSha256);
                } catch (\Throwable) {
                    $this->lastOkHttpAllowedHostsSha256 = null;
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

        $path = trim($path);
        if ($path === '' || str_contains($path, "\0") || strlen($path) > 8192) {
            return;
        }

        $payload = [
            'version' => 1,
            'chain_id' => $this->config->chainId,
            'instance_controller' => $this->config->instanceController,
            'last_ok_at' => $this->lastOkAt,
            'runtime_config_sha256' => $this->lastOkRuntimeConfigSha256,
            'http_allowed_hosts_sha256' => $this->lastOkHttpAllowedHostsSha256,
            'composer_lock_sha256' => $this->lastOkComposerLockSha256,
            'php_fingerprint_sha256' => $this->lastOkPhpFingerprintSha256,
            'image_digest_sha256' => $this->lastOkImageDigestSha256,
            'snapshot' => $status->snapshot->toArray(),
        ];

        try {
            $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            $this->logger?->warning('[trust-kernel] unable to persist last-ok snapshot (json): ' . $e->getMessage());
            return;
        }

        $dir = dirname($path);
        if ($dir === '' || $dir === '.' || str_contains($dir, "\0")) {
            return;
        }
        $dirTrim = rtrim($dir, "/\\");
        if ($dirTrim === '') {
            $dirTrim = $dir;
        }
        if (is_link($dirTrim)) {
            return;
        }
        if (is_link($path)) {
            return;
        }
        if (!is_dir($dir)) {
            return;
        }

        // Refuse persisting state under the public web root if DOCUMENT_ROOT is known.
        $docRoot = $_SERVER['DOCUMENT_ROOT'] ?? null;
        if (is_string($docRoot) && trim($docRoot) !== '' && !str_contains($docRoot, "\0")) {
            $docReal = realpath($docRoot);
            $dirReal = realpath($dir);
            if (is_string($docReal) && is_string($dirReal)) {
                $docPrefix = rtrim($docReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
                $dirWithSep = rtrim($dirReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
                if (str_starts_with($dirWithSep, $docPrefix)) {
                    $this->logger?->warning('[trust-kernel] refusing to persist last-ok state under DOCUMENT_ROOT');
                    return;
                }
            }
        }

        $base = basename($path);
        $tmp = $dir . DIRECTORY_SEPARATOR . '.' . $base . '.' . bin2hex(random_bytes(6)) . '.tmp';

        try {
            $fp = @fopen($tmp, 'xb');
            if ($fp === false) {
                return;
            }

            try {
                $payloadBytes = $json . "\n";
                $len = strlen($payloadBytes);
                $offset = 0;
                while ($offset < $len) {
                    $n = fwrite($fp, substr($payloadBytes, $offset));
                    if ($n === false || $n === 0) {
                        throw new \RuntimeException('write_failed');
                    }
                    $offset += $n;
                }
                fflush($fp);
            } finally {
                fclose($fp);
            }

            @chmod($tmp, 0640);
            if (!@rename($tmp, $path)) {
                @unlink($tmp);
                return;
            }
            @chmod($path, 0640);
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
            throw new TrustKernelException($msg);
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
