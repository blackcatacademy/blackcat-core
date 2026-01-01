<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

/**
 * Trust policy v5:
 * - binds runtime config via on-chain attestation (same as v3),
 * - binds HTTP allowed hosts list via on-chain attestation (prevents host allowlist tamper),
 * - optionally binds additional provenance attestations (composer.lock / PHP fingerprint / image digest).
 *
 * The contract stores only `activePolicyHash` (bytes32). The policy semantics live off-chain in the TrustKernel.
 */
final class TrustPolicyV5
{
    /**
     * @param 'root_uri'|'full' $mode
     * @param 'strict'|'warn' $enforcement
     */
    public function __construct(
        public readonly string $mode,
        public readonly int $maxStaleSec,
        public readonly string $enforcement,
        public readonly string $runtimeConfigAttestationKey,
        public readonly string $httpAllowedHostsAttestationKey,
        public readonly bool $requireRuntimeConfigAttestation = true,
        public readonly bool $runtimeConfigAttestationMustBeLocked = true,
        public readonly bool $requireHttpAllowedHostsAttestation = true,
        public readonly bool $httpAllowedHostsAttestationMustBeLocked = true,
        public readonly ?string $composerLockAttestationKey = null,
        public readonly bool $requireComposerLockAttestation = false,
        public readonly bool $composerLockAttestationMustBeLocked = true,
        public readonly ?string $phpFingerprintAttestationKey = null,
        public readonly bool $requirePhpFingerprintAttestation = false,
        public readonly bool $phpFingerprintAttestationMustBeLocked = true,
        public readonly ?string $imageDigestAttestationKey = null,
        public readonly bool $requireImageDigestAttestation = false,
        public readonly bool $imageDigestAttestationMustBeLocked = true,
    ) {
        $mode = strtolower(trim($mode));
        if ($mode === '' || !in_array($mode, ['root_uri', 'full'], true)) {
            throw new \InvalidArgumentException('Invalid trust policy mode (expected root_uri|full).');
        }
        if ($maxStaleSec < 1 || $maxStaleSec > 86400) {
            throw new \InvalidArgumentException('Invalid trust policy maxStaleSec (expected 1..86400).');
        }

        $enforcement = strtolower(trim($enforcement));
        if ($enforcement === '' || !in_array($enforcement, ['strict', 'warn'], true)) {
            throw new \InvalidArgumentException('Invalid trust policy enforcement (expected strict|warn).');
        }

        Bytes32::normalizeHex($runtimeConfigAttestationKey);

        Bytes32::normalizeHex($httpAllowedHostsAttestationKey);

        if ($requireComposerLockAttestation) {
            if (!is_string($composerLockAttestationKey) || trim($composerLockAttestationKey) === '') {
                throw new \InvalidArgumentException('composerLockAttestationKey is required when requireComposerLockAttestation=true.');
            }
            Bytes32::normalizeHex($composerLockAttestationKey);
        }
        if ($requirePhpFingerprintAttestation) {
            if (!is_string($phpFingerprintAttestationKey) || trim($phpFingerprintAttestationKey) === '') {
                throw new \InvalidArgumentException('phpFingerprintAttestationKey is required when requirePhpFingerprintAttestation=true.');
            }
            Bytes32::normalizeHex($phpFingerprintAttestationKey);
        }
        if ($requireImageDigestAttestation) {
            if (!is_string($imageDigestAttestationKey) || trim($imageDigestAttestationKey) === '') {
                throw new \InvalidArgumentException('imageDigestAttestationKey is required when requireImageDigestAttestation=true.');
            }
            Bytes32::normalizeHex($imageDigestAttestationKey);
        }
    }

    /**
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        return [
            'schema_version' => 5,
            'type' => 'blackcat.trust.policy',
            'mode' => strtolower(trim($this->mode)),
            'max_stale_sec' => $this->maxStaleSec,
            'enforcement' => strtolower(trim($this->enforcement)),
            'require_runtime_config_attestation' => $this->requireRuntimeConfigAttestation,
            'runtime_config_attestation_key' => Bytes32::normalizeHex($this->runtimeConfigAttestationKey),
            'runtime_config_attestation_must_be_locked' => $this->runtimeConfigAttestationMustBeLocked,
            'require_http_allowed_hosts_attestation' => $this->requireHttpAllowedHostsAttestation,
            'http_allowed_hosts_attestation_key' => Bytes32::normalizeHex($this->httpAllowedHostsAttestationKey),
            'http_allowed_hosts_attestation_must_be_locked' => $this->httpAllowedHostsAttestationMustBeLocked,
            'require_composer_lock_attestation' => $this->requireComposerLockAttestation,
            'composer_lock_attestation_key' => $this->composerLockAttestationKey !== null ? Bytes32::normalizeHex($this->composerLockAttestationKey) : null,
            'composer_lock_attestation_must_be_locked' => $this->composerLockAttestationMustBeLocked,
            'require_php_fingerprint_attestation' => $this->requirePhpFingerprintAttestation,
            'php_fingerprint_attestation_key' => $this->phpFingerprintAttestationKey !== null ? Bytes32::normalizeHex($this->phpFingerprintAttestationKey) : null,
            'php_fingerprint_attestation_must_be_locked' => $this->phpFingerprintAttestationMustBeLocked,
            'require_image_digest_attestation' => $this->requireImageDigestAttestation,
            'image_digest_attestation_key' => $this->imageDigestAttestationKey !== null ? Bytes32::normalizeHex($this->imageDigestAttestationKey) : null,
            'image_digest_attestation_must_be_locked' => $this->imageDigestAttestationMustBeLocked,
        ];
    }

    public function hashBytes32(): string
    {
        return CanonicalJson::sha256Bytes32($this->toArray());
    }
}
