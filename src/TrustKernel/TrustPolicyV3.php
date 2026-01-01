<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class TrustPolicyV3
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
        public readonly bool $requireRuntimeConfigAttestation = true,
        public readonly bool $runtimeConfigAttestationMustBeLocked = true,
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
    }

    /**
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        return [
            'schema_version' => 3,
            'type' => 'blackcat.trust.policy',
            'mode' => strtolower(trim($this->mode)),
            'max_stale_sec' => $this->maxStaleSec,
            'enforcement' => strtolower(trim($this->enforcement)),
            'require_runtime_config_attestation' => $this->requireRuntimeConfigAttestation,
            'runtime_config_attestation_key' => Bytes32::normalizeHex($this->runtimeConfigAttestationKey),
            'runtime_config_attestation_must_be_locked' => $this->runtimeConfigAttestationMustBeLocked,
        ];
    }

    public function hashBytes32(): string
    {
        return CanonicalJson::sha256Bytes32($this->toArray());
    }
}

