<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class InstanceControllerSnapshot implements \JsonSerializable
{
    public function __construct(
        public readonly int $version,
        public readonly bool $paused,
        public readonly string $activeRoot,
        public readonly string $activeUriHash,
        public readonly string $activePolicyHash,
        public readonly string $pendingRoot,
        public readonly string $pendingUriHash,
        public readonly string $pendingPolicyHash,
        public readonly int $pendingCreatedAt,
        public readonly int $pendingTtlSec,
        public readonly int $genesisAt,
        public readonly int $lastUpgradeAt,
    ) {
        Bytes32::normalizeHex($activeRoot);
        Bytes32::normalizeHex($activeUriHash);
        Bytes32::normalizeHex($activePolicyHash);
        Bytes32::normalizeHex($pendingRoot);
        Bytes32::normalizeHex($pendingUriHash);
        Bytes32::normalizeHex($pendingPolicyHash);
    }

    /**
     * @return array{
     *   version:int,
     *   paused:bool,
     *   active_root:string,
     *   active_uri_hash:string,
     *   active_policy_hash:string,
     *   pending_root:string,
     *   pending_uri_hash:string,
     *   pending_policy_hash:string,
     *   pending_created_at:int,
     *   pending_ttl_sec:int,
     *   genesis_at:int,
     *   last_upgrade_at:int
     * }
     */
    public function toArray(): array
    {
        return [
            'version' => $this->version,
            'paused' => $this->paused,
            'active_root' => $this->activeRoot,
            'active_uri_hash' => $this->activeUriHash,
            'active_policy_hash' => $this->activePolicyHash,
            'pending_root' => $this->pendingRoot,
            'pending_uri_hash' => $this->pendingUriHash,
            'pending_policy_hash' => $this->pendingPolicyHash,
            'pending_created_at' => $this->pendingCreatedAt,
            'pending_ttl_sec' => $this->pendingTtlSec,
            'genesis_at' => $this->genesisAt,
            'last_upgrade_at' => $this->lastUpgradeAt,
        ];
    }

    public function jsonSerialize(): mixed
    {
        return $this->toArray();
    }
}
