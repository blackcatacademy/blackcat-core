<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class InstanceControllerSnapshot
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
}

