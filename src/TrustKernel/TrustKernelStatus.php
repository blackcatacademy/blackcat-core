<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class TrustKernelStatus
{
    /**
     * @param list<string> $errors
     */
    public function __construct(
        public readonly bool $trustedNow,
        public readonly bool $readAllowed,
        public readonly bool $writeAllowed,
        public readonly bool $rpcOkNow,
        public readonly bool $paused,
        public readonly ?InstanceControllerSnapshot $snapshot,
        public readonly ?string $computedRoot,
        public readonly int $checkedAt,
        public readonly ?int $lastOkAt,
        public readonly array $errors = [],
    ) {
    }
}

