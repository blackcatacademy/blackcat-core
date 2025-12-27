<?php

declare(strict_types=1);

namespace BlackCat\Core\Kernel;

use BlackCat\Core\TrustKernel\TrustKernel;
use BlackCat\Core\TrustKernel\TrustKernelStatus;

final class HttpKernelContext
{
    /**
     * @param array<string,mixed>|null $phpRuntime
     */
    public function __construct(
        public readonly TrustKernel $kernel,
        public readonly TrustKernelStatus $status,
        public readonly ?array $phpRuntime = null,
    ) {
    }
}

