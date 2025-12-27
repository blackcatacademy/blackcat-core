<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class IntegrityViolationException extends \RuntimeException
{
    public function __construct(
        public readonly string $violationCode,
        string $message,
    ) {
        parent::__construct($message);
    }
}

