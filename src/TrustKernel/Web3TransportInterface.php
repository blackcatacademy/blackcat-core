<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

interface Web3TransportInterface
{
    public function postJson(string $url, string $jsonBody, int $timeoutSec): string;
}

