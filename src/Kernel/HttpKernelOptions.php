<?php

declare(strict_types=1);

namespace BlackCat\Core\Kernel;

final class HttpKernelOptions
{
    /** @var list<string> */
    public array $allowedMethods = ['GET', 'POST', 'HEAD', 'OPTIONS'];

    public bool $applyIniHardening = true;
    public bool $sendSecurityHeaders = true;

    /**
     * If true, calls `$kernel->check()` and requires `readAllowed` before running the app.
     *
     * If false, the TrustKernel still enforces on sensitive operations (secrets/DB writes),
     * but the request itself is not gated.
     */
    public bool $checkTrustOnRequest = true;

    /**
     * If strict policy is active and PHP runtime has "error" findings, fail closed.
     */
    public bool $requireRuntimeHardeningInStrict = true;

    /**
     * Catch app exceptions and render generic 500 (recommended for minimal installs).
     */
    public bool $catchAppExceptions = true;
}

