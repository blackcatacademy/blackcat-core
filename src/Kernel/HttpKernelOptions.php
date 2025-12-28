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
     * Trusted reverse proxy peers (IP/CIDR).
     *
     * This list is used to:
     * - reject forwarding headers from untrusted sources (anti-spoofing),
     * - optionally honor X-Forwarded-Proto=https when the peer is trusted.
     *
     * Runtime config may override/extend this via `http.trusted_proxies`.
     *
     * @var list<string>
     */
    public array $trustedProxies = ['127.0.0.1', '::1'];

    /**
     * If true, any request that contains forwarding headers (e.g. X-Forwarded-Proto)
     * must come from a trusted proxy peer.
     *
     * This prevents client-side header spoofing.
     */
    public bool $rejectUntrustedForwardedHeaders = true;

    /**
     * If true, and the immediate peer is a trusted proxy, treat X-Forwarded-Proto=https as HTTPS
     * for the rest of the request (best-effort, sets $_SERVER['HTTPS']).
     */
    public bool $honorTrustedForwardedProto = true;

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
