<?php

declare(strict_types=1);

/**
 * BlackCat minimal front controller (template).
 *
 * This file is intended to be copied into your web root as `index.php`
 * and used as the single entrypoint for all requests.
 *
 * Requirements:
 * - web server rewrite to route all requests to index.php
 * - deny direct access to other *.php files (recommended; see .htaccess template)
 *
 * Notes:
 * - This is not a framework router. It only boots the kernel early, sets safe defaults,
 *   and provides basic request hardening.
 * - You still need to mount your application after the kernel bootstrap.
 */

use BlackCat\Core\Kernel\HttpKernel;
use BlackCat\Core\Kernel\HttpKernelContext;

$autoload = __DIR__ . '/../vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
} else {
    // Adjust to your project structure as needed.
    // If you are not using Composer, include your own autoloader here.
}

HttpKernel::run(static function (HttpKernelContext $ctx): void {
    // ---- Mount your application below this line ----
    // Example:
    // require __DIR__ . '/../app/bootstrap.php';
    //
    // If you are using a framework, hand off to its kernel here.
    //
    // You have access to:
    // - $ctx->kernel (TrustKernel; guards are already installed)
    // - $ctx->status (TrustKernelStatus from initial check)
    // - $ctx->phpRuntime (optional runtime hardening diagnostics)
});
