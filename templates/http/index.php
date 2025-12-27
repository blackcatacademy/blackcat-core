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

use BlackCat\Core\Kernel\KernelBootstrap;
use BlackCat\Core\Security\HttpRequestGuard;
use BlackCat\Core\Security\PhpRuntimeInspector;

$autoload = __DIR__ . '/../vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
} else {
    // Adjust to your project structure as needed.
    // If you are not using Composer, include your own autoloader here.
}

// Best-effort hardening (do not rely on runtime ini_set alone; configure php.ini where possible).
@ini_set('display_errors', '0');
@ini_set('display_startup_errors', '0');
@ini_set('log_errors', '1');
@ini_set('expose_php', '0');
@ini_set('zend.exception_ignore_args', '1');
@ini_set('session.use_strict_mode', '1');
@ini_set('session.use_only_cookies', '1');
@ini_set('session.use_trans_sid', '0');
@ini_set('session.cookie_httponly', '1');

// Basic security headers (safe defaults; customize in your app if needed).
@header_remove('X-Powered-By');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

// Basic request guard (reject obvious exploit primitives early).
try {
    HttpRequestGuard::assertSafeRequest($_SERVER);
} catch (Throwable $e) {
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Bad Request\n";
    exit(0);
}

// Boot kernel early (strict-by-default). This installs TrustKernel guards for secrets + DB writes.
$kernel = KernelBootstrap::bootOrFail();

// Optional: perform one trust check at the beginning of each request.
// For extremely high-traffic systems you may want to rely on lazy checks (only when secrets/DB writes happen).
$status = $kernel->check();
if (!$status->readAllowed) {
    http_response_code(503);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Service Unavailable\n";
    exit(0);
}

// Optional: runtime hardening diagnostics (useful during installation).
// In strict enforcement, treat runtime errors as a hard failure.
$runtime = PhpRuntimeInspector::inspect();
foreach (($runtime['findings'] ?? []) as $finding) {
    if (!is_array($finding)) {
        continue;
    }
    $severity = $finding['severity'] ?? null;
    if ($severity === 'error' && $status->enforcement === 'strict') {
        http_response_code(503);
        header('Content-Type: text/plain; charset=utf-8');
        echo "Service Unavailable\n";
        exit(0);
    }
}

// ---- Mount your application below this line ----
// Example:
// require __DIR__ . '/../app/bootstrap.php';
//
// If you are using a framework, hand off to its kernel here.

