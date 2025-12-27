# Front controller hardening (kernel-only web installs)

This doc describes a **strict single-entrypoint** HTTP setup for minimal BlackCat installs:
- `blackcat-core` (TrustKernel + guards),
- `blackcat-config` (file-based runtime config),
- `blackcat-kernel-contracts` (on-chain authority).

The goal is to reduce attack surface for **cheap hosting** deployments where OS-level isolation is limited.

## Why a strict front controller matters

Many real-world compromises on shared hosting look like this:
- attacker uploads a new `backdoor.php` (via FTP, leaked panel creds, writable web dir),
- attacker calls it directly over HTTP,
- attacker reads config/secrets and pivots.

BlackCat’s TrustKernel can block secrets/DB writes when integrity is violated, but a strict front controller adds an extra layer:
- reduces the number of HTTP entrypoints to one (`index.php`),
- blocks obvious exploit primitives early (path traversal, stream wrappers),
- applies safe runtime defaults (best effort) and security headers.

## Template files

BlackCat ships templates you can copy into your web root:
- `blackcat-core/templates/http/index.php`
- `blackcat-core/templates/http/.htaccess` (Apache)
- `blackcat-core/templates/http/nginx.conf.snippet` (Nginx)
- `blackcat-core/templates/http/Caddyfile.snippet` (Caddy)

The template `index.php` uses the reusable kernel entrypoint:
- `BlackCat\Core\Kernel\HttpKernel`

If you use Nginx/Caddy, implement equivalent rules:
- deny direct access to `*.php` except `index.php`,
- route all requests to `index.php`.

Legacy references (not supported, app-specific):
- `blackcat-core/templates/http/legacy/`

## Runtime hardening checks

During install / audits, inspect PHP hardening posture:
- `BlackCat\Core\Security\PhpRuntimeInspector::inspect()` (used by the template)

It highlights:
- `allow_url_include=1` (hard error),
- `cgi.fix_pathinfo=1` in FPM/CGI (hard error),
- missing curl vs `allow_url_fopen` transport requirements (TrustKernel RPC),
- `display_errors` / `auto_prepend_file` concerns,
- missing `disable_functions` for process-exec primitives (recommendation).

## What this does NOT solve

If an attacker achieves **arbitrary code execution inside your process without touching files** (e.g., a true RCE bug),
they can still call your application code and attempt to trigger sensitive operations.

BlackCat’s defense-in-depth is:
- TrustKernel guards around secrets and DB writes,
- on-chain policy + pause/emergency workflows,
- integrity monitoring (detect tamper, detect new entrypoints in `mode=full`),
- optional off-host watchdog/relayer design.

For high assurance, keep emergency keys off-host and treat the on-chain authority as the final source of truth.
