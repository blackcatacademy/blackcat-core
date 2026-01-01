# Trust Kernel Status (health output)

For automation / monitoring you typically want a single command that:

- boots the Trust Kernel from `blackcat-config` runtime config
- performs a full integrity + Web3 trust check
- returns machine-readable JSON + an exit code

## Script

Use `blackcat-core/scripts/trust-kernel-status.php`.

Example:

```bash
php scripts/trust-kernel-status.php --pretty
```

## Exit codes

- `0` trusted
- `2` untrusted (fail-closed signal for production)
- `1` bootstrap/runtime error (missing config, invalid config, etc.)

## Enforcement

The JSON output contains `enforcement` (`strict` | `warn`) derived from the **on-chain policy hash**.

- `strict`: deny by throwing exceptions (fail-closed)
- `warn`: logs loud warnings and continues (dev-only), but still respects hard-stop conditions (e.g. on-chain `paused`)

The JSON output also contains:
- `mode` (`root_uri` | `full`) (derived from runtime config / policy)
- `max_stale_sec` (runtime config)

For “production readiness” checks (reject `warn`), use `blackcat-core/scripts/trust-kernel-install-verify.php`.

## Dev-mode

If you explicitly want to *observe* failures in dev without failing the command, use:

```bash
php scripts/trust-kernel-status.php --allow-untrusted
```
