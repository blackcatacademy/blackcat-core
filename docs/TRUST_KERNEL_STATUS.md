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

## Dev-mode

If you explicitly want to *observe* failures in dev without failing the command, use:

```bash
php scripts/trust-kernel-status.php --allow-untrusted
```

