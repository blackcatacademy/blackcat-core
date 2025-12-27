# Deployment hardening (single VM reality)

This project can be deployed in very different environments. Not every user will have:
- multiple VMs / microVMs,
- SELinux/AppArmor tuning,
- HSM/KMS,
- an ops team.

This document describes a **cheap-but-reasonable** baseline for a single VM, and what it can (and cannot) protect.

## Key principle

If an attacker gets arbitrary code execution **inside your application process**, you cannot make them “unable to use the app”.
What you *can* do is make it much harder to:
- persist (modify code/config without detection),
- extract key material,
- silently tamper with data,
- keep a long attack window (watchdog + emergency pause).

## Recommended single-VM baseline

### 1) Keep DB separate (recommended)

- Put the database on a separate host/VM and do not expose it publicly.
- Only allow the app host to reach it over a private network.

If you truly bind the DB to `127.0.0.1` on the DB host, you will need an explicit, hardened proxy/tunnel on the DB host
to accept connections from your app host.

### 2) Separate Unix users (privilege separation)

- Run the web runtime (PHP-FPM/workers) as `blackcat-app`.
- Run the Trust Watchdog as `blackcat-watchdog` (different UID so `blackcat-app` cannot signal/kill it).

### 3) Immutable code + strict integrity root

- Put the executable code in an immutable directory (root-owned, not writable by `blackcat-app`).
- Set `trust.integrity.root_dir` to this directory.
- Use `trust.web3.mode="full"` in production.

In `mode="full"`, the Trust Kernel treats the integrity root as immutable and fails closed if *unexpected files*
appear under `trust.integrity.root_dir`.

### 4) Never allow “uploads” to be executable

Do not put uploads inside the integrity root.

If you must have uploads under the web root, mount them separately with hardening flags and disable PHP execution there
at the web server level.

### 5) Keys/config placement

- Keep runtime config in a secure location (e.g. `/etc/blackcat/config.runtime.json`).
- Keep keys outside the web root and outside any directory writable by the web runtime.

### 6) Run the local Watchdog

Use:
- `blackcat-core/scripts/trust-kernel-watchdog.php` (JSON-lines output + optional outbox).
- `blackcat-core/scripts/trust-kernel-status.php` (single-shot health output).
- `blackcat-core/scripts/trust-kernel-install-verify.php` (post-install verification: trust + bypass scan + permission sanity).

The long-term “actuator” (sending on-chain `pause()` / `reportIncident()`) is recommended to run **off-host** so
your emergency signer keys are not on the compromised machine.

## Cheap hosting / FTP install ceremony

If the hosting provider forces an FTP-style workflow (no separate worker, limited shell access), treat FTP as a
**temporary installer transport**:

1) Upload files.
2) Immediately disable/remove FTP access.
3) Verify the install matches the expected Web3 state.

Recommended steps:

- After upload, remove/disable any installer script and immediately disable FTP.
- Make the code tree read-only if possible (at least prevent group/world write).
- Run a post-install verification:

```bash
php scripts/trust-kernel-install-verify.php --pretty
```

This verification fails (exit code `2`) when:
- Trust Kernel is untrusted (root mismatch, policy mismatch, ReleaseRegistry mismatch, etc.)
- on-chain policy is not `strict` (unless you pass `--allow-warn`)
- `trust.web3.mode` is not `full` (unless you pass `--allow-root-uri`)
- bypass scan finds forbidden patterns (raw PDO, direct `*.key` reads)
- integrity root contains symlinks or group/world writable files (POSIX)

## What this does not solve

- A fully compromised host can still cause DoS (kill processes, delete files).
- If the attacker gets root on the app VM, all bets are off unless you have an off-host sentinel and off-host signers.
- If your web server executes code from writable directories, integrity guarantees collapse.
