# Minimal security stack (kernel-only)

Goal: allow users to deploy **only**:
- `blackcat-core` (kernel primitives + Trust Kernel),
- `blackcat-config` (file-based runtime config + hardening),
- `blackcat-kernel-contracts` (on-chain trust authority),

…and still gain strong security properties without adopting the full `blackcat-*` ecosystem.

## What you get

- tamper detection (local code integrity vs on-chain root)
- strict fail-closed enforcement for secrets/DB writes (on-chain policy hash)
- bypass resistance at the kernel primitive level (guards + CI scanner)
- optional watchdog (local polling + remote sentinel design)

## What you must accept (truth)

If an attacker gets **arbitrary PHP code execution inside your app process**, no purely-PHP mechanism can provide absolute guarantees.
BlackCat’s goal is **defense-in-depth**, to reduce the practical blast radius:
- reduce HTTP entrypoints (strict front controller + web server deny rules),
- make persistence detectable (`mode=full` integrity root),
- make key theft harder (OS perms + no env fallbacks + guarded decrypt),
- reduce the time window (watchdog + on-chain pause).

Front controller hardening:
- `blackcat-core/docs/FRONT_CONTROLLER.md`

## Recommended minimal ceremony (prod)

### 1) Deploy contracts (EVM)

Deploy `blackcat-kernel-contracts` and create a **per-install** `InstanceController` clone.

For Edgen Chain:
- chain_id: `4207`
- RPC: `https://rpc.layeredge.io`
- explorer: `https://edgenscan.io`

### 2) Build integrity manifest + compute root

Pick an immutable code directory (no uploads/caches).

Build the manifest + compute `root` / `uri_hash`:
- `blackcat-core/docs/INTEGRITY_MANIFEST.md`

### 3) Commit root + policy on-chain

On your per-install `InstanceController`:
- set `activeRoot`
- set `activeUriHash` (optional but recommended)
- set `activePolicyHash` to **strict** policy (recommended: `TrustPolicyV3 strict`)

If you use policy v3, also set + lock the runtime config attestation key/value (recommended).

### 4) Create runtime config (file-based)

Create runtime config (strict permissions):

```bash
php vendor/bin/config runtime:init --template=trust-edgen
# optional (explicit path):
# php vendor/bin/config runtime:init --template=trust-edgen --out=/etc/blackcat/config.runtime.json
```

Fill:
- `trust.web3.contracts.instance_controller`
- `trust.integrity.root_dir`
- `trust.integrity.manifest`
- keep `trust.web3.mode="full"` for production (compat option: `root_uri`)

Validate (optional, but recommended):

```bash
php vendor/bin/config runtime:scan
```

Edgen template doc:
- `blackcat-config/docs/TRUST_KERNEL_EDGEN.md`

### 5) Boot kernel early (fail-closed)

In your app entrypoint (before any business logic):

```php
use BlackCat\Core\Kernel\KernelBootstrap;

KernelBootstrap::bootOrFail();
```

### 6) Post-install verification (cheap hosting / FTP)

- disable FTP right after upload
- run:

```bash
php scripts/trust-kernel-install-verify.php --pretty
```

Hardening notes:
- `blackcat-core/docs/DEPLOYMENT_HARDENING.md`

## Dev posture

Dev “warn” mode is only allowed when the **on-chain policy hash** commits to a warn policy.
Runtime config must not be able to switch strict ↔ warn.

## Next: watchdog actuator (off-host)

For production, keep emergency signing keys **off-host**.
Use the local watchdog for observation, but trigger `pause()` / incident txs via an off-host relayer.

See:
- `blackcat-core/docs/TRUST_WATCHDOG.md`
