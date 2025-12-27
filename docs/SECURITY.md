# Security primitives

`blackcat-core` contains low-level security primitives intended to be **auditable** and usable in kernel-only deployments.

Higher-level security features (auth flows, crypto manifests, DB ingress) live in dedicated modules.

## KeyManager (versioned keys)

`BlackCat\Core\Security\KeyManager` loads keys from:
1) key files (preferred): `<basename>_vN.key`
2) environment variables (legacy fallback): base64-encoded

Key length is enforced (libsodium AEAD key length for crypto keys).

Security note:
- When `blackcat-config` runtime config is present, ENV key fallback is **disabled by default**.
- To explicitly allow ENV fallback (legacy/dev only), set `crypto.allow_env_keys=true` in the runtime config.

Optional trust hook:
- `KeyManager::setAccessGuard()` can be used to fail-closed before any key material is read/rotated.
  The Trust Kernel bootstrap installs this guard automatically.

## Crypto (AEAD)

`BlackCat\Core\Security\Crypto` is a libsodium-based helper:
- AEAD XChaCha20-Poly1305 (nonce + authenticated data)
- supports multiple keys for decryption (newest → oldest)

It can optionally use the bridge from `blackcat/crypto` when installed (`BlackCat\Crypto\Bridge\CoreCryptoBridge`), but core remains functional without it.

## CSRF

`BlackCat\Core\Security\CSRF` provides CSRF token issuing/verification with:
- optional PSR-16 cache backend
- optional session binding

For production systems, use it together with `blackcatacademy/blackcat-sessions` (session lifecycle and DB persistence).

## FileVault (file-at-rest encryption)

`BlackCat\Core\Security\FileVault` encrypts files at rest using libsodium.

Notes:
- It uses versioned keys (`filevault_key_vN.key`) or the crypto bridge when available.
- It is a low-level primitive; higher-level “who can download what” policy belongs to domain modules.

## Recaptcha (optional helper)

`BlackCat\Core\Security\Recaptcha` is an optional helper to verify Google reCAPTCHA v2/v3 tokens.

- If you provide `opts['httpClient']` (callable), no additional PHP extensions are required.
- Otherwise it uses `ext-curl` (optional). If `ext-curl` is not available, it throws a clear runtime error.

## Trust Kernel (Web3, optional but recommended for production)

If you install `blackcat-config` and configure `trust.web3` + `trust.integrity`, core can enforce an external trust authority:
- reads on-chain state from the per-install `InstanceController`,
- validates the active root against `ReleaseRegistry` (`isTrustedRoot`) when the controller has a non-zero `releaseRegistry` pointer,
  and optionally pins the expected registry address via runtime config,
- verifies local files against an integrity manifest,
- blocks DB writes immediately on RPC quorum loss,
- allows reads (including key reads) only until `max_stale_sec`, then fails closed.

Policy hash notes:
- `TrustPolicyV1` (schema v1): `mode` + `max_stale_sec` (treated as **strict** enforcement).
- `TrustPolicyV2` (schema v2): adds `enforcement` (`strict` | `warn`).
  - `warn` is a **dev-only** posture and emits loud warnings; production policy should commit to `strict`.
- `TrustPolicyV3` (schema v3): adds **runtime config attestation** (binds the runtime config to an on-chain bytes32 slot).
  - in `strict` mode, a mismatched / missing attestation fails closed
  - the attestation key is `sha256("blackcat.runtime_config.canonical_sha256.v1")`
  - the recommended value is `sha256(canonical_json(runtime_config))` (see `blackcat-config` `runtime:attestation:runtime-config`)

Bootstrap helper:

```php
use BlackCat\Core\TrustKernel\TrustKernelBootstrap;

// Production (trust required): fail-closed.
// Throws if config is missing/invalid or trust.web3 is not configured.
$trust = TrustKernelBootstrap::bootFromBlackCatConfigOrFail();

// Library/optional: returns null when runtime config is missing or trust.web3 is not configured.
// Throws on invalid config (fail-closed).
$trustOptional = TrustKernelBootstrap::bootIfConfiguredFromBlackCatConfig();

// Legacy best-effort: returns null on any error (NOT recommended for production).
$trustLegacy = TrustKernelBootstrap::tryBootFromBlackCatConfig();
```

## Bypass resistance (policy)

The Trust Kernel installs guards at the **kernel primitive level** (`KeyManager`, `Database`).
To keep this security model intact across the ecosystem, bypass paths must be forbidden:

- Do not instantiate raw `PDO` (use `BlackCat\Core\Database`).
- Do not call `Database::getPdo()` (raw PDO access is guarded/denied; use wrapper methods).
- Do not read `*.key` files directly (use `BlackCat\Core\Security\KeyManager`).

Recommended CI check (requires `blackcatacademy/blackcat-config`):

```bash
php vendor/bin/config security:scan .
```
