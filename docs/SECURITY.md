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
- verifies local files against an integrity manifest,
- blocks DB writes immediately on RPC quorum loss,
- allows reads (including key reads) only until `max_stale_sec`, then fails closed.

Bootstrap helper:

```php
use BlackCat\Core\TrustKernel\TrustKernelBootstrap;

// Best-effort: returns null if blackcat-config is not installed or trust.web3 is not configured.
$trust = TrustKernelBootstrap::tryBootFromBlackCatConfig();
```
