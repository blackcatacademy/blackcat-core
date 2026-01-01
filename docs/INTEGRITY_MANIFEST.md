# Integrity manifest (v1)

The Trust Kernel protects against “code/config tamper” by comparing:

- **on-chain** `activeRoot` / `activeUriHash` (source of truth),
- **local** file hashes from an integrity manifest + a computed Merkle root.

If the local code tree differs from the on-chain commitment, the kernel fails closed in `strict` policy.

## Concepts

- `trust.integrity.root_dir`: absolute directory containing the files you want to protect.
  - Recommended: **immutable code directory** (no uploads, no runtime caches).
- `trust.integrity.manifest`: JSON file with `{ path => sha256(file) }` mapping.
  - Recommended: store **outside** of `root_dir` (e.g. `/etc/blackcat/integrity.manifest.json`).
- `root`: Merkle root computed from `(path, file_hash)` pairs (see `Sha256Merkle`).
- `uri`: optional release identifier (e.g. a GitHub release URL). If used, the chain commits to `activeUriHash=sha256(uri)`.

## Build a manifest (tool)

Use:
- `blackcat-core/scripts/trust-integrity-manifest-build.php`

Example:

```bash
php scripts/trust-integrity-manifest-build.php \
  --root=/srv/app \
  --out=/etc/blackcat/integrity.manifest.json \
  --uri=https://example.com/releases/app/1.0.0 \
  --pretty
```

Output is JSON with:
- `root` (bytes32 hex) → commit to `InstanceController.activeRoot`
- `uri_hash` (bytes32 hex) → commit to `InstanceController.activeUriHash` (optional)

## Production recommendation

Set:
- `trust.web3.mode="full"`

In `mode="full"` the Trust Kernel treats `root_dir` as immutable and fails closed if **unexpected files**
appear under `root_dir` (prevents “upload a new backdoor file that is not in the manifest”).

## Anti-bypass reminder

An integrity root does not help if your runtime can bypass the kernel:
- do not use raw PDO (use `BlackCat\Core\Database`)
- do not read `*.key` files directly (use `BlackCat\Core\Security\KeyManager`)

Use `blackcat-config` scan in CI:

```bash
php vendor/bin/config security:scan .
```

