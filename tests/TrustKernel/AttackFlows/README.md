# TrustKernel attack-flow tests

Goal: simulate realistic attempts to bypass the Trust Kernel (Web3 trust + local integrity) and ensure the runtime fails closed in `strict` mode.

## Covered attack directions (examples)

- **Policy downgrade attempts**
  - try to switch from strict → warn without an on-chain policy hash change (must not be possible)
  - unknown policy hash must behave as strict (no downgrade fallback)

- **RPC manipulation**
  - chain ID mismatch
  - quorum disagreement / inconsistent responses
  - full RPC outage (stale mode behavior)

- **Local tampering**
  - file content tampering
  - manifest tampering / mismatch
  - symlink/path traversal attempts (root dir and files)

- **Contract pointer attacks**
  - `InstanceController` address has no code
  - EIP-1167 clone with missing/empty implementation code
  - `releaseRegistry` pointer mismatch (when pinned via config)
  - `ReleaseRegistry.isTrustedRoot(activeRoot)` returns false

This folder is intentionally grown over time: add a test whenever a new bypass class is identified.

