# BlackCat Core — Roadmap

## Scope (what core is)

`blackcat-core` is the **kernel**: minimal, auditable primitives used by the rest of the ecosystem.

Core owns:
- `BlackCat\Core\Database` (safe PDO wrapper)
- security primitives (`KeyManager`, `Crypto`, `CSRF`, `FileVault`)
- PSR-16 caches, small logging utilities, tiny migration runner
- small DX helpers (templates/validation)

Core does **not** own domain truth (schemas, views, auth flows, workers).

## Modular boundaries (single source of truth)

- Schemas/views/joins/repositories: `blackcatacademy/blackcat-database`
- DB encryption ingress + manifest: `blackcatacademy/blackcat-database-crypto` + `blackcat/crypto`
- Auth flows: `blackcatacademy/blackcat-auth`
- Sessions: `blackcatacademy/blackcat-sessions`
- Outbox/inbox workers: `blackcatacademy/blackcat-messaging`
- Mailing/notifications worker: `blackcatacademy/blackcat-mailing`
- Jobs: `blackcatacademy/blackcat-jobs`
- JWT: `blackcatacademy/blackcat-jwt`
- RBAC: `blackcatacademy/blackcat-rbac`
- Payments: gateway modules (e.g. `blackcatacademy/blackcat-gopay`)

## Stage 0 — Stabilization for the first stable release

- Freeze kernel boundaries and document them (README + `docs/*`).
- Remove non-kernel leftovers (app-specific helpers, legacy SQL snippets).
- Do not ship compatibility facades in core (use dedicated modules; see `docs/COMPATIBILITY.md`).
- Add CI (phpunit + phpstan) and a minimal unit test suite for the kernel primitives.
- Align ecosystem requirements (supported PHP version policy, required extensions).

## Stage 1 — Kernel hardening

- Database: finalize safety defaults (comment enforcement, guards, retry strategy) and document recommended presets per environment.
- Security: finalize key naming conventions, memory zeroing policy, and bridge behavior when `blackcat/crypto` is installed.
- Cache: document file cache encryption mode and operational constraints (permissions, quotas, GC strategy).

## Stage 2 — Integration contracts

- Provide contract-level docs for how core is used by:
  - `blackcat-database` (runtime + generated repositories)
  - `blackcat-database-crypto` (ingress adapters)
  - `blackcat-auth` / `blackcat-sessions` / `blackcat-messaging` (runtime composition)
- Add lightweight “contract tests” that can be executed in downstream modules.

## Stage 3 — DX / Operations

- Add structured examples (bootstrap templates for services and CLI tools).
- Add a small troubleshooting guide (common env/extension issues).
- Document recommended module composition presets (minimal / standard / high-security / multi-tenant).

## Stage 4 — Trust Kernel (Web3) (planned)

Goal: make `blackcat-core` sufficient for **minimal installs** while still enforcing a strict, auditable trust chain in production.

Core owns only the **runtime enforcement surface**. Contracts, installers, and CLI live elsewhere.

### Single source of truth (boundaries)

- On-chain authority + upgrade/attestation state machine: `blackcatacademy/blackcat-kernel-contracts`
- Signed release artifacts, hashing/Merkle primitives: `blackcatacademy/blackcat-integrity`
- Runtime config + file permission checks + policy defaults: `blackcatacademy/blackcat-config`
- Operational commands (optional): `blackcatacademy/blackcat-cli`
- Install/upgrade ceremony + secure bootstrap (optional tooling): `blackcatacademy/blackcat-installer` / `blackcatacademy/blackcat-install` / `blackcatacademy/blackcat-deployer`

### Runtime responsibilities (what core must enforce)

- **TrustKernel reader**: read on-chain state via EVM JSON-RPC (multi-RPC quorum; verify `chain_id`) and validate the contract address + code hash.
- **Local integrity**: compute/verify a local Merkle/tree root (or checksum set) for installed components and compare it to the on-chain attested root.
- **Fail-closed in prod**: if trust is unavailable or stale, enter safe-mode and expose a deterministic status for monitoring/CLI to consume.
  - Recommended prod default: `max_stale_sec = 180` (writes paused immediately on quorum loss; reads may be allowed until stale, then fail-closed).
- **Key gating** (critical): do not release/unwrap security-critical secrets unless trust checks pass (FTP tampering must not enable “silent reconfiguration”).
- **Pluggable policy**: tiered behavior (dev warns, prod refuses) must be a policy object, not ad-hoc `if`s scattered across repos.

### Minimal install flow (core-only on the server)

- A separate “setup device” (offline-ish) requests/creates the per-install smart contract and verifies it on-chain.
- Multiple signers confirm the setup (multi-sig threshold), ideally from separate devices.
- The server installs only `blackcat-core` (and its required deps), plus a runtime config file that contains:
  - chain + RPC quorum configuration,
  - contract addresses,
  - local integrity inputs (`trust.integrity.root_dir`, `trust.integrity.manifest`),
  - the chosen trust mode (root+URI vs full detail),
  - strict production policy defaults.

## Stage 5 — Trust Watchdog (“security grid”) (planned)

Goal: add an optional worker/sentinel layer that:
- detects missing check-ins / RPC quorum loss / suspicious state changes,
- triggers emergency actions (pause / incident reporting) via a remote trust anchor,
- minimizes the attacker’s time window and makes incidents auditable.

Design notes:
- [Trust Watchdog](TRUST_WATCHDOG.md)
