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
- Keep compatibility facades but document them clearly (`docs/COMPATIBILITY.md`).
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
