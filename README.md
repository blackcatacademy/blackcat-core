![BlackCat Core](.github/blackcat-core-banner.png)

# BlackCat Core (Kernel)

[![CI](https://github.com/blackcatacademy/blackcat-core/actions/workflows/ci.yml/badge.svg)](https://github.com/blackcatacademy/blackcat-core/actions/workflows/ci.yml)

`blackcat-core` is the **minimal kernel** of the BlackCat ecosystem: a small, auditable set of primitives and utilities that other modules build on.

It is designed for two modes:
- **Kernel-only deployments** (extreme minimalism / custom systems)
- **Modular deployments** (recommended): `blackcat-core` + purpose-built modules (`blackcat-database`, `blackcat-auth`, `blackcat-messaging`, …)

## What lives here

- `BlackCat\Core\Database` — hardened PDO wrapper (prepared statements, retries, observability helpers, safety guards).
- `BlackCat\Database\SqlDialect` + `BlackCat\Database\Support\Observability` / `QueryObserver` — shared DB primitives used by the kernel DB wrapper and generated repositories.
- `BlackCat\Core\Security\KeyManager` / `Crypto` / `CSRF` / `FileVault` — low-level security primitives (versioned keys, AEAD, CSRF binding, file-at-rest encryption).
- `BlackCat\Core\Cache\*` — PSR-16 caches (memory/file/null) and locking support.
- `BlackCat\Core\Log\Logger` / `AuditLogger` — lightweight logging helpers for kernel-only stacks.
- `BlackCat\Core\Migrations\MigrationRunner` — tiny migration runner (no schema source of truth inside core).
- `BlackCat\Core\Templates\Templates` + `BlackCat\Core\Validation\Validator` — small DX helpers.

## What does NOT live here

To keep a single source of truth and avoid duplicated business logic, these belong to dedicated modules:

- **DB schema, views, joins, generated repositories** → `blackcatacademy/blackcat-database`
- **DB encryption ingress (automatic field encryption/hmac)** → `blackcatacademy/blackcat-database-crypto` (+ `blackcat/crypto`)
- **Auth flows (register/login/verify/reset/magic-link/webauthn)** → `blackcatacademy/blackcat-auth`
- **Sessions** → `blackcatacademy/blackcat-sessions`
- **Outbox/inbox workers + transports** → `blackcatacademy/blackcat-messaging`
- **Notifications + mailing worker** → `blackcatacademy/blackcat-mailing`
- **Job queue** → `blackcatacademy/blackcat-jobs`
- **JWT** → `blackcatacademy/blackcat-jwt`
- **RBAC** → `blackcatacademy/blackcat-rbac`
- **GoPay** → `blackcatacademy/blackcat-gopay`

## Compatibility facades (optional)

Some legacy class names are kept as **thin facades**. When the target module is installed, the class is `class_alias`-ed to the real implementation; otherwise it fails fast with a clear error:

- `BlackCat\Core\Messaging\Outbox` / `Inbox` → `blackcatacademy/blackcat-messaging`
- `BlackCat\Core\Mail\Mailer` → `blackcatacademy/blackcat-mailing`
- `BlackCat\Core\Security\Auth` / `LoginLimiter` → `blackcatacademy/blackcat-auth`
- Global `JWT`, `RBAC`, `JobQueue` → `blackcatacademy/blackcat-jwt`, `blackcatacademy/blackcat-rbac`, `blackcatacademy/blackcat-jobs`

New code should depend on the dedicated module directly.

## Install

```bash
composer require blackcatacademy/blackcat-core
```

## Kernel bootstrap (Trust Kernel)

For kernel-only deployments where Web3 integrity enforcement is mandatory, use:

```php
use BlackCat\Core\Kernel\KernelBootstrap;

KernelBootstrap::bootOrFail(); // fail-closed
```

This requires `blackcatacademy/blackcat-config` + a runtime config that includes `trust.web3` + `trust.integrity`.

Note:
- As a safety net, kernel primitives (`KeyManager`, `Database`) attempt a **one-time** Trust Kernel auto-bootstrap when a guard is missing.
- Production should still call `KernelBootstrap::bootOrFail()` as early as possible (before any app logic runs).

## Quick start (Database)

```php
use BlackCat\Core\Database;

Database::init([
  'dsn'  => 'mysql:host=127.0.0.1;dbname=app;charset=utf8mb4',
  'user' => 'app',
  'pass' => 'secret',
  'appName' => 'my-service',
]);

$db = Database::getInstance();
$row = $db->fetch('SELECT 1 AS ok');
```

## Documentation

- [Docs index](docs/README.md)
- [Bootstrap examples](docs/BOOTSTRAP_EXAMPLES.md)
- [Database](docs/DATABASE.md)
- [Security](docs/SECURITY.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Roadmap](docs/ROADMAP.md)

## Project meta

- Contributing: `.github/CONTRIBUTING.md`
- Security: `.github/SECURITY.md`
