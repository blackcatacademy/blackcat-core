# Getting Started

`blackcat-core` can be used standalone, but the **recommended** way in the BlackCat ecosystem is to combine it with the dedicated modules:

- `blackcatacademy/blackcat-database` (schemas, views, joins, generated repositories)
- `blackcat/crypto` + `blackcatacademy/blackcat-database-crypto` (automatic DB encryption ingress)
- `blackcatacademy/blackcat-auth` (auth flows)
- `blackcatacademy/blackcat-sessions` (sessions)
- `blackcatacademy/blackcat-messaging` (outbox/inbox workers)
- `blackcatacademy/blackcat-mailing` (notifications + mail worker)

## Requirements

Required:
- PHP `^8.1`
- `ext-json`, `ext-sodium`
- `ext-pdo` + a driver (`pdo_mysql` / `pdo_pgsql` / …)

Optional:
- `ext-mbstring` (improves multibyte handling and SQL preview sanitization)
- `ext-curl` (used by some optional helpers like `BlackCat\Core\Security\Recaptcha`)

## Install

```bash
composer require blackcatacademy/blackcat-core
```

## Kernel bootstrap (Trust Kernel)

If you use `blackcatacademy/blackcat-config` and enable the Trust Kernel (`trust.web3` + `trust.integrity`),
prefer booting the kernel **before any app code runs**:

```php
use BlackCat\Core\Kernel\KernelBootstrap;

KernelBootstrap::bootOrFail(); // fail-closed
```

As a safety net, `KeyManager` and `Database` will attempt a one-time Trust Kernel auto-bootstrap when guards are missing,
but production should still bootstrap explicitly at process start.

When `blackcatacademy/blackcat-config` is installed, this safety net is **trust-required** and will fail closed if the Trust Kernel is not configured.

## Bootstrap: Database

```php
use BlackCat\Core\Database;
// Optional: if env/getenv is blocked, initialize config from a secure runtime config file.
// (only when blackcat-config is installed)
$runtimeConfigClass = implode('\\\\', ['BlackCat', 'Config', 'Runtime', 'Config']);
if (class_exists($runtimeConfigClass) && is_callable([$runtimeConfigClass, 'initFromFirstAvailableJsonFileIfNeeded'])) {
  $m = 'initFromFirstAvailableJsonFileIfNeeded';
  $runtimeConfigClass::$m();
}

Database::init([
  'dsn'  => class_exists($runtimeConfigClass) && is_callable([$runtimeConfigClass, 'get'])
    ? $runtimeConfigClass::get('db.dsn', $_ENV['DB_DSN'] ?? 'mysql:host=127.0.0.1;dbname=app;charset=utf8mb4')
    : ($_ENV['DB_DSN'] ?? 'mysql:host=127.0.0.1;dbname=app;charset=utf8mb4'),
  'user' => class_exists($runtimeConfigClass) && is_callable([$runtimeConfigClass, 'get'])
    ? $runtimeConfigClass::get('db.user', $_ENV['DB_USER'] ?? null)
    : ($_ENV['DB_USER'] ?? null),
  'pass' => class_exists($runtimeConfigClass) && is_callable([$runtimeConfigClass, 'get'])
    ? $runtimeConfigClass::get('db.pass', $_ENV['DB_PASS'] ?? null)
    : ($_ENV['DB_PASS'] ?? null),
  'appName' => 'my-service',
]);

$db = Database::getInstance();
```

Recommended flags in production:
- `requireSqlComment` (enforces `/*app:...*/` comment)
- `dangerousSqlGuard` (blocks UPDATE/DELETE without WHERE/LIMIT)

## Bootstrap: Keys directory (versioned keys)

Core uses **versioned key files** as the default convention:

- `<basename>_v1.key`, `<basename>_v2.key`, …

Examples:
- `crypto_key_v1.key` (envelope encryption key)
- `csrf_key_v1.key` (CSRF HMAC)
- `ip_hash_key_v1.key` (IP hashing for security telemetry)

See [Security](SECURITY.md).

## Recommended architecture

- Keep **schema truth** in `blackcat-database` only (no hardcoded SQL in domain modules).
- Keep **crypto ingress truth** in `blackcat-database-crypto` (encryption map + manifest).
- Treat `blackcat-core` as the audited kernel: primitives only, no business logic.

## Next steps

- Copy-paste snippets: [Bootstrap Examples](BOOTSTRAP_EXAMPLES.md)
- Common setup/runtime issues: [Troubleshooting](TROUBLESHOOTING.md)
- Legacy facade mapping: [Compatibility](COMPATIBILITY.md)
