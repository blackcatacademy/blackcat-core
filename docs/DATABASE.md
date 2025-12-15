# Database (BlackCat\Core\Database)

`BlackCat\Core\Database` is a hardened PDO wrapper used across the BlackCat ecosystem.

It focuses on:
- prepared statements (no string interpolation helpers)
- transaction helpers (including SAVEPOINT support)
- safety guards (optional)
- observability hooks (optional)

This is **not** a schema source of truth. For schemas/views/generated repositories use `blackcatacademy/blackcat-database`.

## Initialization

```php
use BlackCat\Core\Database;

Database::init([
  'dsn'  => 'pgsql:host=localhost;port=5432;dbname=blackcat',
  'user' => 'postgres',
  'pass' => 'secret',
  'appName' => 'my-service',

  // optional safety:
  'requireSqlComment'   => false,
  'dangerousSqlGuard'   => false,
  'statementTimeoutMs'  => 5_000,

  // optional read replica:
  'replica' => [
    'dsn'  => 'pgsql:host=replica;port=5432;dbname=blackcat',
    'user' => 'postgres',
    'pass' => 'secret',
  ],
]);

$db = Database::getInstance();
```

## Queries

- `fetch(string $sql, array $params = []): ?array`
- `fetchAll(string $sql, array $params = []): array`
- `execute(string $sql, array $params = []): int`
- `transaction(callable $fn): mixed`
- `txWithMeta(callable $fn, array $meta = [], array $opts = []): mixed` (recommended for observability)

## Safety guards (recommended)

Enable in bootstrap:
- `Database::getInstance()->requireSqlComment(true)` — require an `/*app:...*/` SQL comment.
- `Database::getInstance()->enableDangerousSqlGuard(true)` — blocks UPDATE/DELETE without WHERE (MySQL may allow LIMIT).
- `Database::getInstance()->enablePlaceholderGuard(true)` — warns on placeholder mismatch.

## Observability

The ecosystem uses SQL comments to propagate safe metadata (service, operation, correlation id):
- `BlackCat\Database\Support\Observability::sqlComment($meta)` (from `blackcat-database`)

When `requireSqlComment` is enabled, queries must be prefixed with `/*app:...*/`.

## Errors

Core wraps PDO failures and exposes a small set of meaningful exceptions:
- `DatabaseException` (base)
- `DeadlockException`
- `LockTimeoutException`
- `SerializationFailureException`
- `ConnectionGoneException`

## Query caching

For cross-request caching use PSR-16 caches and `BlackCat\Core\Database\QueryCache`.
For schema-driven repository-level caching and patterns, prefer `blackcat-database` services/repositories.

