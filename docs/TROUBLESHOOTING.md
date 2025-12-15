# Troubleshooting

## Missing PHP extensions

- **libsodium missing**: Crypto/KeyManager requires `ext-sodium`.
  - Symptom: `libsodium extension required`
  - Fix: install/enable `ext-sodium` for your PHP runtime.

- **PDO driver missing**: Database requires `ext-pdo` plus a driver (`pdo_pgsql`, `pdo_mysql`, …).
  - Symptom: `could not find driver`
  - Fix: install the correct PDO driver extension for your DB.

- **curl missing (optional)**: `BlackCat\Core\Security\Recaptcha` uses `ext-curl` unless you provide `opts['httpClient']`.
  - Symptom: `Recaptcha requires ext-curl or a custom httpClient callable`
  - Fix: install `ext-curl` or pass a custom HTTP client callable.

## Keys not found / wrong format

- Core prefers **versioned key files**: `<basename>_vN.key` (example: `crypto_key_v1.key`).
  - Symptom: `Key not configured: ... (no key file, no env)`
  - Fix: provision the key file in your keys dir, or set the relevant env var (base64).

## SQL comment required

If `requireSqlComment` is enabled, every non-trivial query must be prefixed with an SQL comment:

- Symptom: `SQL comment required (use Observability::sqlComment(meta))`
- Fix:
  - Prefix queries with `/*app:...*/` **or**
  - Use `BlackCat\\Database\\Support\\Observability::sqlComment($meta)` (from `blackcatacademy/blackcat-database`) to generate safe metadata comments.

## DB crypto ingress not booting

Repositories and services can auto-load the crypto ingress via `BlackCat\\Database\\Crypto\\IngressLocator`.

- If you set `BLACKCAT_DB_ENCRYPTION_REQUIRED=1`, missing ingress becomes a hard error.
- Common causes:
  - `BLACKCAT_DB_ENCRYPTION_MAP` not set or points to a non-existent file
  - `BLACKCAT_KEYS_DIR` not set or missing key files
  - Missing packages: `blackcat/crypto` + `blackcatacademy/blackcat-database-crypto`

## File cache permissions (FileCache)

`BlackCat\\Core\\Cache\\FileCache` expects to create and write files under its cache directory.

- Fix: ensure the cache directory exists, is writable, and has restrictive permissions (`0700`).

