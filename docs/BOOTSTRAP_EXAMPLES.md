# Bootstrap examples

This page contains **copy-paste** bootstrap snippets for common setups.

## Kernel-only (core only, no modules)

### 1) Install

```bash
composer require blackcatacademy/blackcat-core
```

### 2) Provision a local key (one-time)

Core expects versioned key files: `<basename>_vN.key`.

Example (32 bytes for libsodium AEAD keys):

```bash
mkdir -p keys
openssl rand -out keys/crypto_key_v1.key 32
chmod 0400 keys/crypto_key_v1.key
```

### 3) Use Crypto

```php
<?php
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use BlackCat\Core\Security\Crypto;

Crypto::initFromKeyManager(__DIR__ . '/keys');

$cipher = Crypto::encrypt('secret', 'compact_base64');
$plain = Crypto::decrypt($cipher);

if ($plain === null) {
    throw new RuntimeException('Decrypt failed');
}
```

## Modular DB stack (core + database + optional crypto ingress)

### 1) Install (DB + schema)

```bash
composer require blackcatacademy/blackcat-core blackcatacademy/blackcat-database
```

### 2) Install (DB + automatic encryption ingress)

```bash
composer require blackcat/crypto blackcatacademy/blackcat-database-crypto
```

### 3) Configure runtime config (recommended, no env)

Create a runtime config file (recommended locations include `/etc/blackcat/config.json` or `~/.config/blackcat/config.runtime.json`):

```json
{
  "crypto": {
    "keys_dir": "/srv/blackcat/keys",
    "manifest": "/etc/blackcat/crypto.manifest.json"
  }
}
```

To enable the Trust Kernel, add `trust.integrity` + `trust.web3` to the same runtime config file (see `blackcat-config` docs).

### 4) Bootstrap (TrustKernel + Database + ingress sanity-check)

```php
<?php
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use BlackCat\Core\Database;
use BlackCat\Database\Crypto\IngressLocator;
use BlackCat\Core\TrustKernel\TrustKernelBootstrap;

// Optional: installs DB/key access guards if `trust.web3` is configured via blackcat-config runtime config.
// For "trust required" production deployments, prefer `bootFromBlackCatConfigOrFail()`.
$trust = TrustKernelBootstrap::bootIfConfiguredFromBlackCatConfig();

Database::init([
    'dsn' => $_ENV['DB_DSN'] ?? 'pgsql:host=127.0.0.1;port=5432;dbname=app',
    'user' => $_ENV['DB_USER'] ?? 'postgres',
    'pass' => $_ENV['DB_PASS'] ?? 'secret',
    'appName' => 'my-service',
    'requireSqlComment' => false,
    'dangerousSqlGuard' => true,
]);

// Fail-closed by default: this throws unless ingress is configured.
$ingress = IngressLocator::requireAdapter();
// validate the adapter can encrypt a sample payload
$ingress->encrypt('example_table', ['example' => 'value']);
```
