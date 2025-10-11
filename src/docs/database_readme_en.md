# 🐈‍⬛ BlackCat\Core\Database

Lightweight, secure, and production-ready database layer for PHP 8.1+  
No dependencies, no Composer required, fully **PSR-3 compatible** with a built-in fallback logger.

---

## ✨ Key Features

- ✅ **Safe prepared statements** – never interpolates raw values  
- ✅ **Built-in PSR-3 logger** (`LoggerInterface`) – silent and safe logging  
- ✅ **Automatic transactions and SAVEPOINTs** – supports nested transactions  
- ✅ **Helpers**: `fetchPairs`, `fetchValue`, `paginate`, and more  
- ✅ **Sanitized SQL preview** for safe debugging  
- ✅ **Unified error model** – wraps all PDO errors into `DatabaseException`  
- ✅ **Zero external dependencies** – pure PHP

---

## 🚀 Quick Start

### 1️⃣ Initialization (e.g., in `bootstrap.php`)

```php
use BlackCat\Core\Database;

$config = [
    'dsn' => 'mysql:host=localhost;dbname=eshop;charset=utf8mb4',
    'user' => 'eshop_user',
    'pass' => 'secret123',
    'init_commands' => [
        "SET time_zone = '+00:00'",
        "SET sql_mode = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION'"
    ],
];

Database::init($config);
$db = Database::getInstance();
```

---

### 2️⃣ Simple Queries

```php
// SELECT single row
$user = $db->fetch("SELECT * FROM users WHERE id = :id", ['id' => 42]);

// SELECT multiple rows
$list = $db->fetchAll("SELECT * FROM products WHERE active = 1");

// INSERT
$db->execute("INSERT INTO logs (event, created_at) VALUES (:e, NOW())", [
    'e' => 'UserLogin',
]);
```

---

### 3️⃣ Transactions with Auto-Rollback

```php
$result = $db->transaction(function(Database $tx) {
    $tx->execute("UPDATE accounts SET balance = balance - :amt WHERE id = :id", [
        'amt' => 500, 'id' => 1,
    ]);
    $tx->execute("UPDATE accounts SET balance = balance + :amt WHERE id = :id", [
        'amt' => 500, 'id' => 2,
    ]);
    return true; // commit
});
```

> If the callback throws an exception, the transaction **rolls back automatically**.  
> Nested calls are handled via **SAVEPOINTs** (when supported by the driver).

---

### 4️⃣ Helpers

```php
// Single scalar value
$count = $db->fetchValue("SELECT COUNT(*) FROM users WHERE active = 1");

// Key-value pair result
$pairs = $db->fetchPairs("SELECT id, username FROM users");

// Existence check
if ($db->exists("SELECT 1 FROM users WHERE email = :e", ['e' => 'test@example.com'])) {
    echo "User exists.";
}

// Pagination
$page = $db->paginate("SELECT * FROM books ORDER BY created DESC", [], 2, 10);
```

---

### 5️⃣ Caching & Debugging

```php
$db->enableDebug(true); // optional detailed logging
$db->setSlowQueryThresholdMs(1000); // slow query warning threshold

$rows = $db->cachedFetchAll(
    "SELECT * FROM categories ORDER BY name",
    [],
    ttl: 5 // cache 5 seconds
);
```

---

## 🧩 Logging (PSR-3)

The class accepts any PSR-3 compatible logger (e.g. Monolog).  
If none is provided, it automatically falls back to `LoggerPsrAdapter`.

```php
use BlackCat\Core\Log\LoggerPsrAdapter;

Database::init($config, new LoggerPsrAdapter());
```

All errors, warnings, and slow queries are logged safely,  
never exposing credentials or parameter values.

---

## 🧠 Security Principles

| Area | Status | Notes |
|------|--------|-------|
| SQL Injection | 🔒 protected via prepared statements |
| Sensitive data in logs | 🔒 sanitized and masked |
| Nested transactions | ⚙️ SAVEPOINT-based, fallback-safe |
| Exception handling | ⚙️ unified `DatabaseException` wrapper |
| Singleton protection | 🔒 cloning & unserialize blocked |
| SQL preview | 🧹 parameters replaced with `'…'` |

---

## 🧪 Testing

During testing, you can check if the singleton is initialized:

```php
if (Database::isInitialized()) {
    // ...
}
```

To reset between tests (optional):

```php
ReflectionClass::from(Database::class)
    ->getProperty('instance')
    ->setValue(null);
```

---

## ⚠️ Production Notes

- Always use **`charset=utf8mb4`** in DSN
- Avoid **`PDO::ATTR_PERSISTENT = true`** unless necessary
- Recommended MySQL settings:
  ```sql
  SET sql_mode = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION';
  SET time_zone = '+00:00';
  ```
- Long-running CLI scripts may require reconnect logic via `ping()`.

---

## 📚 License & Author

Part of the **BlackCat Core** framework  
(c) 2025 — MIT License  
Author: *Vit Black*

---