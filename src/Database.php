<?php
declare(strict_types=1);

class DatabaseException extends RuntimeException {}

final class Database
{
    private static ?self $instance = null;
    private ?PDO $pdo = null;
    private array $config = [];

    /**
     * Soukromý konstruktor — singleton
     */
    private function __construct(array $config, PDO $pdo)
    {
        $this->config = $config;
        $this->pdo = $pdo;
    }

    /**
     * Inicializace (volej z bootstrapu) - eager connect
     *
     * Konfigurace: [
     *   'dsn' => 'mysql:host=...;dbname=...;charset=utf8mb4',
     *   'user' => 'dbuser',
     *   'pass' => 'secret',
     *   'options' => [PDO::ATTR_TIMEOUT => 5, ...],
     *   'init_commands' => [ "SET time_zone = '+00:00'", "SET sql_mode = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION'" ]
     * ]
     */
    public static function init(array $config): void
    {
        if (self::$instance !== null) {
            throw new DatabaseException('Database already initialized');
        }

        $dsn = $config['dsn'] ?? null;
        $user = $config['user'] ?? null;
        $pass = $config['pass'] ?? null;
        $givenOptions = $config['options'] ?? [];
        $initCommands = $config['init_commands'] ?? [];

        if (!$dsn) {
            throw new DatabaseException('Missing DSN in database configuration.');
        }

        // Bezpečnostní defaulty, které nelze přepsat
        $enforcedDefaults = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_STRINGIFY_FETCHES => false,
        ];

        $options = $givenOptions;
        foreach ($enforcedDefaults as $k => $v) {
            $options[$k] = $v;
        }

        try {
            $pdo = new PDO($dsn, $user, $pass, $options);

            // Run optional initialization commands (best-effort)
            if (!empty($initCommands) && is_array($initCommands)) {
                foreach ($initCommands as $cmd) {
                    if (!is_string($cmd)) continue;
                    try { $pdo->exec($cmd); } catch (PDOException $_) { /* ignore init failures */ }
                }
            }

            // Basic connectivity check
            try {
                $pdo->query('SELECT 1');
            } catch (PDOException $e) {
                // If the simple query fails, still create instance but note possible connectivity issues.
                if (class_exists('Logger')) {
                    // non-fatal connectivity warning
                    Logger::warn('Database connectivity check failed', null, ['error' => substr((string)$e->getMessage(), 0, 200)]);
                }
                throw new DatabaseException('Failed to connect to database', 0, $e);
            }

        } catch (PDOException $e) {
            // Minimal, non-sensitive log via centralized logger (no plaintext credentials).
            if (class_exists('Logger')) {
                // prefer systemError for richer info (silent on failure)
                try {
                    Logger::systemError($e, null, null, ['phase' => 'init', 'preview' => null]);
                } catch (\Throwable $_) {
                    // swallow — Logger must not throw
                }
            }
            throw new DatabaseException('Failed to connect to database', 0, $e);
        }

        self::$instance = new self($config, $pdo);
    }

    /**
     * Vrátí singleton instanci Database.
     */
    public static function getInstance(): self
    {
        if (self::$instance === null) {
            throw new DatabaseException('Database not initialized. Call Database::init($config) in bootstrap.');
        }
        return self::$instance;
    }

    /**
     * Vrátí PDO instanci (init musí být volané předtím)
     */
    public function getPdo(): PDO
    {
        if ($this->pdo === null) {
            throw new DatabaseException('Database not initialized properly (PDO missing).');
        }
        return $this->pdo;
    }

    /**
     * Ptá se, zda je DB initnuta
     */
    public static function isInitialized(): bool
    {
        return self::$instance !== null;
    }

    /* ----------------- Helper metody ----------------- */

    /**
     * Prepare and execute statement with safe explicit binding.
     * Returns PDOStatement on success or throws DatabaseException.
     */
    /** @var bool */
    private bool $debug = false;

    /** Volitelně povolit debug/logging (nevolat v produkci bez zabezpečeného logu) */
    public function enableDebug(bool $on = true): void
    {
        $this->debug = $on;
    }

    /**
     * Prepare and execute statement with smart binding.
     * Supports both named (:name) and positional (?) placeholders.
     * If $params is sequential (0-based keys) -> použije $stmt->execute($params)
     * Otherwise provede explicitní bindValue pro lepší typovou bezpečnost.
     */
    public function prepareAndRun(string $sql, array $params = []): \PDOStatement
    {
        $start = microtime(true);
        try {
            $pdo = $this->getPdo();
            $stmt = $pdo->prepare($sql);
            if ($stmt === false) {
                throw new DatabaseException('Failed to prepare statement.');
            }

            $isSequential = array_values($params) === $params;

            if ($isSequential) {
                $stmt->execute($params);
            } else {
                foreach ($params as $key => $value) {
                    $paramName = (strpos((string)$key, ':') === 0) ? $key : ':' . $key;

                    if ($value === null) {
                        $stmt->bindValue($paramName, null, PDO::PARAM_NULL);
                    } elseif (is_int($value)) {
                        $stmt->bindValue($paramName, $value, PDO::PARAM_INT);
                    } elseif (is_bool($value)) {
                        $stmt->bindValue($paramName, $value ? 1 : 0, PDO::PARAM_INT);
                    } elseif (is_string($value)) {
                        if (strpos($value, "\0") !== false && defined('PDO::PARAM_LOB')) {
                            $stmt->bindValue($paramName, $value, PDO::PARAM_LOB);
                        } else {
                            $stmt->bindValue($paramName, $value, PDO::PARAM_STR);
                        }
                    } else {
                        $stmt->bindValue($paramName, (string)$value, PDO::PARAM_STR);
                    }
                }
                $stmt->execute();
            }

            $durationMs = (microtime(true) - $start) * 1000.0;

            if ($this->debug && class_exists('Logger')) {
                try {
                    Logger::info('Database query executed', null, [
                        'preview' => $this->sanitizeSqlPreview($sql),
                        'duration_ms' => round($durationMs, 2),
                    ]);
                } catch (\Throwable $_) {}
            } elseif ($durationMs > $this->slowQueryThresholdMs && class_exists('Logger')) {
                try {
                    Logger::warn('Slow database query', null, [
                        'preview' => $this->sanitizeSqlPreview($sql),
                        'duration_ms' => round($durationMs, 2),
                    ]);
                } catch (\Throwable $_) {}
            }

            return $stmt;
        } catch (PDOException $e) {
            if (class_exists('Logger')) {
                try {
                    Logger::systemError($e, null, null, ['sql_preview' => $this->sanitizeSqlPreview($sql)]);
                } catch (\Throwable $_) {
                    // never bubble logging errors
                }
            }
            throw new DatabaseException('Database query failed', 0, $e);
        }
    }

    /** Jednoduché query bez parametrů */
    public function query(string $sql): \PDOStatement
    {
        try {
            $stmt = $this->getPdo()->query($sql);
            if ($stmt === false) throw new DatabaseException('Query failed');
            return $stmt;
        } catch (PDOException $e) {
            throw new DatabaseException('Query failed', 0, $e);
        }
    }

    /** Execute raw SQL with params — convenient wrapper */
    public function executeRaw(string $sql, array $params = []): int
    {
        $stmt = $this->prepareAndRun($sql, $params);
        return $stmt->rowCount();
    }

    /**
     * transaction wrapper with support for savepoints (nested transactions).
     * Vrací návratovou hodnotu callable.
     */
    public function transaction(callable $fn): mixed
    {
        $pdo = $this->getPdo();

        if (!$pdo->inTransaction()) {
            $this->beginTransaction();
            try {
                $res = $fn($this);
                $this->commit();
                return $res;
            } catch (\Throwable $e) {
                try { $this->rollback(); } catch (\Throwable $_) {}
                throw $e;
            }
        }

        // už jsme v transakci => savepoint
        static $fallbackCounter = 0;
        try {
            $sp = 'SP_' . bin2hex(random_bytes(6));
        } catch (\Throwable $_) {
            $fallbackCounter++;
            $sp = 'SP_FALLBACK_' . $fallbackCounter;
        }

        try {
            $pdo->exec("SAVEPOINT {$sp}");
            $res = $fn($this);
            $pdo->exec("RELEASE SAVEPOINT {$sp}");
            return $res;
        } catch (\Throwable $e) {
            try { $pdo->exec("ROLLBACK TO SAVEPOINT {$sp}"); } catch (\Throwable $_) {}
            throw $e;
        }
    }

    public function fetch(string $sql, array $params = []): ?array
    {
        $stmt = $this->prepareAndRun($sql, $params);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    public function fetchAll(string $sql, array $params = []): array
    {
        $stmt = $this->prepareAndRun($sql, $params);
        return $stmt->fetchAll();
    }

    /**
     * Execute an INSERT/UPDATE/DELETE and return affected rows.
     */
    public function execute(string $sql, array $params = []): int
    {
        $stmt = $this->prepareAndRun($sql, $params);
        return $stmt->rowCount();
    }

    /* transactions */
    public function beginTransaction(): bool
    {
        try { return $this->getPdo()->beginTransaction(); }
        catch (PDOException $e) { 
            if (class_exists('Logger')) {
            try { Logger::systemError($e, null, null, ['phase' => 'beginTransaction']); } catch (\Throwable $_) {}
            }
            throw new DatabaseException('Failed to begin transaction', 0, $e);
        }
    }

    public function commit(): bool
    {
        try { return $this->getPdo()->commit(); }
        catch (PDOException $e) { 
            if (class_exists('Logger')) {
            try { Logger::systemError($e, null, null, ['phase' => 'commit']); } catch (\Throwable $_) {}
            }
            throw new DatabaseException('Failed to commit transaction', 0, $e);
        }
    }

    public function rollback(): bool
    {
        try { return $this->getPdo()->rollBack(); }
        catch (PDOException $e) { 
            if (class_exists('Logger')) {
            try { Logger::systemError($e, null, null, ['phase' => 'rollback']); } catch (\Throwable $_) {}
            }
            throw new DatabaseException('Failed to rollback transaction', 0, $e);
        }
    }

    public function lastInsertId(?string $name = null): string
    {
        return $this->getPdo()->lastInsertId($name);
    }

    /* sanitizace SQL preview pro log (neukládat parametry s citlivými údaji) */
    private function sanitizeSqlPreview(string $sql): string
    {
        // collapse whitespace & remove newlines
        $s = preg_replace('/\s+/', ' ', trim($sql));
        $max = 300;
        if (function_exists('mb_strlen')) {
            return mb_strlen($s) > $max ? mb_substr($s, 0, $max) . '...' : $s;
        }
        return strlen($s) > $max ? substr($s, 0, $max) . '...' : $s;
    }

    /** @var int slow query threshold in ms (default 500) */
    private int $slowQueryThresholdMs = 500;

    /** Setter pro práh (volitelně zavolat z bootstrapu) */
    public function setSlowQueryThresholdMs(int $ms): void
    {
        $this->slowQueryThresholdMs = max(0, $ms);
    }

    /* ----------------- ochrana singletonu ----------------- */
    private function __clone() {}
    public function __wakeup(): void
    {
        throw new DatabaseException('Cannot unserialize singleton');
    }

    /**
     * Optional helper: quick health check (best-effort).
     */
    public function ping(): bool
    {
        try {
            $this->getPdo()->query('SELECT 1');
            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Vrátí první sloupec z prvního řádku (scalar), nebo $default když nic.
     */
    public function fetchValue(string $sql, array $params = [], $default = null): mixed
    {
        $row = $this->fetch($sql, $params);
        if ($row === null) return $default;
        foreach ($row as $v) { return $v; }
        return $default;
    }

    /**
     * Vrátí pole hodnot z jedné kolony (první sloupec každého řádku).
     * Např. SELECT id FROM ... -> [1,2,3]
     */
    public function fetchColumn(string $sql, array $params = []): array
    {
        $stmt = $this->prepareAndRun($sql, $params);
        $out = [];
        while (($val = $stmt->fetchColumn(0)) !== false) {
            $out[] = $val;
        }
        return $out;
    }

    /**
     * Vrátí asociativní pole párově key=>value podle první a druhé kolony.
     * Pokud dotaz vrací jen jednu kolonu, hodnoty budou = první kolona.
     */
    public function fetchPairs(string $sql, array $params = []): array
    {
        $rows = $this->fetchAll($sql, $params);
        $out = [];
        foreach ($rows as $r) {
            $vals = array_values($r);
            if (count($vals) === 0) continue;
            $k = $vals[0];
            $v = $vals[1] ?? $vals[0];
            $out[$k] = $v;
        }
        return $out;
    }

    /**
     * Zjistí, zda existuje nějaký záznam (bool).
     * Používá LIMIT 1 pro efektivitu pokud dotaz logicky vrací více.
     */
    public function exists(string $sql, array $params = []): bool
    {
        $stmt = $this->prepareAndRun($sql, $params);
        $row = $stmt->fetch();
        return $row !== false && $row !== null;
    }

    /**
     * Jednoduchý per-request cache pro časté read-only dotazy (např. kategorie v hlavičce).
     * TTL v sekundách (default 2s; 0 = bez expirace v rámci requestu).
     */
    public function cachedFetchAll(string $sql, array $params = [], int $ttl = 2): array
    {
        static $cache = [];
        $key = md5($sql . '|' . serialize($params));
        $now = time();
        if (isset($cache[$key]) && ($cache[$key]['expires'] === 0 || $cache[$key]['expires'] > $now)) {
            return $cache[$key]['data'];
        }
        $data = $this->fetchAll($sql, $params);
        $cache[$key] = [
            'expires' => $ttl > 0 ? $now + $ttl : 0,
            'data' => $data,
        ];
        return $data;
    }

    /**
     * Paginate helper: vrátí ['items'=>[], 'total'=>int, 'page'=>int, 'perPage'=>int]
     * Pokud je $countSql null, pokusí se automaticky spočítat COUNT(*) obalením dotazu (pozor na komplexní queries).
     * Preferuj předat $countSql pokud máš velký/komplexní dotaz.
     */
    public function paginate(string $sql, array $params = [], int $page = 1, int $perPage = 20, ?string $countSql = null): array
    {
        $page = max(1, (int)$page);
        $perPage = max(1, (int)$perPage);
        $offset = ($page - 1) * $perPage;

        // fetch items with limit
        $pagedSql = $sql . " LIMIT :__limit OFFSET :__offset";
        $paramsWithLimit = $params;
        $paramsWithLimit['__limit'] = $perPage;
        $paramsWithLimit['__offset'] = $offset;
        $items = $this->fetchAll($pagedSql, $paramsWithLimit);

        // total count
        if ($countSql !== null) {
            $total = (int)$this->fetchValue($countSql, $params, 0);
        } else {
            // bezpečnostní fallback — obalit query; může selhat u některých SQL konstrukcí
            try {
                $total = (int)$this->fetchValue("SELECT COUNT(*) FROM ({$sql}) AS __count_sub", $params, 0);
            } catch (\Throwable $_) {
                // pokud to nepůjde, zkus len(items) jako konservativní hodnota
                $total = count($items);
            }
        }

        return [
            'items' => $items,
            'total' => $total,
            'page'  => $page,
            'perPage' => $perPage,
        ];
    }
}