<?php
declare(strict_types=1);

namespace BlackCat\Core;

use BlackCat\Database\SqlDialect;
use BlackCat\Database\Support\Observability;
use Psr\Log\LoggerInterface;

class DatabaseException extends \RuntimeException {}
/** More specific exceptions for simpler retry/alerting. */
class DeadlockException extends DatabaseException {}
class LockTimeoutException extends DatabaseException {}
class SerializationFailureException extends DatabaseException {}
class ConnectionGoneException extends DatabaseException {}

final class Database
{
    private static ?self $instance = null;
    /** @var null|callable(string):void */
    private static $writeGuard = null;
    private static bool $writeGuardLocked = false;
    /** @var null|callable(string):void */
    private static $readGuard = null;
    private static bool $readGuardLocked = false;
    /** @var null|callable(string):void */
    private static $pdoAccessGuard = null;
    private static bool $pdoAccessGuardLocked = false;
    private static bool $trustKernelAutoBootAttempted = false;
    private ?\PDO $pdo = null;
    /** Optional read-replica PDO */
    private ?\PDO $pdoRead = null;

    private array $config = [];
    private ?LoggerInterface $logger = null;
    private string $dsnId = 'unknown';
    private bool $readOnlyGuard = false;
    /** Force route for the current call context: 'primary'|'replica'|null */
    private ?string $routeOverride = null;

    // Circuit breaker (primary)
    private int $cbFails = 0;
    private ?int $cbOpenUntil = null; // unix ts
    private int $cbThreshold = 8;
    private int $cbCooldownSec = 10;

    /** stick-to-primary window after writes (ms) for eventual consistency */
    private int $stickAfterWriteMs = 500;
    private float $lastWriteAtMs = 0.0;

    // Replica cooldown on failure + reconnect
    private ?int $replicaDownUntil = null; // unix ts
    private int $replicaCooldownSec = 10;

    // require SQL comment enforcement flag
    private bool $requireSqlComment = false;

    // Debug & slow query
    private bool $debug = false;
    private int $slowQueryThresholdMs = 500;

    // Auto-EXPLAIN sampling for slow SELECTs
    private bool $autoExplain = false;
    private bool $autoExplainAnalyze = false;
    // Guard: UPDATE/DELETE without WHERE (MySQL may alternatively allow LIMIT)
    private bool $dangerousSqlGuard = false;
    // Guard: placeholder mismatch (warn only)
    private bool $placeholderGuard = false;
    // SQL firewall: blocks obvious SQL injection escalation primitives (multi-statements, file IO, etc.).
    /** @var 'strict'|'warn'|'off' */
    private string $sqlFirewallMode = 'strict';
    // Observers + ring buffer of recent queries
    /** @var array<\BlackCat\Database\Support\QueryObserver> */
    private array $observers = [];
    private int $lastQueriesMax = 200;
    /** @var array<int,array{ts:float,ms?:float,sql:string,route:string,err?:string}> */
    private array $lastQueries = [];

    // Replica health-gate (lag)
    /** @var callable|null fn(PDO $replica): ?int lagMs */
    private $replicaHealthChecker = null;
    private ?int $replicaMaxLagMs = null;           // if set and lag > max -> route to primary
    private int $replicaHealthCheckSec = 2;         // throttle
    private ?int $replicaHealthCheckedAt = null;
    private ?int $replicaLagMs = null;

    // Simple N+1 detector
    private bool $n1Enabled = false;
    private int $n1Threshold = 5;
    private int $n1MaxSamples = 3;
    /** @var array<string,int> fingerprint => count */
    private array $n1Counts = [];
    /** @var array<string,bool> */
    private array $n1Warned = [];
    /** @var array<string,array<int,string>> fingerprint => sample origins */
    private array $n1Samples = [];

    /** Private constructor — singleton. */
    private function __construct(array $config, \PDO $pdo, ?LoggerInterface $logger = null, ?\PDO $pdoRead = null)
    {
        $this->config = $config;
        $this->pdo = $pdo;
        $this->pdoRead = $pdoRead;
        $this->logger = $logger;
    }

    private static function dsnFingerprint(string $dsn): string {
        $m = [];
        // mysql & pgsql by host/port/dbname
        if (preg_match('~^(mysql|pgsql):.*?host=([^;]+)(?:;port=([0-9]+))?.*?(?:;dbname=([^;]+))?~i', $dsn, $m)) {
            $drv = strtolower($m[1]);
            $host = $m[2];
            $port = (($m[3] ?? '') !== '') ? (string)$m[3] : ($drv === 'mysql' ? '3306' : '5432');
            $db = $m[4] ?? '';
            return "{$drv}://{$host}:{$port}/{$db}";
        }
        // sqlite path / :memory:
        if (preg_match('~^sqlite:(?://)?(.+)$~i', $dsn, $m)) {
            $path = $m[1];
            if (stripos($path, ':memory:') === 0) return 'sqlite://memory';
            // strip query/fragment
            $path = preg_replace('~[?#].*$~', '', $path) ?? $path;
            $base = basename($path);
            return 'sqlite://' . ($base !== '' ? $base : 'db');
        }
        return substr(hash('sha256', $dsn), 0, 16);
    }

    /**
     * Initialization (call from bootstrap) - eager connect.
     *
     * Configuration: [
     *   'dsn' => 'mysql:host=...;dbname=...;charset=utf8mb4',
     *   'user' => 'dbuser',
     *   'pass' => 'secret',
     *   'options' => [\PDO::ATTR_TIMEOUT => 5, ...],
     *   'init_commands' => [ "SET time_zone = '+00:00'" ],
     *   'appName' => 'blackcat',
     *   'requireSqlComment' => bool,
     *   'replica' => [
     *       'dsn' => 'mysql:host=replica;dbname=...;charset=utf8mb4',
     *       'user' => 'dbuser', 'pass' => 'secret',
     *       'options' => [], 'init_commands' => []
     *   ],
     *   'replicaStickMs' => 500,
     *   // Optional:
     *   'sqlMode' => 'STRICT_TRANS_TABLES,...',   // MySQL/MariaDB
     *   'idleTxTimeoutMs' => 0,                   // PG: idle_in_transaction_session_timeout
     *   'statementTimeoutMs' => 5000,
     *   'lockWaitTimeoutSec' => 2,
     *   // Replica health-gate:
     *   'replicaMaxLagMs' => 250,                 // e.g. 250 ms
     *   'replicaHealthCheckSec' => 2
     *   // SQL firewall (recommended):
     *   //  - strict: throw on violations (default)
     *   //  - warn: log and continue (dev only)
     *   //  - off: disable (not recommended)
     *   'sqlFirewallMode' => 'strict'|'warn'|'off',
     * ]
     */
    public static function init(array $config, ?LoggerInterface $logger = null): void
    {
        if (self::$instance !== null) {
            throw new DatabaseException('Database already initialized');
        }

        $dsn = $config['dsn'] ?? null;
        $user = $config['user'] ?? null;
        $pass = $config['pass'] ?? null;
        $givenOptions = $config['options'] ?? [];
        $initCommands = $config['init_commands'] ?? [];
        $appName = (string)($config['appName'] ?? 'blackcat');
        $requireSqlComment = (bool)($config['requireSqlComment'] ?? false);
        $replicaCfg = $config['replica'] ?? null;
        $stickMs = (int)($config['replicaStickMs'] ?? 500);
        // Replica health-gate (optional)
        $replicaMaxLagMs = isset($config['replicaMaxLagMs']) ? (int)$config['replicaMaxLagMs'] : null;
        $replicaHealthCheckSec = isset($config['replicaHealthCheckSec']) ? (int)$config['replicaHealthCheckSec'] : 2;

        if (!$dsn) {
            throw new DatabaseException('Missing DSN in database configuration.');
        }

        $pdo = self::createPdo($dsn, $user, $pass, $givenOptions, $initCommands, $logger, $appName, $config);

        $pdoRead = null;
        if (is_array($replicaCfg) && !empty($replicaCfg['dsn'])) {
            $pdoRead = self::createPdo(
                (string)$replicaCfg['dsn'],
                $replicaCfg['user'] ?? null,
                $replicaCfg['pass'] ?? null,
                $replicaCfg['options'] ?? [],
                $replicaCfg['init_commands'] ?? [],
                $logger,
                $appName,
                $config
            );
        }

        $inst = new self($config, $pdo, $logger, $pdoRead);
        $inst->dsnId = is_string($dsn) ? self::dsnFingerprint($dsn) : 'unknown';
        $inst->stickAfterWriteMs = max(0, $stickMs);
        $inst->replicaMaxLagMs = $replicaMaxLagMs;
        $inst->replicaHealthCheckSec = max(1, $replicaHealthCheckSec);
        $fwMode = $config['sqlFirewallMode'] ?? 'strict';
        if (is_bool($fwMode)) { $fwMode = $fwMode ? 'strict' : 'off'; }
        if (!is_string($fwMode)) { $fwMode = 'strict'; }
        $inst->setSqlFirewallMode($fwMode);
        if (is_string($dsn) && str_starts_with($dsn,'mysql:') && !str_contains($dsn,'charset=')) {
            $logger?->warning('DSN without charset=utf8mb4; consider adding it for MySQL.');
        }
        if ($requireSqlComment) {
            $inst->requireSqlComment(true);
        }
        self::$instance = $inst;
    }

    /**
     * Initialize Database singleton using an already-created PDO instance.
     *
     * Intended for legacy bridges where the application already owns PDO (e.g. old code paths
     * calling APIs that now expect {@see \BlackCat\Core\Database}).
     *
     * If Database is already initialized, this is a no-op.
     */
    public static function initFromPdo(\PDO $pdo, array $config = [], ?LoggerInterface $logger = null, ?\PDO $pdoRead = null): void
    {
        if (self::$instance !== null) {
            return;
        }

        // Enforce the same safety defaults as createPdo() (best-effort; some drivers may reject).
        try { $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION); } catch (\Throwable) {}
        try { $pdo->setAttribute(\PDO::ATTR_EMULATE_PREPARES, false); } catch (\Throwable) {}
        try { $pdo->setAttribute(\PDO::ATTR_DEFAULT_FETCH_MODE, \PDO::FETCH_ASSOC); } catch (\Throwable) {}
        try { $pdo->setAttribute(\PDO::ATTR_STRINGIFY_FETCHES, false); } catch (\Throwable) {}
        try {
            if ((string)$pdo->getAttribute(\PDO::ATTR_DRIVER_NAME) === 'mysql') {
                if (defined('PDO::MYSQL_ATTR_MULTI_STATEMENTS')) {
                    $pdo->setAttribute(\PDO::MYSQL_ATTR_MULTI_STATEMENTS, false);
                }
                if (defined('PDO::MYSQL_ATTR_LOCAL_INFILE')) {
                    $pdo->setAttribute(\PDO::MYSQL_ATTR_LOCAL_INFILE, false);
                }
            }
        } catch (\Throwable) {}

        if ($pdoRead instanceof \PDO) {
            try { $pdoRead->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION); } catch (\Throwable) {}
            try { $pdoRead->setAttribute(\PDO::ATTR_EMULATE_PREPARES, false); } catch (\Throwable) {}
            try { $pdoRead->setAttribute(\PDO::ATTR_DEFAULT_FETCH_MODE, \PDO::FETCH_ASSOC); } catch (\Throwable) {}
            try { $pdoRead->setAttribute(\PDO::ATTR_STRINGIFY_FETCHES, false); } catch (\Throwable) {}
            try {
                if ((string)$pdoRead->getAttribute(\PDO::ATTR_DRIVER_NAME) === 'mysql') {
                    if (defined('PDO::MYSQL_ATTR_MULTI_STATEMENTS')) {
                        $pdoRead->setAttribute(\PDO::MYSQL_ATTR_MULTI_STATEMENTS, false);
                    }
                    if (defined('PDO::MYSQL_ATTR_LOCAL_INFILE')) {
                        $pdoRead->setAttribute(\PDO::MYSQL_ATTR_LOCAL_INFILE, false);
                    }
                }
            } catch (\Throwable) {}
        }

        $inst = new self($config, $pdo, $logger, $pdoRead);

        $dsnId = 'pdo';
        try {
            $drv = (string)$pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);
            if ($drv !== '') {
                $dsnId = 'pdo:' . $drv;
            }
        } catch (\Throwable) {
        }
        $inst->dsnId = $dsnId;

        $inst->stickAfterWriteMs = max(0, (int)($config['replicaStickMs'] ?? 500));
        $inst->replicaMaxLagMs = isset($config['replicaMaxLagMs']) ? (int)$config['replicaMaxLagMs'] : null;
        $inst->replicaHealthCheckSec = max(1, (int)($config['replicaHealthCheckSec'] ?? 2));

        $requireSqlComment = (bool)($config['requireSqlComment'] ?? false);
        if ($requireSqlComment) {
            $inst->requireSqlComment(true);
        }
        $fwMode = $config['sqlFirewallMode'] ?? 'strict';
        if (is_bool($fwMode)) { $fwMode = $fwMode ? 'strict' : 'off'; }
        if (!is_string($fwMode)) { $fwMode = 'strict'; }
        $inst->setSqlFirewallMode($fwMode);

        self::$instance = $inst;
    }

    private static function createPdo(
        string $dsn, ?string $user, ?string $pass, array $givenOptions, array $initCommands,
        ?LoggerInterface $logger, string $appName, array $config
    ): \PDO {
        $enforcedDefaults = [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_EMULATE_PREPARES => false,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
            \PDO::ATTR_STRINGIFY_FETCHES => false,
        ];
        $options = $givenOptions;
        foreach ($enforcedDefaults as $k => $v) { $options[$k] = $v; }

        if (is_string($dsn) && str_starts_with($dsn, 'mysql:') && defined('PDO::MYSQL_ATTR_USE_BUFFERED_QUERY')) {
            $options[\PDO::MYSQL_ATTR_USE_BUFFERED_QUERY] = false;
        }
        if (is_string($dsn) && str_starts_with($dsn, 'mysql:') && defined('PDO::MYSQL_ATTR_MULTI_STATEMENTS')) {
            $options[\PDO::MYSQL_ATTR_MULTI_STATEMENTS] = false;
        }
        if (is_string($dsn) && str_starts_with($dsn, 'mysql:') && defined('PDO::MYSQL_ATTR_LOCAL_INFILE')) {
            $options[\PDO::MYSQL_ATTR_LOCAL_INFILE] = false;
        }
        $pdo = new \PDO($dsn, $user, $pass, $options);
        if ($pdo->getAttribute(\PDO::ATTR_DRIVER_NAME) === 'mysql' && defined('PDO::MYSQL_ATTR_USE_BUFFERED_QUERY')) {
            $pdo->setAttribute(\PDO::MYSQL_ATTR_USE_BUFFERED_QUERY, false);
        }
        if ($pdo->getAttribute(\PDO::ATTR_DRIVER_NAME) === 'mysql' && defined('PDO::MYSQL_ATTR_MULTI_STATEMENTS')) {
            $pdo->setAttribute(\PDO::MYSQL_ATTR_MULTI_STATEMENTS, false);
        }
        if ($pdo->getAttribute(\PDO::ATTR_DRIVER_NAME) === 'mysql' && defined('PDO::MYSQL_ATTR_LOCAL_INFILE')) {
            $pdo->setAttribute(\PDO::MYSQL_ATTR_LOCAL_INFILE, false);
        }

        try {
            $driver = (string)$pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);

            if ($driver === 'pgsql') {
                $pdo->exec("SET TIME ZONE 'UTC'");
                if ($appName !== '') {
                $pdo->exec("SET application_name = " . self::q($pdo, $appName));
                }
                $stmMs = (int)($config['statementTimeoutMs'] ?? 5000);
                if ($stmMs > 0) { $pdo->exec("SET statement_timeout = " . (int)$stmMs); }
                // Optional: idle_in_transaction_session_timeout
                $idleTxMs = (int)($config['idleTxTimeoutMs'] ?? 0);
                if ($idleTxMs > 0) {
                    $pdo->exec("SET idle_in_transaction_session_timeout = " . (int)$idleTxMs);
                }

            } elseif ($driver === 'mysql') {
                $pdo->exec("SET time_zone = '+00:00'");
                $lockWaitSec = (int)($config['lockWaitTimeoutSec'] ?? 2);
                if ($lockWaitSec > 0) { $pdo->exec("SET SESSION innodb_lock_wait_timeout = " . $lockWaitSec); }
                $stmMs = (int)($config['statementTimeoutMs'] ?? 0);
                if ($stmMs > 0) {
                    try { $pdo->exec("SET SESSION max_execution_time = " . $stmMs); }
                    catch (\Throwable $_) { $pdo->exec("SET SESSION max_statement_time = " . max(1, (int)ceil($stmMs / 1000.0))); }
                }
                // Only apply sql_mode if explicitly configured.
                if (!empty($config['sqlMode']) && is_string($config['sqlMode'])) {
                    $pdo->exec("SET SESSION sql_mode = " . self::q($pdo, $config['sqlMode']));
                }
            }
        } catch (\Throwable $e) {
            if ($logger !== null) {
                try { $logger->warning('db-session-settings-failed', ['error' => $e->getMessage()]); } catch (\Throwable $_) {}
            }
        }

        // Init commands
        foreach ((array)$initCommands as $cmd) {
            if (is_string($cmd)) {
                try { $pdo->exec($cmd); } catch (\Throwable $_) {}
            }
        }

        // Basic connectivity check
        try {
            $pdo->query('SELECT 1');
        } catch (\PDOException $e) {
            if ($logger !== null) {
                try { $logger->warning('Database connectivity check failed', ['error' => substr((string)$e->getMessage(), 0, 200)]); } catch (\Throwable $_) {}
            }
            throw new DatabaseException('Failed to connect to database', 0, $e);
        }

        return $pdo;
    }

    private static function q(\PDO $pdo, string $value): string {
        $q = $pdo->quote($value);
        return $q !== false ? $q : "'" . str_replace("'", "''", $value) . "'";
    }

    /** Helper to decide whether to use replica for this query */
    private function choosePdoFor(string $sql): \PDO
    {
        // Scoped override
        if ($this->routeOverride === 'primary') return $this->pdoPrimary();
        if ($this->routeOverride === 'replica' && $this->pdoRead !== null) {
            $s = ltrim($sql);
            if ($this->isSimpleSelectForReplica($s) && $this->isReplicaHealthy()) return $this->pdoRead;
            return $this->pdoPrimary();
        }

        if ($this->pdoRead === null) return $this->pdoPrimary();
        // in transaction? always primary
        if ($this->inTransaction()) return $this->pdoPrimary();

        // Inline hints
        $u = strtoupper($sql);
        if (str_contains($u, '/*FORCE:PRIMARY*/')) { return $this->pdoPrimary(); }
        if (str_contains($u, '/*FORCE:REPLICA*/')) {
            if ($this->isSimpleSelectForReplica($sql) && $this->isReplicaHealthy()) {
                return $this->pdoRead ?? $this->pdoPrimary();
            }
            return $this->pdoPrimary();
        }

        // Replica in cooldown?
        if ($this->replicaDownUntil && time() < $this->replicaDownUntil) {
            return $this->pdoPrimary();
        }

        // stick-to-primary window after write
        if ($this->stickAfterWriteMs > 0 && $this->lastWriteAtMs > 0) {
            $delta = (int)round(microtime(true) * 1000.0 - $this->lastWriteAtMs);
            if ($delta < $this->stickAfterWriteMs) {
                return $this->pdoPrimary();
            }
        }

        $s = ltrim($sql);
        // strip simple comments
        if (str_starts_with($s, '/*')) { $s = preg_replace('~/\*.*?\*/~s', '', $s) ?? $s; $s = ltrim($s); }
        if (str_starts_with($s, '--')) {
            $isLineComment = true;
            if ($this->isMysql()) {
                $next = $s[2] ?? '';
                $isLineComment = $next !== '' && ord($next) <= 0x20;
            }
            if ($isLineComment) {
                $s = preg_replace('~--.*?$~m', '', $s) ?? $s;
                $s = ltrim($s);
            }
        }
        if (!preg_match('~^([A-Z]+)~i', $s, $m)) return $this->pdoPrimary();
        $verb = strtoupper($m[1]);

        // "WITH" can be SELECT or DML; route to primary unless it is clearly a simple SELECT (no locks).
        if ($verb === 'WITH') {
            if ($this->isSimpleSelectForReplica($s) && $this->isReplicaHealthy()) {
                return $this->pdoRead ?? $this->pdoPrimary();
            }
            return $this->pdoPrimary();
        }

        // Route SELECT to replica only if there are no locks and no SELECT ... INTO.
        if ($verb === 'SELECT') {
            if ($this->isSelectNeedingPrimary($s)) {
                return $this->pdoPrimary();
            }
            if (!$this->isReplicaHealthy()) return $this->pdoPrimary();
            return $this->pdoRead ?? $this->pdoPrimary();
        }

        // SHOW is read-only -> replica OK.
        if ($verb === 'SHOW') {
            return $this->pdoRead ?? $this->pdoPrimary();
        }

        // EXPLAIN: default to replica, but for PG EXPLAIN ANALYZE with DML prefer primary (it actually executes the DML).
        if ($verb === 'EXPLAIN') {
            $uu = strtoupper($s);
            $hasAnalyze = (bool)preg_match('~\bANALYZE\b~', $uu);
            $innerVerb = null;
            if (preg_match('~\bEXPLAIN(?:\s*\([^)]*\))?\s+([A-Z]+)~', $uu, $mm)) {
                $innerVerb = $mm[1];
            }
            if ($this->isPg() && $hasAnalyze && $innerVerb !== 'SELECT') {
                return $this->pdoPrimary();
            }
            return $this->pdoRead ?? $this->pdoPrimary();
        }
        return $this->pdoPrimary();
    }

    // SELECT requiring primary (FOR UPDATE/SHARE, LOCK IN SHARE MODE, SELECT INTO).
    private function isSelectNeedingPrimary(string $sql): bool
    {
        $u = strtoupper($sql);
        if (preg_match('~\bFOR\s+UPDATE\b~', $u)) return true;
        if (preg_match('~\bFOR\s+SHARE\b~', $u)) return true; // PG
        if (preg_match('~\bLOCK\s+IN\s+SHARE\s+MODE\b~', $u)) return true; // MySQL
        // SELECT ... INTO – dialect-specific behavior:
        //  - PG: SELECT INTO creates a table -> primary
        //  - MySQL/MariaDB: INTO OUTFILE/DUMPFILE has side effects -> primary
        //    but "INTO @user_var" is read-only -> replica OK
        if ($this->isPg()) {
            if (preg_match('~\bSELECT\b.*\bINTO\b~s', $u)) return true;
        } else { // MySQL/MariaDB
            if (preg_match('~\bINTO\s+(OUTFILE|DUMPFILE)\b~', $u)) return true;
            if (preg_match('~\bSELECT\b.*\bINTO\b~s', $u) && !preg_match('~\bINTO\s+@~', $u)) return true;
        }
        return false;
    }

    // Simple heuristic test for "WITH ... SELECT" without locks (otherwise -> primary).
    private function isSimpleSelectForReplica(string $sql): bool
    {
        $u = strtoupper($sql);
        if (!preg_match('~\bSELECT\b~', $u)) return false;
        return !$this->isSelectNeedingPrimary($u);
    }

    /** Returns the Database singleton instance. */
    public static function getInstance(): self
    {
        if (self::$instance === null) {
            throw new DatabaseException('Database not initialized. Call Database::init($config) in bootstrap.');
        }
        return self::$instance;
    }

    private function pdoPrimary(): \PDO
    {
        if ($this->pdo === null) {
            throw new DatabaseException('Database not initialized properly (PDO missing).');
        }
        return $this->pdo;
    }

    public function getPdo(): \PDO
    {
        if (self::$pdoAccessGuardLocked && self::$pdoAccessGuard === null) {
            throw new DatabaseException('Database PDO access guard is locked but missing; restart the process.');
        }

        if (self::$pdoAccessGuard === null) {
            $this->autoBootTrustKernelIfPossible();
        }

        if (self::$pdoAccessGuard !== null) {
            (self::$pdoAccessGuard)('db.raw_pdo');
        }
        return $this->pdoPrimary();
    }

    public function hasReplica(): bool { return $this->pdoRead !== null; }

    public function setLogger(\Psr\Log\LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    public function getLogger(): ?LoggerInterface
    {
        return $this->logger;
    }

    public static function isInitialized(): bool
    {
        return self::$instance !== null;
    }

    public function close(): void
    {
        $this->pdo = null;
        $this->pdoRead = null;
    }

    public function dialect(): SqlDialect
    {
        $drv = $this->driver();
        if ($drv === 'pgsql') return SqlDialect::postgres;
        if ($drv === 'mysql' || $drv === 'mariadb') return SqlDialect::mysql;
        return SqlDialect::mysql;
    }

    public function enableDebug(bool $on = true): void { $this->debug = $on; }
    /** Enable blocking UPDATE/DELETE without WHERE (MySQL may alternatively allow LIMIT). */
    public function enableDangerousSqlGuard(bool $on = true): void { $this->dangerousSqlGuard = $on; }
    /** Enable EXPLAIN sampling for slow SELECTs (threshold via setSlowQueryThresholdMs()). */
    public function enableAutoExplain(bool $on = true, bool $analyze = false): void { $this->autoExplain = $on; $this->autoExplainAnalyze = $analyze; }
    /** Enable placeholder/parameter mismatch guard (warns via logger). */
    public function enablePlaceholderGuard(bool $on = true): void { $this->placeholderGuard = $on; }
    /** SQL firewall mode: strict|warn|off. */
    public function setSqlFirewallMode(string $mode): void
    {
        $m = strtolower(trim($mode));
        if (!in_array($m, ['strict', 'warn', 'off'], true)) {
            throw new DatabaseException('Invalid sqlFirewallMode (expected strict|warn|off).');
        }
        $this->sqlFirewallMode = $m;
    }
    /** Returns SQL firewall mode. */
    public function sqlFirewallMode(): string { return $this->sqlFirewallMode; }
    /** Adds a query observer (e.g. Prometheus/StatsD). */
    public function addObserver(\BlackCat\Database\Support\QueryObserver $obs): void { $this->observers[] = $obs; }
    /** Maximum size of the recent-queries ring buffer. */
    public function setLastQueriesMax(int $n): void { $this->lastQueriesMax = max(10, $n); }
    /** Returns recent queries (newest last). */
    public function getLastQueries(): array { return $this->lastQueries; }
    /** Enable the simple N+1 detector. */
    public function enableNPlusOneDetector(bool $on = true, int $threshold = 5, int $maxSamples = 3): void {
        $this->n1Enabled = $on; $this->n1Threshold = max(2, $threshold); $this->n1MaxSamples = max(1, $maxSamples);
    }
    public function n1Stats(): array { return ['enabled'=>$this->n1Enabled,'threshold'=>$this->n1Threshold,'counts'=>$this->n1Counts]; }

    public function exec(string $sql, array $params = []): int
    {
        $this->circuitCheck();
        $stmt = $this->prepareAndRun($sql, $params);
        try {
            $n = $stmt->rowCount();
            if ($this->isWriteSql($sql)) {
                $this->lastWriteAtMs = microtime(true) * 1000.0;
            }
            return $n;
        } finally { $stmt->closeCursor(); }
    }

    public function execWithMeta(string $sql, array $params = [], array $meta = []): int
    {
        $meta = Observability::withDefaults($meta, $this);
        $sql  = Observability::sqlComment($meta) . $sql;

        $t0 = microtime(true);
        try {
            $r  = $this->exec($sql, $params);
            $ms = Observability::ms($t0);

            if (Observability::shouldSample($meta)) {
                $this->logger?->info('sql-exec', [
                    'ms'    => $ms,
                    'rows'  => $r,
                    'shape' => Observability::paramsShape($params),
                ] + $meta);
            }
            return $r;

        } catch (\Throwable $e) {
            $ms   = Observability::ms($t0);
            $err  = Observability::errorFields($e);
            $this->logger?->error('sql-exec-error', [
                'ms'    => $ms,
                'shape' => Observability::paramsShape($params),
            ] + $err + $meta);
            throw $e;
        }
    }

    public function fetchRowWithMeta(string $sql, array $params = [], array $meta = []): ?array
    {
        $meta = Observability::withDefaults($meta, $this);
        $sql  = Observability::sqlComment($meta) . $sql;

        $t0 = microtime(true);
        try {
            $row = $this->fetch($sql, $params);
            $ms  = Observability::ms($t0);

            if (Observability::shouldSample($meta)) {
                $this->logger?->info('sql-select-row', [
                    'ms'    => $ms,
                    'hit'   => $row !== null,
                    'shape' => Observability::paramsShape($params),
                ] + $meta);
            }
            return $row;

        } catch (\Throwable $e) {
            $ms  = Observability::ms($t0);
            $err = Observability::errorFields($e);
            $this->logger?->error('sql-select-row-error', [
                'ms'    => $ms,
                'shape' => Observability::paramsShape($params),
            ] + $err + $meta);
            throw $e;
        }
    }

    public function fetchAllWithMeta(string $sql, array $params = [], array $meta = []): array
    {
        $meta = Observability::withDefaults($meta, $this);
        $sql  = Observability::sqlComment($meta) . $sql;

        $t0 = microtime(true);
        try {
            $rows = $this->fetchAll($sql, $params);
            $ms   = Observability::ms($t0);

            if (Observability::shouldSample($meta)) {
                $this->logger?->info('sql-select', [
                    'ms'    => $ms,
                    'rows'  => count($rows),
                    'shape' => Observability::paramsShape($params),
                ] + $meta);
            }
            return $rows;

        } catch (\Throwable $e) {
            $ms  = Observability::ms($t0);
            $err = Observability::errorFields($e);
            $this->logger?->error('sql-select-error', [
                'ms'    => $ms,
                'shape' => Observability::paramsShape($params),
            ] + $err + $meta);
            throw $e;
        }
    }

    public function fetchValueWithMeta(string $sql, array $params = [], mixed $default = null, array $meta = []): mixed
    {
        $meta = Observability::withDefaults($meta, $this);
        $sql  = Observability::sqlComment($meta) . $sql;

        $t0 = microtime(true);
        try {
            $val = $this->fetchValue($sql, $params, $default);
            $ms  = Observability::ms($t0);

            if (Observability::shouldSample($meta)) {
                $this->logger?->info('sql-select-value', [
                    'ms'    => $ms,
                    'hit'   => $val !== null && $val !== false,
                    'type'  => gettype($val),
                    'shape' => Observability::paramsShape($params),
                ] + $meta);
            }
            return $val;

        } catch (\Throwable $e) {
            $ms  = Observability::ms($t0);
            $err = Observability::errorFields($e);
            $this->logger?->error('sql-select-value-error', [
                'ms'    => $ms,
                'shape' => Observability::paramsShape($params),
            ] + $err + $meta);
            throw $e;
        }
    }

    public function existsWithMeta(string $sql, array $params = [], array $meta = []): bool
    {
        $meta = Observability::withDefaults($meta, $this);
        $sql  = Observability::sqlComment($meta) . $sql;

        $t0 = microtime(true);
        try {
            $exists = $this->exists($sql, $params);
            $ms     = Observability::ms($t0);

            if (Observability::shouldSample($meta)) {
                $this->logger?->info('sql-exists', [
                    'ms'     => $ms,
                    'exists' => $exists,
                    'shape'  => Observability::paramsShape($params),
                ] + $meta);
            }
            return $exists;

        } catch (\Throwable $e) {
            $ms  = Observability::ms($t0);
            $err = Observability::errorFields($e);
            $this->logger?->error('sql-exists-error', [
                'ms'    => $ms,
                'shape' => Observability::paramsShape($params),
            ] + $err + $meta);
            throw $e;
        }
    }

    public function txWithMeta(callable $fn, array $meta = [], array $opts = []): mixed
    {
        $meta = Observability::withDefaults($meta, $this);
        $txId = Observability::newTxId();
        $meta += ['tx' => $txId];

        $mode    = !empty($opts['readOnly']) ? 'ro' : 'rw';
        $nested  = $this->inTransaction();
        $retries = max(0, (int)($opts['retries'] ?? 0));
        $iso     = $opts['isolation'] ?? null;
        $tmo     = isset($opts['timeoutMs']) ? (int)$opts['timeoutMs'] : null;

        $wrap = function(callable $cb) use ($iso, $tmo) {
            $runner = fn() => $cb($this);
            if ($iso !== null) {
                $prev = $runner;
                $runner = fn() => $this->withIsolationLevel((string)$iso, fn() => $prev());
            }
            if ($tmo !== null) {
                $prev = $runner;
                $runner = fn() => $this->withStatementTimeout($tmo, fn() => $prev());
            }
            return $runner();
        };

        $try = 0;
        BEGIN_RETRY:
        $t0 = microtime(true);
        try {
            if (Observability::shouldSample($meta)) {
                $this->logger?->info('tx-begin', ['mode'=>$mode,'nested'=>$nested] + $meta);
            }

            $result = $wrap(function() use ($fn, $mode) {
                if ($mode === 'ro') {
                    return $this->transactionReadOnly(fn() => $fn($this));
                }
                return $this->transaction(fn() => $fn($this));
            });

            if (Observability::shouldSample($meta)) {
                $this->logger?->info('tx-commit', [
                    'nested'=>$nested,
                    'ms'    => Observability::ms($t0),
                ] + $meta);
            }
            return $result;

        } catch (\Throwable $e) {
            $err = Observability::errorFields($e);
            $this->logger?->error('tx-rollback', [
                'nested'=>$nested,
                'ms'    => Observability::ms($t0),
            ] + $err + $meta);

            $pdoe = $e instanceof \PDOException ? $e
                : (($e instanceof DatabaseException && $e->getPrevious() instanceof \PDOException) ? $e->getPrevious() : null);

            if ($retries > 0 && $pdoe !== null && self::isTransientPdo($pdoe) && ++$try <= $retries) {
                usleep((int)min(1000, 50 * (1 << ($try-1))) * 1000);
                goto BEGIN_RETRY;
            }
            throw $e;
        }
    }

    public function txRoWithMeta(callable $fn, array $meta = [], array $opts = []): mixed
    {
        $opts['readOnly'] = true;
        return $this->txWithMeta($fn, $meta, $opts);
    }

    public function id(): string { return $this->dsnId; }

    public function serverVersion(): ?string {
        try { return (string)$this->pdoPrimary()->getAttribute(\PDO::ATTR_SERVER_VERSION); }
        catch (\Throwable $_) { return null; }
    }

    public function quote(string $value): string {
        $q = $this->pdoPrimary()->quote($value);
        return $q === false ? "'" . str_replace("'", "''", $value) . "'" : $q;
    }

    public function withStatement(string $sql, callable $cb): mixed {
        $stmt = $this->query($sql);
        try { return $cb($stmt); }
        finally { $stmt->closeCursor(); }
    }

    public function fetchOne(string $sql, array $params = []): mixed { return $this->fetchValue($sql, $params, null); }

    public function iterateColumn(string $sql, array $params = []): \Generator {
        $stmt = $this->prepareAndRun($sql, $params);
        try {
            while (($val = $stmt->fetchColumn(0)) !== false) {
                yield $val;
            }
        } finally {
            $stmt->closeCursor();
        }
    }

    private function hasNamedPlaceholders(string $sql): bool {
        return (bool)preg_match('/:[A-Za-z_][A-Za-z0-9_]*/', $sql);
    }

    private function hasPositionalPlaceholders(string $sql): bool {
        return strpos($sql, '?') !== false;
    }

    private function usesPositionalOnly(string $sql): bool {
        return $this->hasPositionalPlaceholders($sql) && !$this->hasNamedPlaceholders($sql);
    }

    private function isTransient(\PDOException $e): bool { return self::isTransientPdo($e); }

    public static function isTransientPdo(\PDOException $e): bool
    {
        $sqlstate = $e->errorInfo[0] ?? (string)$e->getCode();
        $code     = (int)($e->errorInfo[1] ?? 0);
        if (in_array($sqlstate, ['40P01','40001','55P03'], true)) return true; // PG
        if ($code === 1213 || $code === 1205) return true; // MySQL/MariaDB
        // Heuristic: treat common "communication errors" as transient.
        $msg = strtolower($e->getMessage());
        if (str_contains($msg, 'server has gone away') || str_contains($msg, 'lost connection') || str_contains($msg, 'closed the connection unexpectedly')) {
            return true;
        }
        return false;
    }

    public function withAdvisoryLock(string $name, int $timeoutSec, callable $fn): mixed {
        if ($this->isMysql()) {
            $n = $this->normalizeLockName($name);
            $ok = (bool)$this->fetchValue('SELECT GET_LOCK(:n, :t)', [':n'=>$n, ':t'=>$timeoutSec], 0);
            if (!$ok) throw new DatabaseException("GET_LOCK timeout: $name");
            try { return $fn($this); }
            finally { $this->execute('SELECT RELEASE_LOCK(:n)', [':n'=>$n]); }
        }
        if ($this->isPg()) {
            // Use the 2× int32 API – works across PG versions.
            [$a,$b] = $this->advisoryHashParts($name);
            $ok = (bool)$this->fetchValue('SELECT pg_try_advisory_lock(:a, :b)', [':a'=>$a, ':b'=>$b], 0);
            if (!$ok) throw new DatabaseException("pg_try_advisory_lock busy: $name");
            try { return $fn($this); }
            finally { $this->execute('SELECT pg_advisory_unlock(:a, :b)', [':a'=>$a, ':b'=>$b]); }
        }
        return $fn($this);
    }

    public function withStatementTimeout(int $ms, callable $fn): mixed {
        if ($this->isPg()) {
            return $this->transaction(function() use($ms,$fn){
                $this->exec('SET LOCAL statement_timeout = '.(int)$ms);
                return $fn($this);
            });
        }
        if ($this->isMysql()) {
            $ms = max(0, $ms);
            $usedVar = null;
            $oldVal  = 0;
            try {
                $oldVal = (int)$this->fetchValue('SELECT @@SESSION.max_execution_time', [], 0);
                $this->exec('SET SESSION max_execution_time = ' . (int)$ms);
                $usedVar = 'mysql';
            } catch (\Throwable $_) {
                $oldVal = (float)$this->fetchValue('SELECT @@SESSION.max_statement_time', [], 0.0);
                $sec = ($ms <= 0) ? 0 : max(1, (int)ceil($ms / 1000.0));
                $this->exec('SET SESSION max_statement_time = ' . $sec);
                $usedVar = 'mariadb';
            }
            try { return $fn($this); }
            finally {
                try {
                    if ($usedVar === 'mysql') { $this->exec('SET SESSION max_execution_time = ' . (int)$oldVal); }
                    elseif ($usedVar === 'mariadb') { $this->exec('SET SESSION max_statement_time = ' . (is_numeric($oldVal) ? (float)$oldVal : 0)); }
                } catch (\Throwable $_) {}
            }
        }
        return $fn($this);
    }

    public function withIsolationLevel(string $level, callable $fn): mixed
    {
        $map = [
            'read uncommitted' => 'READ UNCOMMITTED',
            'read committed'   => 'READ COMMITTED',
            'repeatable read'  => 'REPEATABLE READ',
            'serializable'     => 'SERIALIZABLE',
        ];
        $lvl = strtoupper($level);
        $lvl = $map[strtolower($level)] ?? $lvl;
        if (!in_array($lvl, $map, true) && !in_array($lvl, array_values($map), true)) {
            throw new DatabaseException("Unsupported isolation level: {$level}");
        }

        if ($this->isPg()) {
            return $this->transaction(function () use ($fn, $lvl) {
                $this->exec("SET LOCAL TRANSACTION ISOLATION LEVEL {$lvl}");
                return $fn($this);
            });
        }

        if ($this->isMysql()) {
            $pdo = $this->pdoPrimary();
            if ($pdo->inTransaction()) {
                return $fn($this);
            }
            $this->exec("SET TRANSACTION ISOLATION LEVEL {$lvl}");
            $this->exec('START TRANSACTION');
            try {
                $res = $fn($this);
                $this->commit();
                return $res;
            } catch (\Throwable $e) {
                try { $this->rollback(); } catch (\Throwable $_) {}
                throw $e;
            }
        }

        return $this->transaction($fn);
    }

    /**
     * Variant that enforces correct isolation usage on MySQL:
     * - if a transaction is already active, throws (prevents a silent no-op).
     * - otherwise uses the standard withIsolationLevel().
     */
    public function withIsolationLevelStrict(string $level, callable $fn): mixed
    {
        if ($this->isMysql() && $this->pdoPrimary()->inTransaction()) {
            throw new DatabaseException('withIsolationLevelStrict: cannot change isolation inside active transaction on MySQL; call before BEGIN or wrap your workload.');
        }
        return $this->withIsolationLevel($level, $fn);
    }

    public function explainPlan(string $sql, array $params = [], bool $analyze = false): array
    {
        if ($this->isMysql()) {
            if ($analyze) {
                try { return $this->fetchAll('EXPLAIN ANALYZE ' . $sql, $params); } catch (\Throwable $_) {}
            }
            return $this->fetchAll('EXPLAIN ' . $sql, $params);
        }
        if ($this->isPg()) {
            if ($analyze) {
                $rows = $this->fetchAll('EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ' . $sql, $params);
                return $rows;
            }
            return $this->fetchAll('EXPLAIN ' . $sql, $params);
        }
        return $this->fetchAll('EXPLAIN ' . $sql, $params);
    }

    public function quoteIdent(string $name): string {
        $parts = explode('.', $name);
        if ($this->isMysql()) return implode('.', array_map(fn($p)=>'`'.str_replace('`','``',$p).'`', $parts));
        return implode('.', array_map(fn($p)=>'"'.str_replace('"','""',$p).'"', $parts));
    }

    public function inClause(string $col, array $values, string $prefix='p', int $chunk=0): array {
        if (!$values) return ['1=0', []];
        if ($chunk > 0 && count($values) > $chunk) {
            $parts = []; $params = []; $i=0; $g=0;
            foreach (array_chunk($values, $chunk) as $grp) {
                $ph = [];
                foreach ($grp as $v) { $k = ":{$prefix}_{$g}_".$i++; $ph[] = $k; $params[$k] = $v; }
                $parts[] = "$col IN (".implode(',', $ph).")";
                $i = 0; $g++;
            }
            return ['('.implode(' OR ', $parts).')', $params];
        }
        $i=0; $ph=[]; $params=[];
        foreach ($values as $v) { $k=":{$prefix}_".$i++; $ph[]=$k; $params[$k]=$v; }
        return ["$col IN (".implode(',', $ph).")", $params];
    }

    public function transactionReadOnly(callable $fn): mixed
    {
        $pdo = $this->pdoPrimary();

        if ($this->isPg()) {
            return $this->transaction(function() use($fn) {
                $this->exec('SET TRANSACTION READ ONLY');
                return $fn($this);
            });
        }

        if ($this->isMysql()) {
            if ($pdo->inTransaction()) {
                return $fn($this);
            }
            $this->exec('START TRANSACTION READ ONLY');
            try {
                $res = $fn($this);
                $this->commit();
                return $res;
            } catch (\Throwable $e) {
                try { $this->rollback(); } catch (\Throwable $_) {}
                throw $e;
            }
        }

        return $this->transaction($fn);
    }

    public function paginateKeyset(
        string $sqlBase,
        array $params,
        string $pkIdent,
        string $pkResultKey,
        string|int|null $afterPk,
        int $limit = 50,
        string $direction = 'DESC',
        bool $inclusive = false
    ): array {
        $limit = max(1, (int)$limit);
        $dir   = strtoupper($direction) === 'ASC' ? 'ASC' : 'DESC';
        $cmp   = $inclusive ? ($dir === 'ASC' ? '>=' : '<=') : ($dir === 'ASC' ? '>' : '<');

        if (!preg_match('~^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)?$~', $pkIdent)) {
            throw new DatabaseException('pkIdent must be a plain identifier (e.g., "t.id")');
        }

        $idExpr     = $this->quoteIdent($pkIdent);
        $hasWhere   = (bool)preg_match('/\bwhere\b/i', $sqlBase);
        $usePos     = $this->usesPositionalOnly($sqlBase);

        $condSql = '';
        if ($afterPk !== null) {
            if ($usePos) {
                $condSql = ($hasWhere ? ' AND ' : ' WHERE ') . "$idExpr $cmp ?";
            } else {
                $condSql = ($hasWhere ? ' AND ' : ' WHERE ') . "$idExpr $cmp :__after";
            }
        } elseif (!$hasWhere) {
            $condSql = ' WHERE 1=1';
        }

        // FIX: removed an incorrect "+" concatenator.

        if ($usePos) {
            $sql = $sqlBase . $condSql . " ORDER BY $idExpr $dir LIMIT ?";
            $p = array_values($params);
            if ($afterPk !== null) { $p[] = $afterPk; }
            $p[] = $limit;
        } else {
            $sql = $sqlBase . $condSql . " ORDER BY $idExpr $dir LIMIT :__limit";
            $p = $params;
            if ($afterPk !== null) { $p['__after'] = $afterPk; }
            $p['__limit'] = $limit;
        }

        $items = $this->fetchAll($sql, $p);

        $next = null;
        if ($items) {
            $last = end($items);
            $next = $last[$pkResultKey] ?? null;
        }

        return [
            'items'     => $items,
            'nextAfter' => $next,
            'limit'     => $limit,
            'direction' => $dir,
        ];
    }

    /** Retry wrappery pro SELECT/EXEC **/
    public function fetchWithRetry(string $sql, array $params = [], int $attempts = 3, int $baseDelayMs = 50): ?array {
        $try=0; $delay=$baseDelayMs;
        while (true) {
            try { return $this->fetch($sql, $params); }
            catch (DatabaseException $e) {
                $pdoe = $e->getPrevious();
                $transient = $pdoe instanceof \PDOException && self::isTransientPdo($pdoe);
                if (!$transient || ++$try >= $attempts) throw $e;
                usleep($delay*1000); $delay = min(1000, $delay*2);
            }
        }
    }
    public function fetchAllWithRetry(string $sql, array $params = [], int $attempts = 3, int $baseDelayMs = 50): array {
        $try=0; $delay=$baseDelayMs;
        while (true) {
            try { return $this->fetchAll($sql, $params); }
            catch (DatabaseException $e) {
                $pdoe = $e->getPrevious();
                $transient = $pdoe instanceof \PDOException && self::isTransientPdo($pdoe);
                if (!$transient || ++$try >= $attempts) throw $e;
                usleep($delay*1000); $delay = min(1000, $delay*2);
            }
        }
    }
    public function fetchValueWithRetry(string $sql, array $params = [], mixed $default = null, int $attempts = 3, int $baseDelayMs = 50): mixed {
        $try=0; $delay=$baseDelayMs;
        while (true) {
            try { return $this->fetchValue($sql, $params, $default); }
            catch (DatabaseException $e) {
                $pdoe = $e->getPrevious();
                $transient = $pdoe instanceof \PDOException && self::isTransientPdo($pdoe);
                if (!$transient || ++$try >= $attempts) throw $e;
                usleep($delay*1000); $delay = min(1000, $delay*2);
            }
        }
    }
    public function execWithRetry(string $sql, array $params = [], int $attempts = 3, int $baseDelayMs = 50): int {
        $try=0; $delay=$baseDelayMs;
        while (true) {
            try { return $this->exec($sql, $params); }
            catch (DatabaseException $e) {
                $pdoe = $e->getPrevious();
                $transient = $pdoe instanceof \PDOException && self::isTransientPdo($pdoe);
                if (!$transient || ++$try >= $attempts) throw $e;
                usleep($delay*1000); $delay = min(1000, $delay*2);
            }
        }
    }

    // --- EXPLAIN as JSON (when possible) ---
    public function explainJson(string $sql, array $params = [], bool $analyze = false): array {
        if ($this->isPg()) {
            $opts = $analyze ? '(ANALYZE, BUFFERS, FORMAT JSON)' : '(FORMAT JSON)';
            $rows = $this->fetchAll("EXPLAIN {$opts} ".$sql, $params);
            $json = $rows[0]['QUERY PLAN'] ?? ($rows[0][array_key_first($rows[0])] ?? null);
            if (is_string($json)) { return json_decode($json, true) ?: [['plan'=>$rows]]; }
            if (is_array($json))  { return $json; }
            return [['plan'=>$rows]];
        }
        if ($this->isMysql()) {
            try {
                $rows = $this->fetchAll('EXPLAIN FORMAT=JSON '.$sql, $params);
                $doc  = $rows[0]['EXPLAIN'] ?? ($rows[0][array_key_first($rows[0])] ?? null);
                if (is_string($doc)) { return json_decode($doc, true) ?: [['plan'=>$rows]]; }
            } catch (\Throwable $_) {
                $rows = $this->fetchAll('EXPLAIN '.$sql, $params);
                return [['plan'=>$rows]];
            }
        }
        return [['plan'=>$this->fetchAll('EXPLAIN '.$sql, $params)]];
    }

    // --- Safer fetchPairs with duplicate policy ---
    /**
     * @param 'first'|'last'|'error' $onDuplicate
     */
    public function fetchPairsEx(string $sql, array $params = [], string $onDuplicate = 'last'): array {
        $rows = $this->fetchAll($sql, $params);
        $out  = [];
        foreach ($rows as $r) {
            $vals = array_values($r);
            if (!$vals) continue;
            $k = $vals[0];
            $v = $vals[1] ?? $vals[0];
            if (array_key_exists($k, $out)) {
                if ($onDuplicate === 'error') {
                    throw new DatabaseException('fetchPairsEx duplicate key: '.(string)$k);
                } elseif ($onDuplicate === 'first') {
                    continue;
                }
            }
            $out[$k] = $v;
        }
        return $out;
    }

    // --- Bulk INSERT & UPSERT helpers ---
    /**
     * Bulk INSERT with chunking (returns sum of affected rows).
     * @param list<array<string,mixed>> $rows
     */
    public function insertMany(string $table, array $rows, int $chunk = 500): int {
        if (!$rows) return 0;
        $cols = array_keys($rows[0]);
        foreach ($rows as $i=>$r) {
            if (array_keys($r) !== $cols) {
                throw new DatabaseException("insertMany: row {$i} has different columns than the first row");
            }
        }
        $colId = implode(',', array_map(fn($c)=>$this->quoteIdent($c), $cols));
        $total = 0; $g=0;
        foreach (array_chunk($rows, max(1,$chunk)) as $grp) {
            $values = []; $params = []; $i=0;
            foreach ($grp as $r) {
                $ph = [];
                foreach ($cols as $c) { $k=":p{$g}_{$i}_{$c}"; $ph[]=$k; $params[$k]=$r[$c]; }
                $values[] = '(' . implode(',', $ph) . ')'; $i++;
            }
            $sql = 'INSERT INTO ' . $this->quoteIdent($table) . " ({$colId}) VALUES " . implode(',', $values);
            $total += $this->execute($sql, $params);
            $g++;
        }
        return $total;
    }

    /**
     * UPSERT (INSERT ... ON CONFLICT / ON DUPLICATE KEY UPDATE).
     * @param list<array<string,mixed>>|array<string,mixed> $rows
     * @param list<string> $uniqueKeys
     * @param list<string>|null $updateCols
     */
    public function upsert(string $table, array $rows, array $uniqueKeys, ?array $updateCols = null, int $chunk = 500): int {
        $batch = \array_is_list($rows) ? $rows : [$rows];
        if (!$batch) return 0;
        /** @var list<string> $cols */
        $cols = array_values(array_map(static fn ($c): string => (string) $c, array_keys($batch[0])));
        foreach ($batch as $i=>$r) {
            $rowCols = array_values(array_map(static fn ($c): string => (string) $c, array_keys($r)));
            if ($rowCols !== $cols) {
                throw new DatabaseException("upsert: row {$i} has different columns than the first row");
            }
        }
        if ($updateCols === null) {
            $updateCols = array_values(array_diff($cols, $uniqueKeys));
        }
        $colId = implode(',', array_map(fn($c)=>$this->quoteIdent($c), $cols));
        $ukId  = implode(',', array_map(fn($c)=>$this->quoteIdent($c), $uniqueKeys));

        $total=0; $g=0;
        foreach (array_chunk($batch, max(1,$chunk)) as $grp) {
            $values=[]; $params=[]; $i=0;
            foreach ($grp as $r) {
                $ph=[]; foreach ($cols as $c) { $k=":u{$g}_{$i}_{$c}"; $ph[]=$k; $params[$k]=$r[$c]; }
                $values[]='('.implode(',', $ph).')'; $i++;
            }
            if ($this->isPg()) {
                $set = implode(',', array_map(fn($c)=> $this->quoteIdent($c).'=EXCLUDED.'.$this->quoteIdent($c), $updateCols));
                $sql = 'INSERT INTO '.$this->quoteIdent($table)." ({$colId}) VALUES ".implode(',', $values)
                     . " ON CONFLICT ({$ukId}) DO UPDATE SET {$set}";
            } else { // MySQL/MariaDB
                if ($this->mysqlValuesDeprecated()) {
                    // MySQL 8.0.19+: avoid deprecated VALUES(); use a row alias.
                    $alias = '__ins';
                    $set = implode(',', array_map(fn($c)=> $this->quoteIdent($c).'='.$alias.'.'.$this->quoteIdent($c), $updateCols));
                    $sql = 'INSERT INTO '.$this->quoteIdent($table)." ({$colId}) VALUES ".implode(',', $values)
                         . " AS {$alias} ON DUPLICATE KEY UPDATE {$set}";
                } else {
                    // MariaDB (and older MySQL): VALUES() is OK.
                    $set = implode(',', array_map(fn($c)=> $this->quoteIdent($c).'=VALUES('.$this->quoteIdent($c).')', $updateCols));
                    $sql = 'INSERT INTO '.$this->quoteIdent($table)." ({$colId}) VALUES ".implode(',', $values)
                         . " ON DUPLICATE KEY UPDATE {$set}";
                }
            }
            $total += $this->execute($sql, $params);
            $g++;
        }
        return $total;
    }

    private function sanitizeSqlPreview(string $sql): string
    {
        // Anonymize the content of all string literals (even short ones).
        $s = preg_replace("/'(?:''|\\\\'|[^'])*'/", "'…'", $sql);
        if ($s === null) {
            $s = $sql;
        }
        $s2 = preg_replace('/\s+/', ' ', trim($s));
        $s = $s2 === null ? trim($sql) : $s2;
        $max = 300;
        if (function_exists('mb_strlen') && function_exists('mb_substr')) {
            return mb_strlen($s) > $max ? mb_substr($s, 0, $max) . '...' : $s;
        }
        return strlen($s) > $max ? substr($s, 0, $max) . '...' : $s;
    }

    private function isWriteSql(string $sql): bool {
        $s = ltrim($sql);
        if (str_starts_with($s, '/*')) { $s = preg_replace('~/\*.*?\*/~s', '', $s) ?? $s; $s = ltrim($s); }
        if (str_starts_with($s, '--')) {
            $isLineComment = true;
            if ($this->isMysql()) {
                $next = $s[2] ?? '';
                $isLineComment = $next !== '' && ord($next) <= 0x20;
            }
            if ($isLineComment) {
                $s = preg_replace('~--.*?$~m', '', $s) ?? $s;
                $s = ltrim($s);
            }
        }
        if (!preg_match('~^([A-Z]+)~i', $s, $m)) return false;
        $verb = strtoupper($m[1]);
        return in_array($verb, ['INSERT','UPDATE','DELETE','REPLACE','MERGE','TRUNCATE','ALTER','CREATE','DROP','RENAME','GRANT','REVOKE','VACUUM'], true);
    }

    /** GET_LOCK name normalization (MySQL/MariaDB limit is 64 chars). */
    private function normalizeLockName(string $name): string {
        if (strlen($name) <= 64) return $name;
        return 'bc:' . substr(sha1($name), 0, 61); // 'bc:' (3) + 61 = 64
    }
    /** Two-part hash for PG advisory lock API (int4,int4). */
    private function advisoryHashParts(string $s): array {
        $a = crc32('pg1:'.$s);
        $b = crc32('pg2:'.$s);
        if ($a & 0x80000000) { $a -= 0x100000000; }
        if ($b & 0x80000000) { $b -= 0x100000000; }
        return [$a, $b];
    }
    /** MySQL 8.0.19+ deprecates VALUES() in ON DUPLICATE KEY UPDATE. */
    private function mysqlValuesDeprecated(): bool {
        if (!$this->isMysql() || $this->isMariaDb()) return false;
        $v = $this->serverVersion() ?? '0';
        $v = preg_replace('~[^0-9.].*$~', '', $v) ?: '0';
        return version_compare($v, '8.0.19', '>=');
    }

    /** True if this is UPDATE/DELETE without WHERE (and optionally LIMIT on MySQL). */
    private function isDangerousWriteWithoutWhere(string $sql): bool {
        $u = strtoupper($sql);
        if (!preg_match('~^\s*(UPDATE|DELETE)\b~', $u)) return false;
        if (preg_match('~\bWHERE\b~', $u)) return false;
        if ($this->isMysql() && preg_match('~\bLIMIT\s+\d+\b~', $u)) return false;
        return true;
    }
    /** Placeholder guard – logs mismatch between :named placeholders and provided params. */
    private function guardPlaceholders(string $sql, array $params): void {
        if ($params === [] || $this->usesPositionalOnly($sql)) return;
        preg_match_all('/:([A-Za-z_][A-Za-z0-9_]*)/', $sql, $m);
        $need = array_unique($m[1]);
        $have = array_map(fn($k)=> ltrim((string)$k, ':'), array_keys($params));
        $missing = array_values(array_diff($need, $have));
        $extra   = array_values(array_diff($have, $need));
        if ($missing || $extra) {
            $this->logger?->warning('Placeholder mismatch', ['missing'=>$missing,'extra'=>$extra,'sql'=>$this->sanitizeSqlPreview($sql)]);
        }
    }
    /** Ring buffer for recent queries + observers. */
    private function pushLastQuery(string $sql, string $route, ?float $ms, ?string $err): void {
        $rec = ['ts'=>microtime(true), 'sql'=>$this->sanitizeSqlPreview($sql), 'route'=>$route];
        if ($ms !== null) { $rec['ms'] = round($ms, 2); }
        if ($err !== null) { $rec['err'] = substr($this->sanitizeSqlPreview($err), 0, 200); }
        $this->lastQueries[] = $rec;
        $n = count($this->lastQueries) - $this->lastQueriesMax;
        if ($n > 0) { array_splice($this->lastQueries, 0, $n); }
    }
    private function notifyStart(string $sql, array $params, string $route): void {
        foreach ($this->observers as $o) { try { $o->onQueryStart($sql, $params, $route); } catch (\Throwable $_) {} }
    }
    private function notifyEnd(string $sql, array $params, ?float $ms, ?\Throwable $err, string $route): void {
        foreach ($this->observers as $o) { try { $o->onQueryEnd($sql, $params, $ms, $err, $route); } catch (\Throwable $_) {} }
    }
    // N+1 detector
    private function n1Record(string $sql): void
    {
        if (!$this->n1Enabled) return;
        $s = ltrim($sql);
        if (strncasecmp($s, 'select', 6) !== 0 && strncasecmp($s, 'with', 4) !== 0) return;
        $fp = $this->n1Fingerprint($sql);
        $c = ($this->n1Counts[$fp] ?? 0) + 1;
        $this->n1Counts[$fp] = $c;
        if (count($this->n1Samples[$fp] ?? []) < $this->n1MaxSamples) {
            $origin = '(unknown)';
            foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 10) as $f) {
                $file = $f['file'] ?? '';
                if ($file !== '' && !str_ends_with($file, DIRECTORY_SEPARATOR.'Database.php')) {
                    $origin = $file.':'.($f['line'] ?? '?'); break;
                }
            }
            $this->n1Samples[$fp][] = $origin;
        }
        if ($c === $this->n1Threshold && empty($this->n1Warned[$fp])) {
            $this->n1Warned[$fp] = true;
            $this->logger?->warning('Possible N+1 detected', [
                'count' => $c,
                'fingerprint' => $fp,
                'samples' => $this->n1Samples[$fp] ?? [],
            ]);
        }
    }
    private function n1Fingerprint(string $sql): string
    {
        $s = preg_replace('~/\*.*?\*/~s', ' ', $sql) ?? $sql;
        $s = preg_replace('~--.*?$~m', ' ', $s) ?? $s;
        $s = preg_replace("/'(?:''|\\\\'|[^'])*'/", '?', $s) ?? $s;
        $s = preg_replace('/\b\d+\b/', '?', $s) ?? $s;
        $s = preg_replace('/\bIN\s*\(\s*(?:\?\s*,\s*)+\?\s*\)/i', 'IN ( ? )', $s) ?? $s;
        $s = preg_replace('/\s+/', ' ', trim($s)) ?? $s;
        return hash('sha256', strtoupper($s));
    }

    // Map PDO errors to domain exceptions.
    private function mapPdoToDomainException(\PDOException $e, string $fallbackMsg): DatabaseException {
        $sqlstate = $e->errorInfo[0] ?? (string)$e->getCode();
        $code     = (int)($e->errorInfo[1] ?? 0);
        $msg      = strtolower($e->getMessage());
        if (str_contains($msg, 'server has gone away') || str_contains($msg, 'lost connection') ||
            str_contains($msg, 'connection refused') || str_contains($msg, 'closed the connection unexpectedly')) {
            return new ConnectionGoneException($fallbackMsg, 0, $e);
        }
        if ($sqlstate === '40P01' || $code === 1213) { // deadlock
            return new DeadlockException($fallbackMsg, 0, $e);
        }
        if ($sqlstate === '40001') { // serialization failure
            return new SerializationFailureException($fallbackMsg, 0, $e);
        }
        if ($sqlstate === '55P03' || $code === 1205) { // lock wait timeout
            return new LockTimeoutException($fallbackMsg, 0, $e);
        }
        return new DatabaseException($fallbackMsg, 0, $e);
    }

    // Replica introspection / stickiness
    public function replicaStatus(): array {
        $cooldownUntil = $this->replicaDownUntil;
        $now = time();
        return [
            'hasReplica'   => $this->hasReplica(),
            'cooldownSec'  => $this->replicaCooldownSec,
            'cooldownUntil'=> $cooldownUntil,
            'inCooldown'   => ($cooldownUntil !== null && $now < $cooldownUntil),
            'lagMs'        => $this->replicaLagMs,
            'maxLagMs'     => $this->replicaMaxLagMs,
        ];
    }
    public function getStickAfterWriteMs(): int { return $this->stickAfterWriteMs; }

    public function executeWithRetry(string $sql, array $params = [], int $attempts = 3, int $baseDelayMs = 50): int {
        $try = 0; $delay = $baseDelayMs;
        while (true) {
            try {
                $n = $this->execute($sql, $params);
                return $n;
            } catch (DatabaseException $e) {
                $prev = $e->getPrevious();
                $isTransient = $prev instanceof \PDOException && $this->isTransient($prev);
                if (++$try >= $attempts || !$isTransient) {
                    throw $e;
                }
                usleep($delay * 1000);
                $delay = (int)min($delay * 2, 1000);
            }
        }
    }

    public function executeOne(string $sql, array $params = []): void {
        $n = $this->execute($sql, $params);
        if ($n !== 1) throw new DatabaseException("Expected to affect 1 row, affected={$n}");
    }

    public function driver(): ?string
    {
        try { return (string)$this->pdoPrimary()->getAttribute(\PDO::ATTR_DRIVER_NAME); }
        catch (\Throwable $_) { return null; }
    }

    public function isMysql(): bool { return $this->driver() === 'mysql'; }
    public function isPg(): bool    { return $this->driver() === 'pgsql'; }
    // MariaDB detection via server version.
    public function isMariaDb(): bool {
        if (!$this->isMysql()) return false;
        $ver = $this->serverVersion();
        return is_string($ver) && stripos($ver, 'mariadb') !== false;
    }

    private function isServerGone(\PDOException $e): bool
    {
        $m = strtolower($e->getMessage());
        return str_contains($m, 'server has gone away')
            || str_contains($m, 'lost connection')
            || str_contains($m, 'connection refused')
            || str_contains($m, 'closed the connection unexpectedly');
    }

    private function reconnect(): void
    {
        $cfg = $this->config;
        $dsn = $cfg['dsn'] ?? null;
        $user = $cfg['user'] ?? null;
        $pass = $cfg['pass'] ?? null;
        $givenOptions = $cfg['options'] ?? [];
        $initCommands = $cfg['init_commands'] ?? [];
        $appName = (string)($cfg['appName'] ?? 'blackcat');

        $this->pdo = self::createPdo((string)$dsn, $user, $pass, $givenOptions, $initCommands, $this->logger, $appName, $cfg);
    }

    // Replica reconnect
    private function reconnectReplica(): void
    {
        $cfg = $this->config['replica'] ?? null;
        if (!is_array($cfg) || empty($cfg['dsn'])) return;
        $appName = (string)($this->config['appName'] ?? 'blackcat');
        $this->pdoRead = self::createPdo(
            (string)$cfg['dsn'],
            $cfg['user'] ?? null,
            $cfg['pass'] ?? null,
            $cfg['options'] ?? [],
            $cfg['init_commands'] ?? [],
            $this->logger,
            $appName,
            $this->config
        );
    }

    // Public knobs for health-gate and routing
    public function setReplicaHealthChecker(callable $fn): void { $this->replicaHealthChecker = $fn; }
    public function setReplicaMaxLagMs(?int $ms): void { $this->replicaMaxLagMs = $ms !== null ? max(0, $ms) : null; }
    public function setReplicaHealthCheckSec(int $sec): void { $this->replicaHealthCheckSec = max(1, $sec); }
    public function withPrimary(callable $fn): mixed { $prev=$this->routeOverride; $this->routeOverride='primary'; try { return $fn($this); } finally { $this->routeOverride=$prev; } }
    public function withReplica(callable $fn): mixed { $prev=$this->routeOverride; $this->routeOverride='replica';  try { return $fn($this); } finally { $this->routeOverride=$prev; } }
    /** Blocking wait for a "caught up" replica (lag + stick window). */
    public function waitForReplica(int $timeoutMs = 1500): bool {
        if ($this->pdoRead === null) return true;
        $deadline = microtime(true) + ($timeoutMs / 1000.0);
        do {
            if ($this->isReplicaHealthy()) {
                if ($this->stickAfterWriteMs <= 0 || (microtime(true) * 1000.0 - $this->lastWriteAtMs) >= $this->stickAfterWriteMs) {
                    return true;
                }
            }
            usleep(50_000);
        } while (microtime(true) < $deadline);
        return false;
    }

    /** Replica health-gate (lag) */
    private function isReplicaHealthy(): bool
    {
        if ($this->pdoRead === null) return false;
        if ($this->replicaMaxLagMs === null) return true; // gating disabled

        $now = time();
        if ($this->replicaHealthCheckedAt !== null && ($now - $this->replicaHealthCheckedAt) < $this->replicaHealthCheckSec) {
            return ($this->replicaLagMs ?? 0) <= $this->replicaMaxLagMs;
        }

        $lag = null;
        try {
            if (is_callable($this->replicaHealthChecker)) {
                /** @var callable $fn */
                $fn = $this->replicaHealthChecker;
                $lag = (int)$fn($this->pdoRead);
            } else {
                $lag = $this->detectReplicaLagMs();
            }
        } catch (\Throwable $_) {
            $lag = PHP_INT_MAX; // on failure treat as not healthy
        }

        $this->replicaLagMs = is_int($lag) ? max(0, $lag) : PHP_INT_MAX;
        $this->replicaHealthCheckedAt = $now;
        return $this->replicaLagMs <= $this->replicaMaxLagMs;
    }

    private function detectReplicaLagMs(): ?int
    {
        $pdo = $this->pdoRead;
        if ($pdo === null) {
            return null;
        }
        try {
            $drv = (string)$pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);
            if ($drv === 'pgsql') {
                // NULL on primary; on replica it reports lag in ms.
                $sql = "SELECT EXTRACT(EPOCH FROM (NOW() - pg_last_xact_replay_timestamp())) * 1000 AS lag_ms";
                $stmt = $pdo->query($sql);
                $row = $stmt instanceof \PDOStatement ? $stmt->fetch(\PDO::FETCH_ASSOC) : false;
                $v = $row['lag_ms'] ?? null;
                if ($v === null) return null;
                return (int)round((float)$v);
            }
            if ($drv === 'mysql') {
                // MySQL 8: SHOW REPLICA STATUS; older versions / MariaDB: SHOW SLAVE STATUS.
                $row = null;
                try {
                    $stmt = $pdo->query("SHOW REPLICA STATUS");
                    $row = $stmt instanceof \PDOStatement ? $stmt->fetch(\PDO::FETCH_ASSOC) : false;
                } catch (\Throwable $_) {}
                if (!$row) {
                    try {
                        $stmt = $pdo->query("SHOW SLAVE STATUS");
                        $row = $stmt instanceof \PDOStatement ? $stmt->fetch(\PDO::FETCH_ASSOC) : false;
                    }
                    catch (\Throwable $_) {}
                }
                if (is_array($row)) {
                    $sec = null;
                    if (array_key_exists('Seconds_behind_source', $row)) { $sec = $row['Seconds_behind_source']; }
                    elseif (array_key_exists('Seconds_Behind_Source', $row)) { $sec = $row['Seconds_Behind_Source']; }
                    elseif (array_key_exists('Seconds_behind_master', $row)) { $sec = $row['Seconds_behind_master']; }
                    elseif (array_key_exists('Seconds_Behind_Master', $row)) { $sec = $row['Seconds_Behind_Master']; }
                    if ($sec === null || $sec === '' || $sec === false) return null;
                    if (!is_numeric($sec)) return null;
                    return (int)((float)$sec * 1000.0);
                }
            }
        } catch (\Throwable $_) { /* ignore */ }
        return null;
    }

    public function requireSqlComment(bool $on=true): void { $this->requireSqlComment = $on; }

    public function prepareAndRun(string $sql, array $params = []): \PDOStatement
    {
        $this->circuitCheck();
        $this->sqlFirewallGuard($sql);
        if ($this->requireSqlComment) {
            $trim = ltrim($sql);
            // Allow internal check/config commands without a comment.
            $isTrivial = preg_match(
                '~^\s*(SELECT\s+1|SHOW|PRAGMA|EXPLAIN|BEGIN|COMMIT|ROLLBACK|'
                .'SET(\s+LOCAL|\s+TRANSACTION|\s+SESSION)?\b|'
                .'START\s+TRANSACTION\b|'
                .'SAVEPOINT\b|RELEASE\s+SAVEPOINT\b|ROLLBACK\s+TO\s+SAVEPOINT\b)~i',
                $trim
            );
            if (!$isTrivial && !str_starts_with($trim, '/*app:')) {
                throw new DatabaseException('SQL comment required (use Observability::sqlComment(meta))');
            }
        }
        if ($this->isWriteSql($sql)) {
            if ($this->readOnlyGuard) {
                throw new DatabaseException('Read-only guard: write statements are disabled');
            }
            if (self::$writeGuardLocked && self::$writeGuard === null) {
                throw new DatabaseException('Database write guard is locked but missing; restart the process.');
            }
            if (self::$writeGuard === null) {
                $this->autoBootTrustKernelIfPossible();
            }
            if (self::$writeGuard !== null) {
                (self::$writeGuard)($sql);
            }
        } else {
            if (self::$readGuardLocked && self::$readGuard === null) {
                throw new DatabaseException('Database read guard is locked but missing; restart the process.');
            }
            if (self::$readGuard === null) {
                $this->autoBootTrustKernelIfPossible();
            }
            if (self::$readGuard !== null) {
                (self::$readGuard)($sql);
            }
        }
        if ($this->dangerousSqlGuard && $this->isDangerousWriteWithoutWhere($sql)) {
            throw new DatabaseException('Dangerous write without WHERE/LIMIT detected');
        }
        if ($this->placeholderGuard) {
            $this->guardPlaceholders($sql, $params);
        }

        $start   = microtime(true);
        /** @var int $attempt */
        $attempt = 0;
        $usedReplica = false;
        $route = 'primary';

        RETRY:
        $span = \BlackCat\Database\Support\Observability::startSpan('db.query');
        $pdoUsed = $this->choosePdoFor($sql);
        $usedReplica = ($pdoUsed === $this->pdoRead && $this->pdoRead !== null);
        $route = $usedReplica ? 'replica' : 'primary';
        $this->notifyStart($sql, $params, $route);

        try {
            if (($this->config['orderGuard'] ?? false) === true || ($this->config['orderGuard'] ?? null) === 1 || ($this->config['orderGuard'] ?? null) === '1') {
                if (preg_match('~\bORDER\s+(?!BY\b)~i', $sql)) {
                    $bt = array_slice(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS), 0, 8);
                    $where = array_map(fn($f)=>($f['file'] ?? '?').':'.($f['line'] ?? '?'), $bt);
                    throw new DatabaseException('ORDER without BY detected: '.$this->sanitizeSqlPreview($sql).' @ '.implode(' <- ', $where));
                }
                $s = preg_replace("/'([^'\\\\]|\\\\.)*'/", "''", $sql) ?? $sql;
                if (!preg_match('~\bORDER\s+BY\b~i', $s)) {
                    if (preg_match('~((?:[\w`\".]+\s+(?:ASC|DESC))(?:\s*,\s*[\w`\".]+\s+(?:ASC|DESC))*)\s*(?:LIMIT|OFFSET|$)~i', $s, $m)) {
                        $off = $m[1];
                        $bt = array_slice(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS), 0, 8);
                        $where = array_map(fn($f)=>($f['file'] ?? '?').':'.($f['line'] ?? '?'), $bt);
                        throw new DatabaseException("ORDER BY is missing; bare order clause detected: [{$off}] in SQL: ".$this->sanitizeSqlPreview($sql)." @ ".implode(' <- ', $where));
                    }
                }
            }

            $stmt = $pdoUsed->prepare($sql);
            if ($stmt === false) {
                throw new DatabaseException('Failed to prepare statement.');
            }

            // MySQL/MariaDB strict mode rejects empty-string for BOOL/TINYINT columns.
            // pdo_mysql may bind `false` as "" when no explicit param type is used.
            // Normalize booleans to 0/1 for MySQL to avoid 1366 errors.
            $execParams = $params;
            if ($this->isMysql()) {
                foreach ($execParams as $k => $v) {
                    if (is_bool($v)) {
                        $execParams[$k] = $v ? 1 : 0;
                    }
                }
            }

            $isSequential = array_values($execParams) === $execParams;
            if ($isSequential) {
                $stmt->execute($execParams);
            } else {
                $norm = [];
                foreach ($execParams as $k => $v) {
                    $kk = is_string($k) && $k !== '' && $k[0] !== ':' ? ':'.$k : (string)$k;
                    $norm[$kk] = $v;
                }
                $stmt->execute($norm);
            }

            // N+1 tracking (safe)
            try { $this->n1Record($sql); } catch (\Throwable $_) {}

            $durationMs = (microtime(true) - $start) * 1000.0;
            $this->pushLastQuery($sql, $route, $durationMs, null);

            try {
                if ($this->debug && $this->logger !== null) {
                    $this->logger->info('Database query executed', [
                        'preview'        => $this->sanitizeSqlPreview($sql),
                        'duration_ms'    => round($durationMs, 2),
                        'on'             => $usedReplica ? 'replica' : 'primary',
                        'params_masked'  => \BlackCat\Database\Support\Observability::maskParams($params),
                    ]);
                } elseif ($durationMs > $this->slowQueryThresholdMs && $this->logger !== null) {
                    $this->logger->warning('Slow database query', [
                        'preview'        => $this->sanitizeSqlPreview($sql),
                        'duration_ms'    => round($durationMs, 2),
                        'on'             => $usedReplica ? 'replica' : 'primary',
                        'params_masked'  => \BlackCat\Database\Support\Observability::maskParams($params),
                    ]);
                    // auto-EXPLAIN (best-effort)
                    if ($this->autoExplain && preg_match('~^\s*SELECT\b~i', $sql)) {
                        try {
                            $plan = $this->explainPlan($sql, $params, $this->autoExplainAnalyze);
                            $this->logger->info('sql-explain-plan', ['plan' => $plan]);
                        } catch (\Throwable $_) {}
                    }
                }
            } catch (\Throwable $_) {}

            \BlackCat\Database\Support\Observability::endSpan($span, [
                'db.system'   => $this->driver() ?: 'unknown',
                'db.duration' => (string)round($durationMs, 2),
            ]);
            $this->notifyEnd($sql, $params, $durationMs, null, $route);

            $this->circuitOnSuccess();
            return $stmt;

        } catch (\PDOException $e) {
            $this->pushLastQuery($sql, $route, null, $e->getMessage());
            $this->notifyEnd($sql, $params, null, $e, $route);
            \BlackCat\Database\Support\Observability::endSpan($span, ['db.error' => '1']);
            $this->circuitOnFailure();

            // If replica failed and query is read-only, try primary once + reconnect replica and apply cooldown.
            $isReadOnlyVerb = !$this->isWriteSql($sql);
            if ($usedReplica && $isReadOnlyVerb && $attempt === 0) {
                try {
                    if ($this->isServerGone($e) || self::isTransientPdo($e)) {
                        $this->replicaDownUntil = time() + $this->replicaCooldownSec;
                        try { $this->reconnectReplica(); } catch (\Throwable $_) {}
                    }
                    $attempt = 1;
                    goto RETRY;
                } catch (\Throwable $_) {
                    // ignore and fall through
                }
            }

            // Original primary reconnect (if not in a transaction on the "used" PDO) + retry.
            if (!$pdoUsed->inTransaction() && $this->isServerGone($e) && $attempt <= 1 && !$usedReplica) {
                $attempt = 2;
                try { $this->reconnect(); } catch (\Throwable $_) {}
                goto RETRY;
            }

            if ($this->logger !== null) {
                try {
                    $this->logger->error('Database query failed', [
                        'exception'     => $e,
                        'sql_preview'   => $this->sanitizeSqlPreview($sql),
                        'on'            => $usedReplica ? 'replica' : 'primary',
                        'params_masked' => \BlackCat\Database\Support\Observability::maskParams($params),
                        'origin'        => (function() {
                            foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS) as $f) {
                                $file = $f['file'] ?? '';
                                if ($file !== '' && !str_ends_with($file, DIRECTORY_SEPARATOR.'Database.php')) {
                                    return $file.':'.($f['line'] ?? '?');
                                }
                            }
                            return '(unknown)';
                        })(),
                    ]);
                } catch (\Throwable $_) {}
            }

            $err  = $e->errorInfo[2] ?? $e->getMessage();
            $sqls = (string)($e->errorInfo[0] ?? '');
            $code = (string)($e->errorInfo[1] ?? $e->getCode());
            $origin = '(unknown)';
            foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS) as $f) {
                $file = $f['file'] ?? '';
                if ($file !== '' && !str_ends_with($file, DIRECTORY_SEPARATOR.'Database.php')) {
                    $origin = $file.':'.($f['line'] ?? '?');
                    break;
                }
            }

            $msg = 'Database query failed'
                . ($sqls!=='' ? " [SQLSTATE {$sqls}" . ($code!=='' ? "/{$code}" : '') . ']' : '')
                . ': ' . $this->sanitizeSqlPreview($err)
                . ' | SQL=' . $this->sanitizeSqlPreview($sql)
                . ' @ ' . $origin;

            // Map to a more specific type (helps retry/alerting).
            $mapped = $this->mapPdoToDomainException($e, $msg);
            throw $mapped;
        }
    }

    private function sqlFirewallGuard(string $sql): void
    {
        if ($this->sqlFirewallMode === 'off') {
            return;
        }

        $violations = $this->sqlFirewallViolations($sql);
        if ($violations === []) {
            return;
        }

        $msg = 'SQL firewall: blocked (' . implode(', ', $violations) . ')';
        $ctx = [
            'violations' => $violations,
            'preview' => $this->sanitizeSqlPreview($sql),
        ];

        if ($this->sqlFirewallMode === 'warn') {
            $this->logger?->warning($msg, $ctx);
            return;
        }

        $this->logger?->error($msg, $ctx);
        throw new DatabaseException($msg);
    }

    /**
     * @return list<string>
     */
    private function sqlFirewallViolations(string $sql): array
    {
        $san = $this->stripSqlLiteralsAndComments($sql);
        $trim = rtrim($san);

        $violations = [];

        // Multi-statement guard (block "; ..." and multiple semicolons; allow a single trailing ';').
        $firstSemi = strpos($trim, ';');
        if ($firstSemi !== false) {
            $lastSemi = strrpos($trim, ';');
            $onlyTrailing = ($lastSemi === strlen($trim) - 1) && ($firstSemi === $lastSemi);
            if (!$onlyTrailing) {
                $violations[] = 'multi_statement';
            }
        }

        $u = strtoupper($san);

        // MySQL/MariaDB primitives commonly used to escalate SQL injection into file IO or time-based DoS.
        if (preg_match('~\\bLOAD_FILE\\s*\\(~', $u)) $violations[] = 'load_file';
        if (preg_match('~\\bINTO\\s+OUTFILE\\b~', $u)) $violations[] = 'into_outfile';
        if (preg_match('~\\bINTO\\s+DUMPFILE\\b~', $u)) $violations[] = 'into_dumpfile';
        if (preg_match('~\\bLOAD\\s+DATA\\b~', $u)) $violations[] = 'load_data';
        if (preg_match('~\\bLOCAL\\s+INFILE\\b~', $u)) $violations[] = 'local_infile';
        if (preg_match('~\\bBENCHMARK\\s*\\(~', $u)) $violations[] = 'benchmark';
        if (preg_match('~\\bSLEEP\\s*\\(~', $u)) $violations[] = 'sleep';
        // Allow MySQL lock primitives when used as a standalone statement (internal DDL/install guards).
        // Still blocks their use in more complex queries where they are commonly a SQLi escalation signal.
        $isSimpleMysqlLockFn = (bool) preg_match(
            '~^\\s*SELECT\\s+(GET_LOCK|RELEASE_LOCK|RELEASE_ALL_LOCKS|IS_FREE_LOCK|IS_USED_LOCK)\\s*\\(~',
            $u
        );
        if (!$isSimpleMysqlLockFn && preg_match('~\\bGET_LOCK\\s*\\(~', $u)) $violations[] = 'get_lock';

        // Postgres: server-side COPY is a common escalation vector if DB creds are over-privileged.
        if ($this->isPg() && preg_match('~^\\s*COPY\\b~i', $u)) {
            $violations[] = 'copy';
        }

        return $violations;
    }

    private function stripSqlLiteralsAndComments(string $sql): string
    {
        $len = strlen($sql);
        $out = '';

        // MySQL/MariaDB only treats "--" as a comment when followed by whitespace/control.
        // Other dialects (e.g. Postgres) treat any "--" as a line comment.
        $mysqlDashDashNeedsSpace = $this->isMysql();
        $pgDollarQuotes = $this->isPg();

        $NORMAL = 0;
        $SINGLE = 1;
        $DOUBLE = 2;
        $BACKTICK = 3;
        $LINE_COMMENT = 4;
        $BLOCK_COMMENT = 5;

        $state = $NORMAL;
        for ($i = 0; $i < $len; $i++) {
            $ch = $sql[$i];

            if ($state === $NORMAL) {
                if ($ch === "'") {
                    $state = $SINGLE;
                    $out .= ' ';
                    continue;
                }
                if ($ch === '"') {
                    $state = $DOUBLE;
                    $out .= ' ';
                    continue;
                }
                if ($ch === '`') {
                    $state = $BACKTICK;
                    $out .= ' ';
                    continue;
                }
                // Postgres: dollar-quoted bodies (DO $$...$$; CREATE FUNCTION ... $$...$$;).
                // These can contain semicolons that are not SQL statement separators.
                if ($pgDollarQuotes && $ch === '$') {
                    $delimEnd = strpos($sql, '$', $i + 1);
                    if ($delimEnd !== false) {
                        $tag = substr($sql, $i + 1, $delimEnd - ($i + 1));
                        if (is_string($tag) && preg_match('/^[A-Za-z0-9_]*$/', $tag) === 1) {
                            $delim = '$' . $tag . '$';
                            $endPos = strpos($sql, $delim, $delimEnd + 1);
                            if ($endPos !== false) {
                                $blockEnd = $endPos + strlen($delim);
                                for ($k = $i; $k < $blockEnd; $k++) {
                                    $c = $sql[$k];
                                    $out .= ($c === "\n" || $c === "\r") ? $c : ' ';
                                }
                                $i = $blockEnd - 1;
                                continue;
                            }
                        }
                    }
                }
                if ($ch === '-' && ($i + 1) < $len && $sql[$i + 1] === '-') {
                    if ($mysqlDashDashNeedsSpace) {
                        $next = ($i + 2) < $len ? $sql[$i + 2] : '';
                        // In MySQL/MariaDB "--" begins a comment only when followed by
                        // whitespace/control (otherwise it is subtraction of a negative).
                        if ($next === '' || ord($next) > 0x20) {
                            $out .= $ch;
                            continue;
                        }
                    }
                    $state = $LINE_COMMENT;
                    $out .= '  ';
                    $i++;
                    continue;
                }
                if ($ch === '#') {
                    // MySQL/MariaDB supports "#" line comments; other dialects treat "#" as an operator/token.
                    if ($mysqlDashDashNeedsSpace) {
                        $state = $LINE_COMMENT;
                        $out .= ' ';
                        continue;
                    }
                    $out .= $ch;
                    continue;
                }
                if ($ch === '/' && ($i + 1) < $len && $sql[$i + 1] === '*') {
                    $state = $BLOCK_COMMENT;
                    $out .= '  ';
                    $i++;
                    continue;
                }
                $out .= $ch;
                continue;
            }

            if ($state === $LINE_COMMENT) {
                if ($ch === "\n" || $ch === "\r") {
                    $state = $NORMAL;
                    $out .= $ch;
                    continue;
                }
                $out .= ' ';
                continue;
            }

            if ($state === $BLOCK_COMMENT) {
                if ($ch === '*' && ($i + 1) < $len && $sql[$i + 1] === '/') {
                    $state = $NORMAL;
                    $out .= '  ';
                    $i++;
                    continue;
                }
                $out .= ' ';
                continue;
            }

            if ($state === $SINGLE) {
                if ($ch === '\\') {
                    $out .= ' ';
                    if (($i + 1) < $len) {
                        $out .= ' ';
                        $i++;
                    }
                    continue;
                }
                if ($ch === "'") {
                    if (($i + 1) < $len && $sql[$i + 1] === "'") {
                        $out .= '  ';
                        $i++;
                        continue;
                    }
                    $state = $NORMAL;
                    $out .= ' ';
                    continue;
                }
                $out .= ' ';
                continue;
            }

            if ($state === $DOUBLE) {
                if ($ch === '\\') {
                    $out .= ' ';
                    if (($i + 1) < $len) {
                        $out .= ' ';
                        $i++;
                    }
                    continue;
                }
                if ($ch === '"') {
                    if (($i + 1) < $len && $sql[$i + 1] === '"') {
                        $out .= '  ';
                        $i++;
                        continue;
                    }
                    $state = $NORMAL;
                    $out .= ' ';
                    continue;
                }
                $out .= ' ';
                continue;
            }

            // BACKTICK
            if ($ch === '\\') {
                $out .= ' ';
                if (($i + 1) < $len) {
                    $out .= ' ';
                    $i++;
                }
                continue;
            }
            if ($ch === '`') {
                if (($i + 1) < $len && $sql[$i + 1] === '`') {
                    $out .= '  ';
                    $i++;
                    continue;
                }
                $state = $NORMAL;
                $out .= ' ';
                continue;
            }
            $out .= ' ';
        }

        return $out;
    }

    // query() unified with prepareAndRun(), so it does not bypass guards.
    public function query(string $sql): \PDOStatement
    {
        return $this->prepareAndRun($sql, []);
    }

    public function executeRaw(string $sql, array $params = []): int
    {
        $stmt = $this->prepareAndRun($sql, $params);
        try {
            $n = $stmt->rowCount();
            if ($this->isWriteSql($sql)) {
                $this->lastWriteAtMs = microtime(true) * 1000.0;
            }
            return $n;
        } finally {
            $stmt->closeCursor();
        }
    }

    public function transaction(callable $fn): mixed
    {
        $pdo = $this->pdoPrimary();

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

        if (!$this->supportsSavepoints()) {
            return $fn($this);
        }

        static $fallbackCounter = 0;
        try {
            $sp = 'SP_' . bin2hex(random_bytes(6));
            $sp = preg_replace('/[^A-Za-z0-9_]/', '', $sp);
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

    public function inTransaction(): bool
    {
        try { return $this->pdoPrimary()->inTransaction(); }
        catch (\Throwable $_) { return false; }
    }

    public function fetch(string $sql, array $params = []): ?array
    {
        $stmt = $this->prepareAndRun($sql, $params);
        try {
            $row = $stmt->fetch();
            return $row === false ? null : $row;
        } finally {
            $stmt->closeCursor();
        }
    }

    public function fetchAll(string $sql, array $params = []): array
    {
        $stmt = $this->prepareAndRun($sql, $params);
        try {
            $rows = [];
            while (true) {
                $row = $stmt->fetch(\PDO::FETCH_ASSOC);
                if ($row === false) break;
                $rows[] = $row;
            }
            return $rows;
        } finally {
            $stmt->closeCursor();
        }
    }

    public function iterate(string $sql, array $params = []): \Generator {
        $stmt = $this->prepareAndRun($sql, $params);
        try {
            while (($row = $stmt->fetch(\PDO::FETCH_ASSOC)) !== false) {
                yield $row;
            }
        } finally {
            $stmt->closeCursor();
        }
    }

    public function execute(string $sql, array $params = []): int
    {
        $this->circuitCheck();
        $stmt = $this->prepareAndRun($sql, $params);
        try {
            $n = $stmt->rowCount();
            if ($this->isWriteSql($sql)) {
                $this->lastWriteAtMs = microtime(true) * 1000.0;
            }
            return $n;
        } finally {
            $stmt->closeCursor();
        }
    }

    public function beginTransaction(): bool
    {
        try { return $this->pdoPrimary()->beginTransaction(); }
        catch (\PDOException $e) {
            if ($this->logger !== null) {
                try { $this->logger->error('Failed to begin transaction', ['exception' => $e, 'phase' => 'beginTransaction']); } catch (\Throwable $_) {}
            }
            throw new DatabaseException('Failed to begin transaction', 0, $e);
        }
    }

    public function commit(): bool
    {
        try { return $this->pdoPrimary()->commit(); }
        catch (\PDOException $e) {
            if ($this->logger !== null) {
                try { $this->logger->error('Failed to commit transaction', ['exception' => $e, 'phase' => 'commit']); } catch (\Throwable $_) {}
            }
            throw new DatabaseException('Failed to commit transaction', 0, $e);
        }
    }

    public function rollback(): bool
    {
        try { return $this->pdoPrimary()->rollBack(); }
        catch (\PDOException $e) {
            if ($this->logger !== null) {
                try { $this->logger->error('Failed to rollback transaction', ['exception' => $e, 'phase' => 'rollback']); } catch (\Throwable $_) {}
            }
            throw new DatabaseException('Failed to rollback transaction', 0, $e);
        }
    }

    public function lastInsertId(?string $name = null): ?string
    {
        try {
            $id = $this->pdoPrimary()->lastInsertId($name);
            return $id === false ? null : $id;
        } catch (\Throwable $e) {
            $this->logger?->warning('lastInsertId() failed', [
                'message' => $e->getMessage(),
            ]);
            return null;
        }
    }

    private function supportsSavepoints(): bool
    {
        try {
            $driver = $this->pdoPrimary()->getAttribute(\PDO::ATTR_DRIVER_NAME);
            return in_array($driver, ['mysql', 'pgsql', 'sqlite'], true);
        } catch (\Throwable $_) {
            return false;
        }
    }

    public function setSlowQueryThresholdMs(int $ms): void { $this->slowQueryThresholdMs = max(0, $ms); }

    private function __clone() {}
    public function __wakeup(): void { throw new DatabaseException('Cannot unserialize singleton'); }

    public function ping(): bool
    {
        try { $this->pdoPrimary()->query('SELECT 1'); return true; }
        catch (\Throwable $e) { return false; }
    }

    public function fetchValue(string $sql, array $params = [], mixed $default = null): mixed
    {
        $stmt = $this->prepareAndRun($sql, $params);
        try {
            $val = $stmt->fetchColumn(0);
            return ($val === false) ? $default : $val;
        } finally {
            $stmt->closeCursor();
        }
    }

    public function fetchColumn(string $sql, array $params = []): array
    {
        $stmt = $this->prepareAndRun($sql, $params);
        try {
            $out = [];
            while (($val = $stmt->fetchColumn(0)) !== false) {
                $out[] = $val;
            }
            return $out;
        } finally {
            $stmt->closeCursor();
        }
    }

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

    public function exists(string $sql, array $params = []): bool
    {
        $stmt = $this->prepareAndRun($sql, $params);
        try {
            $row = $stmt->fetch();
            return $row !== false && $row !== null;
        } finally {
            $stmt->closeCursor();
        }
    }

    /**
     * Fast existence check via SELECT 1 FROM (<sql>) LIMIT 1 – does not read row payload.
     * Useful for large tables / wide rows.
     */
    public function existsFast(string $sql, array $params = []): bool
    {
        $wrapped = "SELECT 1 FROM ({$sql}) AS __sub LIMIT 1";
        $val = $this->fetchValue($wrapped, $params, null);
        return $val !== null && $val !== false;
    }

    public function withEmulation(bool $on, callable $fn): mixed {
        $pdo = $this->pdoPrimary();
        $orig = $pdo->getAttribute(\PDO::ATTR_EMULATE_PREPARES);
        try {
            $pdo->setAttribute(\PDO::ATTR_EMULATE_PREPARES, $on);
            return $fn($this);
        } finally {
            $pdo->setAttribute(\PDO::ATTR_EMULATE_PREPARES, $orig);
        }
    }

    public function paginate(string $sql, array $params = [], int $page = 1, int $perPage = 20, ?string $countSql = null): array
    {
        $page = max(1, (int)$page);
        $perPage = max(1, (int)$perPage);
        $offset = ($page - 1) * $perPage;

        $usePositional = $this->usesPositionalOnly($sql);

        if ($usePositional) {
            $pagedSql = $sql . " LIMIT ? OFFSET ?";
            $paramsWithLimit = array_values($params);
            $paramsWithLimit[] = $perPage;
            $paramsWithLimit[] = $offset;
        } else {
            $pagedSql = $sql . " LIMIT :__limit OFFSET :__offset";
            $paramsWithLimit = $params;
            $paramsWithLimit['__limit']  = $perPage;
            $paramsWithLimit['__offset'] = $offset;
        }

        $items = $this->fetchAll($pagedSql, $paramsWithLimit);

        $total = 0;
        if ($countSql !== null) {
            $total = (int)$this->fetchValue($countSql, $params, 0);
        } else {
            try {
                $total = (int)$this->fetchValue("SELECT COUNT(*) FROM ({$sql}) AS __count_sub", $params, 0);
            } catch (\Throwable $_) {
                $total = count($items);
            }
        }

        return [
            'items'   => $items,
            'total'   => $total,
            'page'    => $page,
            'perPage' => $perPage,
        ];
    }

    public function enableReadOnlyGuard(bool $on = true): void { $this->readOnlyGuard = $on; }
    public function isReadOnlyGuardEnabled(): bool { return $this->readOnlyGuard; }

    public static function setWriteGuard(?callable $guard): void
    {
        if (self::$writeGuardLocked) {
            throw new DatabaseException('Database write guard is locked.');
        }
        self::$writeGuard = $guard;
    }

    /**
     * Optional security hook: called before executing read-only statements.
     *
     * In TrustKernel deployments this is used to fail-closed on DB reads when the
     * kernel denies reads (e.g. integrity mismatch / paused controller / stale beyond max).
     */
    public static function setReadGuard(?callable $guard): void
    {
        if (self::$readGuardLocked) {
            throw new DatabaseException('Database read guard is locked.');
        }
        self::$readGuard = $guard;
    }

    public static function lockWriteGuard(): void
    {
        if (self::$writeGuard === null) {
            throw new DatabaseException('Database write guard cannot be locked when not set.');
        }
        self::$writeGuardLocked = true;
    }

    public static function isWriteGuardLocked(): bool
    {
        return self::$writeGuardLocked;
    }

    public static function hasWriteGuard(): bool
    {
        return self::$writeGuard !== null;
    }

    public static function lockReadGuard(): void
    {
        if (self::$readGuard === null) {
            throw new DatabaseException('Database read guard cannot be locked when not set.');
        }
        self::$readGuardLocked = true;
    }

    public static function isReadGuardLocked(): bool
    {
        return self::$readGuardLocked;
    }

    public static function hasReadGuard(): bool
    {
        return self::$readGuard !== null;
    }

    /**
     * Optional security hook: called before exposing raw PDO via {@see self::getPdo()}.
     *
     * This is intended to prevent bypassing kernel guards by calling `$db->getPdo()->exec(...)` directly.
     *
     * The callable receives a context string (currently: "db.raw_pdo").
     */
    public static function setPdoAccessGuard(?callable $guard): void
    {
        if (self::$pdoAccessGuardLocked) {
            throw new DatabaseException('Database PDO access guard is locked.');
        }
        self::$pdoAccessGuard = $guard;
    }

    public static function lockPdoAccessGuard(): void
    {
        if (self::$pdoAccessGuard === null) {
            throw new DatabaseException('Database PDO access guard cannot be locked when not set.');
        }
        self::$pdoAccessGuardLocked = true;
    }

    public static function isPdoAccessGuardLocked(): bool
    {
        return self::$pdoAccessGuardLocked;
    }

    public static function hasPdoAccessGuard(): bool
    {
        return self::$pdoAccessGuard !== null;
    }

    private function autoBootTrustKernelIfPossible(): void
    {
        if (self::$trustKernelAutoBootAttempted) {
            return;
        }
        self::$trustKernelAutoBootAttempted = true;

        try {
            // Security-first:
            // - If blackcat-config is installed, treat it as a trust-required deployment and fail-closed.
            // - Otherwise (legacy stacks), best-effort boot when configured.
            $configClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'Config']);
            $repoClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'ConfigRepository']);
            if (class_exists($configClass) && class_exists($repoClass)) {
                \BlackCat\Core\Kernel\KernelBootstrap::bootOrFail($this->logger);
                return;
            }

            \BlackCat\Core\Kernel\KernelBootstrap::bootIfConfigured($this->logger);
        } catch (\Throwable $e) {
            throw new DatabaseException('TrustKernel auto-boot failed: ' . $e->getMessage(), 0, $e);
        }
    }

    public static function encodeCursor(array $cursor): string {
        $j = json_encode($cursor, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
        return rtrim(strtr(base64_encode($j), '+/', '-_'), '=');
    }
    public static function decodeCursor(?string $token): ?array {
        if (!$token) return null;
        $p = strtr($token, '-_', '+/');
        $p .= str_repeat('=', (4 - strlen($p) % 4) % 4);
        $j = base64_decode($p, true);
        if ($j === false) return null;
        $a = json_decode($j, true);
        return is_array($a) ? $a : null;
    }

    public function configureCircuit(int $threshold = 8, int $cooldownSec = 10): void {
        $this->cbThreshold = max(1,$threshold);
        $this->cbCooldownSec = max(1,$cooldownSec);
    }

    private function circuitCheck(): void {
        if ($this->cbOpenUntil && time() < $this->cbOpenUntil) {
            throw new DatabaseException('DB circuit open (cooldown)');
        }
    }
    private function circuitOnSuccess(): void { $this->cbFails = 0; $this->cbOpenUntil = null; }
    private function circuitOnFailure(): void {
        if (++$this->cbFails >= $this->cbThreshold) { $this->cbOpenUntil = time() + $this->cbCooldownSec; }
    }
}
