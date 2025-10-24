<?php
declare(strict_types=1);

namespace BlackCat\Core;

use Psr\Log\LoggerInterface;

class DatabaseException extends \RuntimeException {}

final class Database
{
    private static ?self $instance = null;
    private ?\PDO $pdo = null;
    private array $config = [];
    private ?LoggerInterface $logger = null;
    private string $dsnId = 'unknown';

    /**
     * Soukromý konstruktor — singleton
     */
    private function __construct(array $config, \PDO $pdo, ?LoggerInterface $logger = null)
    {
        $this->config = $config;
        $this->pdo = $pdo;
        $this->logger = $logger;
    }

    private static function dsnFingerprint(string $dsn): string {
        // mysql:host=127.0.0.1;port=3306;dbname=test;charset=utf8mb4
        // pgsql:host=127.0.0.1;port=5432;dbname=test
        $m = [];
        if (preg_match('~^(mysql|pgsql):.*?host=([^;]+)(?:;port=([0-9]+))?.*?(?:;dbname=([^;]+))?~i', $dsn, $m)) {
            $drv = strtolower($m[1]); $host = $m[2] ?? 'localhost'; $port = $m[3] ?? ($drv==='mysql'?'3306':'5432'); $db = $m[4] ?? '';
            return "{$drv}://{$host}:{$port}/{$db}";
        }
        return substr(hash('sha256', $dsn), 0, 16);
    }

    /**
     * Inicializace (volej z bootstrapu) - eager connect
     *
     * Pokud chceš logování, předej implementaci Psr\Log\LoggerInterface jako druhý parametr.
     *
     * Konfigurace: [
     *   'dsn' => 'mysql:host=...;dbname=...;charset=utf8mb4',
     *   'user' => 'dbuser',
     *   'pass' => 'secret',
     *   'options' => [\PDO::ATTR_TIMEOUT => 5, ...],
     *   'init_commands' => [ "SET time_zone = '+00:00'", "SET sql_mode = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION'" ]
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

        if (!$dsn) {
            throw new DatabaseException('Missing DSN in database configuration.');
        }

        // Bezpečnostní defaulty, které nelze přepsat
        $enforcedDefaults = [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_EMULATE_PREPARES => false,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
            \PDO::ATTR_STRINGIFY_FETCHES => false,
        ];

        $options = $givenOptions;
        foreach ($enforcedDefaults as $k => $v) {
            $options[$k] = $v;
        }

        try {
			// Pokud je DSN MySQL, vypni bufferování (šetří RAM u velkých výsledků)
			if (is_string($dsn) && str_starts_with($dsn, 'mysql:') && defined('PDO::MYSQL_ATTR_USE_BUFFERED_QUERY')) {
			    $options[\PDO::MYSQL_ATTR_USE_BUFFERED_QUERY] = false;
			}
            $pdo = new \PDO($dsn, $user, $pass, $options);
			// Enforce i po inicializaci (pro případ, že options to nepřevzaly)
			if ($pdo->getAttribute(\PDO::ATTR_DRIVER_NAME) === 'mysql' && defined('PDO::MYSQL_ATTR_USE_BUFFERED_QUERY')) {
			    $pdo->setAttribute(\PDO::MYSQL_ATTR_USE_BUFFERED_QUERY, false);
			}
            // Run optional initialization commands (best-effort)
            if (!empty($initCommands) && is_array($initCommands)) {
                foreach ($initCommands as $cmd) {
                    if (!is_string($cmd)) continue;
                    try { $pdo->exec($cmd); } catch (\PDOException $_) { /* ignore init failures */ }
                }
            }

            // Basic connectivity check
            try {
                $pdo->query('SELECT 1');
            } catch (\PDOException $e) {
                // non-fatal connectivity warning (pokud je logger dostupný)
                if ($logger !== null) {
                    try {
                        $logger->warning('Database connectivity check failed', ['error' => substr((string)$e->getMessage(), 0, 200)]);
                    } catch (\Throwable $_) { /* swallow logger errors */ }
                }
                throw new DatabaseException('Failed to connect to database', 0, $e);
            }

        } catch (\PDOException $e) {
            // Minimal, non-sensitive log via injected logger (no plaintext credentials).
            if ($logger !== null) {
                try {
                    $logger->error('Failed to connect to database (init)', [
                                    'message' => $e->getMessage(),
                                    'code' => $e->getCode(),
                                    'phase' => 'init'
                                ]);
                } catch (\Throwable $_) {
                    // swallow — logger must not throw
                }
            }
            throw new DatabaseException('Failed to connect to database', 0, $e);
        }

        self::$instance = new self($config, $pdo, $logger);
        self::$instance->dsnId = is_string($dsn) ? self::dsnFingerprint($dsn) : 'unknown';
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
    public function getPdo(): \PDO
    {
        if ($this->pdo === null) {
            throw new DatabaseException('Database not initialized properly (PDO missing).');
        }
        return $this->pdo;
    }

    public function setLogger(\Psr\Log\LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }
    
    /**
     * Volitelně získat logger (může být null).
     */
    public function getLogger(): ?LoggerInterface
    {
        return $this->logger;
    }

    /**
     * Ptá se, zda je DB initnuta
     */
    public static function isInitialized(): bool
    {
        return self::$instance !== null;
    }

    public function close(): void
    {
        $this->pdo = null; // necháš GC uzavřít spojení
    }

    /* ----------------- Helper metody ----------------- */

    /** @var bool */
    private bool $debug = false;

    /** Volitelně povolit debug/logging (nevolat v produkci bez zabezpečeného logu) */
    public function enableDebug(bool $on = true): void
    {
        $this->debug = $on;
    }

	public function exec(string $sql): int
	{
		try {
			return $this->getPdo()->exec($sql);
		} catch (\PDOException $e) {
			if ($this->logger !== null) {
				try { $this->logger->error('Exec failed', ['exception' => $e, 'sql_preview' => $this->sanitizeSqlPreview($sql)]); } catch (\Throwable $_) {}
			}
			throw new DatabaseException('Exec failed', 0, $e);
		}
	}

    public function id(): string { return $this->dsnId; }

    public function serverVersion(): ?string {
        try { return (string)$this->getPdo()->getAttribute(\PDO::ATTR_SERVER_VERSION); }
        catch (\Throwable $_) { return null; }
    }

    public function quote(string $value): string {
        $q = $this->getPdo()->quote($value);
        return $q === false ? "'" . str_replace("'", "''", $value) . "'" : $q;
    }

    public function withStatement(string $sql, callable $cb): mixed {
        $stmt = $this->query($sql);
        try { return $cb($stmt); }
        finally { $stmt->closeCursor(); }
    }

	/** Alias na první hodnotu prvního řádku – kompatibilita se šablonami */
	public function fetchOne(string $sql, array $params = []): mixed
	{
		return $this->fetchValue($sql, $params, null);
	}

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

    private function isTransient(\PDOException $e): bool {
        $sqlstate = $e->errorInfo[0] ?? (string)$e->getCode();
        $code     = (int)($e->errorInfo[1] ?? 0);
        // PG: deadlock/serialization
        if (in_array($sqlstate, ['40P01','40001'], true)) return true;
        // MySQL: deadlock (1213), lock timeout (1205)
        if ($code === 1213 || $code === 1205 || $sqlstate === '40001') return true;
        return false;
    }

    public function withAdvisoryLock(string $name, int $timeoutSec, callable $fn): mixed {
        if ($this->isMysql()) {
            $ok = (bool)$this->fetchValue('SELECT GET_LOCK(:n, :t)', [':n'=>$name, ':t'=>$timeoutSec], 0);
            if (!$ok) throw new DatabaseException("GET_LOCK timeout: $name");
            try { return $fn($this); }
            finally { $this->execute('SELECT RELEASE_LOCK(:n)', [':n'=>$name]); }
        }
        if ($this->isPg()) {
            // bigint forma; hash se řeší na serveru (méně kolizí, čisté odemykání)
            $ok = (bool)$this->fetchValue('SELECT pg_try_advisory_lock(hashtextextended(:n, 0))', [':n'=>$name], 0);
            if (!$ok) throw new DatabaseException("pg_try_advisory_lock busy: $name");
            try { return $fn($this); }
            finally { $this->execute('SELECT pg_advisory_unlock(hashtextextended(:n, 0))', [':n'=>$name]); }
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
            $ms = max(0,$ms);
            $old = (int)$this->fetchValue('SELECT @@SESSION.max_execution_time', [], 0);
            try {
                $this->exec('SET SESSION max_execution_time = '.(int)$ms);
                return $fn($this);
            } finally {
                $this->exec('SET SESSION max_execution_time = '.$old);
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
            // musí se nastavit pro NÁSLEDUJÍCÍ transakci → sami ji otevřeme
            $pdo = $this->getPdo();
            if ($pdo->inTransaction()) {
                // v probíhající transakci MySQL level nezmění → fallback
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

    public function explainPlan(string $sql, array $params = [], bool $analyze = false): array
    {
        if ($this->isMysql()) {
            // v MySQL nedáváme ANALYZE by default (spouští se dotaz)
            return $this->fetchAll('EXPLAIN ' . $sql, $params);
        }

        if ($this->isPg()) {
            if ($analyze) {
                // JSON je praktické pro nástroje
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
            // složí OR s více IN bloky (IN (...) OR IN (...))
            $parts = []; $params = []; $i=0; $g=0;
            foreach (array_chunk($values, $chunk) as $grp) {
                $ph = [];
                foreach ($grp as $v) {
                    $k = ":{$prefix}_{$g}_".$i++;
                    $ph[] = $k; $params[$k] = $v;
                }
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
        $pdo = $this->getPdo();

        if ($this->isPg()) {
            return $this->transaction(function() use($fn) {
                $this->exec('SET TRANSACTION READ ONLY');
                return $fn($this);
            });
        }

        if ($this->isMysql()) {
            if ($pdo->inTransaction()) {
                // MySQL neumí změnit aktuální transakci na RO → fallback: prostě to spusť
                return $fn($this);
            }
            // explicitně zahájíme READ ONLY transakci
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

    /**
     * Keyset pagination (seek) přes primární klíč/unikátní sloupec.
     *
     * @param string            $sqlBase   SELECT ... FROM ... [JOIN ...] [WHERE ...]  (bez ORDER/LIMIT)
     * @param array             $params    pojmenované nebo poziční parametry pro $sqlBase
     * @param string            $pkCol     název sloupce/aliasu v resultsetu (např. "t.id")
     * @param string|int|null   $afterPk   poslední hodnota z předchozí stránky (cursor), nebo null pro první stránku
     * @param int               $limit     velikost stránky (>=1)
     * @param 'ASC'|'DESC'      $direction směr stránkování (default 'DESC')
     * @param bool              $inclusive zda použít >=/<= (true) nebo >/< (false)
     */
    public function paginateKeyset(
        string $sqlBase,
        array $params,
        string $pkCol,
        string|int|null $afterPk,
        int $limit = 50,
        string $direction = 'DESC',
        bool $inclusive = false
    ): array {
        $limit = max(1, (int)$limit);
        $dir   = strtoupper($direction) === 'ASC' ? 'ASC' : 'DESC';
        $cmp   = $inclusive
            ? ($dir === 'ASC' ? '>=' : '<=')
            : ($dir === 'ASC' ? '>'  : '<');

        // Bezpečné quote identifikátoru (podporuje i "t.id")
        $idExpr = $this->quoteIdent($pkCol);

        // Správně vložit WHERE/AND podle toho, zda $sqlBase už obsahuje WHERE
        $hasWhere = (bool)preg_match('/\bwhere\b/i', $sqlBase);
        $condSql  = '';
        $p        = $params;

        if ($afterPk !== null) {
            $condSql = ($hasWhere ? ' AND ' : ' WHERE ') . "$idExpr $cmp :__after";
            $p['__after'] = $afterPk;
        } elseif (!$hasWhere) {
            // sjednoťme pattern kvůli pozdějšímu rozšiřování
            $condSql = ' WHERE 1=1';
        }

        $sql = $sqlBase . $condSql . " ORDER BY $idExpr $dir LIMIT :__limit";
        $p['__limit'] = $limit;

        $items = $this->fetchAll($sql, $p);
        $next  = $items ? end($items)[$pkCol] ?? null : null;

        return [
            'items'     => $items,
            'nextAfter' => $next,
            'limit'     => $limit,
            'direction' => $dir,
        ];
    }

    public function executeWithRetry(string $sql, array $params = [], int $attempts = 3, int $baseDelayMs = 50): int {
        $try = 0; $delay = $baseDelayMs;
        while (true) {
            try { return $this->execute($sql, $params); }
            catch (\PDOException $e) {
                if (++$try >= $attempts || !$this->isTransient($e)) throw $e;
                usleep($delay * 1000); $delay = (int)min($delay * 2, 1000);
            }
        }
    }

    public function executeOne(string $sql, array $params = []): void {
        $n = $this->execute($sql, $params);
        if ($n !== 1) throw new DatabaseException("Expected to affect 1 row, affected={$n}");
    }

	/** Driver name helper (mysql|pgsql|sqlite|...) */
	public function driver(): ?string
	{
		try { return (string)$this->getPdo()->getAttribute(\PDO::ATTR_DRIVER_NAME); }
		catch (\Throwable $_) { return null; }
	}

	public function isMysql(): bool { return $this->driver() === 'mysql'; }
	public function isPg(): bool    { return $this->driver() === 'pgsql'; }

    private function isServerGone(\PDOException $e): bool
    {
        $m = strtolower($e->getMessage() ?? '');
        return str_contains($m, 'server has gone away')
            || str_contains($m, 'lost connection')
            || str_contains($m, 'connection refused')
            || str_contains($m, 'closed the connection unexpectedly');
    }

    /** Rebuildne PDO v rámci instance – BEZ změny singletonu */
    private function reconnect(): void
    {
        $cfg = $this->config;
        $dsn = $cfg['dsn'] ?? null;
        $user = $cfg['user'] ?? null;
        $pass = $cfg['pass'] ?? null;
        $givenOptions = $cfg['options'] ?? [];

        $enforced = [
            \PDO::ATTR_ERRMODE            => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_EMULATE_PREPARES   => false,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
            \PDO::ATTR_STRINGIFY_FETCHES  => false,
        ];
        $opt = $givenOptions + $enforced;

        if (is_string($dsn) && str_starts_with($dsn, 'mysql:') && defined('PDO::MYSQL_ATTR_USE_BUFFERED_QUERY')) {
            $opt[\PDO::MYSQL_ATTR_USE_BUFFERED_QUERY] = false;
        }

        $pdo = new \PDO((string)$dsn, $user, $pass, $opt);
        if ($pdo->getAttribute(\PDO::ATTR_DRIVER_NAME) === 'mysql' && defined('PDO::MYSQL_ATTR_USE_BUFFERED_QUERY')) {
            $pdo->setAttribute(\PDO::MYSQL_ATTR_USE_BUFFERED_QUERY, false);
        }
        $this->pdo = $pdo; // ← aktualizace aktuální instance
    }

    public function prepareAndRun(string $sql, array $params = []): \PDOStatement
    {
        $start = microtime(true);
        $attempt = 0;

        RETRY:
        try {
            $pdo = $this->getPdo();
            $stmt = $pdo->prepare($sql);
            if ($stmt === false) {
                throw new DatabaseException('Failed to prepare statement.');
            }

            // numericky indexované vs. pojmenované
            $isSequential = array_values($params) === $params;

            if ($isSequential) {
                // Pozn.: u sekvenčních neřešíme typy, PDO si poradí
                $stmt->execute($params);
            } else {
                foreach ($params as $key => $value) {
                    $paramName = (strpos((string)$key, ':') === 0) ? (string)$key : ':' . (string)$key;

                    // typy
                    if (is_resource($value)) {
                        $stmt->bindValue($paramName, $value, \PDO::PARAM_LOB);
                    } elseif ($value === null) {
                        $stmt->bindValue($paramName, null, \PDO::PARAM_NULL);
                    } elseif (is_int($value)) {
                        $stmt->bindValue($paramName, $value, \PDO::PARAM_INT);
                    } elseif (is_bool($value)) {
                        $stmt->bindValue($paramName, $value, \PDO::PARAM_BOOL);
                    } elseif (is_string($value)) {
                        // NUL byte → binární
                        $stmt->bindValue($paramName, $value, str_contains($value, "\0") ? \PDO::PARAM_LOB : \PDO::PARAM_STR);
                    } elseif ($value instanceof \Stringable) {
                        $stmt->bindValue($paramName, (string)$value, \PDO::PARAM_STR);
                    } else {
                        $stmt->bindValue($paramName, (string)$value, \PDO::PARAM_STR);
                    }
                }
                $stmt->execute();
            }

            $durationMs = (microtime(true) - $start) * 1000.0;

            // logování
            try {
                if ($this->debug && $this->logger !== null) {
                    $this->logger->info('Database query executed', [
                        'preview' => $this->sanitizeSqlPreview($sql),
                        'duration_ms' => round($durationMs, 2),
                    ]);
                } elseif ($durationMs > $this->slowQueryThresholdMs && $this->logger !== null) {
                    $this->logger->warning('Slow database query', [
                        'preview' => $this->sanitizeSqlPreview($sql),
                        'duration_ms' => round($durationMs, 2),
                    ]);
                }
            } catch (\Throwable $_) {}

            return $stmt;

        } catch (\PDOException $e) {
            // 1× reconnect & retry, ale jen mimo aktivní transakci
            if (!$this->getPdo()->inTransaction() && $this->isServerGone($e) && $attempt === 0) {
                $attempt = 1;
                try { $this->reconnect(); } catch (\Throwable $_) {}
                goto RETRY;
            }
            if ($this->logger !== null) {
                try {
                    $this->logger->error('Database query failed', [
                        'exception' => $e,
                        'sql_preview' => $this->sanitizeSqlPreview($sql)
                    ]);
                } catch (\Throwable $_) {}
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
        } catch (\PDOException $e) {
            if ($this->logger !== null) {
                try { $this->logger->error('Query failed', ['exception' => $e, 'sql_preview' => $this->sanitizeSqlPreview($sql)]); } catch (\Throwable $_) {}
            }
            throw new DatabaseException('Query failed', 0, $e);
        }
    }

    /** Execute raw SQL with params — convenient wrapper */
	public function executeRaw(string $sql, array $params = []): int
	{
	    $stmt = $this->prepareAndRun($sql, $params);
	    try {
	        return $stmt->rowCount();
	    } finally {
	        $stmt->closeCursor();
	    }
	}

    /**
     * transaction wrapper with support for savepoints (nested transactions).
     */
    public function transaction(callable $fn): mixed
    {
        $pdo = $this->getPdo();

        // Pokud ještě nejsme v transakci, zahájíme běžnou
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

        // --- Jsme v transakci → pokus o savepoint (nested transaction) ---
        if (!$this->supportsSavepoints()) {
            // fallback — žádné savepointy, prostě to jen spustíme v rámci stávající transakce
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

	public function fetch(string $sql, array $params = []): ?array
	{
	    $stmt = $this->prepareAndRun($sql, $params);
	    try {
	        $row = $stmt->fetch();
	        return $row === false ? null : $row;
	    } finally {
	        // Důležité pro unbuffered MySQL – uvolní serverové zdroje
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

    /**
     * Execute an INSERT/UPDATE/DELETE and return affected rows.
     */
	public function execute(string $sql, array $params = []): int
	{
	    $stmt = $this->prepareAndRun($sql, $params);
	    try {
	        return $stmt->rowCount();
	    } finally {
	        $stmt->closeCursor();
	    }
	}

    /* transactions */
    public function beginTransaction(): bool
    {
        try { return $this->getPdo()->beginTransaction(); }
        catch (\PDOException $e) {
            if ($this->logger !== null) {
                try { $this->logger->error('Failed to begin transaction', ['exception' => $e, 'phase' => 'beginTransaction']); } catch (\Throwable $_) {}
            }
            throw new DatabaseException('Failed to begin transaction', 0, $e);
        }
    }

    public function commit(): bool
    {
        try { return $this->getPdo()->commit(); }
        catch (\PDOException $e) {
            if ($this->logger !== null) {
                try { $this->logger->error('Failed to commit transaction', ['exception' => $e, 'phase' => 'commit']); } catch (\Throwable $_) {}
            }
            throw new DatabaseException('Failed to commit transaction', 0, $e);
        }
    }

    public function rollback(): bool
    {
        try { return $this->getPdo()->rollBack(); }
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
            return $this->getPdo()->lastInsertId($name);
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
            $driver = $this->getPdo()->getAttribute(\PDO::ATTR_DRIVER_NAME);
            return in_array($driver, ['mysql', 'pgsql', 'sqlite'], true);
        } catch (\Throwable $_) {
            return false;
        }
    }

    /* sanitizace SQL preview pro log (neukládat parametry s citlivými údaji) */
    private function sanitizeSqlPreview(string $sql): string
    {
        $s = preg_replace("/'[^']{5,}'/", "'…'", $sql);
        // collapse whitespace & remove newlines
        $s = preg_replace('/\s+/', ' ', trim($s));
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
	    $stmt = $this->prepareAndRun($sql, $params);
	    try {
	        $val = $stmt->fetchColumn(0);
	        return ($val === false) ? $default : $val;
	    } finally {
	        $stmt->closeCursor();
	    }
	}

    /**
     * Vrátí pole hodnot z jedné kolony (první sloupec každého řádku).
     */
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

    /**
     * Vrátí asociativní pole párově key=>value podle první a druhé kolony.
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
     */
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
     * Jednoduchý per-request cache pro časté read-only dotazy.
     */
    public function withEmulation(bool $on, callable $fn): mixed {
        $pdo = $this->getPdo();
        $orig = $pdo->getAttribute(\PDO::ATTR_EMULATE_PREPARES);
        try {
            $pdo->setAttribute(\PDO::ATTR_EMULATE_PREPARES, $on);
            return $fn($this);
        } finally {
            $pdo->setAttribute(\PDO::ATTR_EMULATE_PREPARES, $orig);
        }
    }
    
    /**
     * Paginate helper ...
     */
    public function paginate(string $sql, array $params = [], int $page = 1, int $perPage = 20, ?string $countSql = null): array
    {
        $page = max(1, (int)$page);
        $perPage = max(1, (int)$perPage);
        $offset = ($page - 1) * $perPage;

        $pagedSql = $sql . " LIMIT :__limit OFFSET :__offset";
        $paramsWithLimit = $params;
        $paramsWithLimit['__limit'] = $perPage;
        $paramsWithLimit['__offset'] = $offset;
        $items = $this->fetchAll($pagedSql, $paramsWithLimit);

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
            'items' => $items,
            'total' => $total,
            'page'  => $page,
            'perPage' => $perPage,
        ];
    }
}
