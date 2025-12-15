<?php
declare(strict_types=1);

namespace BlackCat\Core\Migrations;

use BlackCat\Core\Database;
use Psr\Log\LoggerInterface;

/**
 * Lightweight schema migrator backed by a single table storing applied versions.
 *
 * Expected table definition (adjust naming via constructor):
 *  - PostgreSQL:
 *      CREATE TABLE IF NOT EXISTS schema_migrations (
 *          version    TEXT PRIMARY KEY,
 *          applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
 *      );
 *  - MySQL:
 *      CREATE TABLE IF NOT EXISTS schema_migrations (
 *          version    VARCHAR(190) PRIMARY KEY,
 *          applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
 *      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
 */
final class MigrationRunner
{
    public function __construct(
        private readonly Database $db,
        private readonly ?LoggerInterface $logger = null,
        private readonly string $table = 'schema_migrations'
    ) {}

    public function ensureTable(): void
    {
        $table = $this->db->quoteIdent($this->table);

        if ($this->db->isPg()) {
            $sql = "CREATE TABLE IF NOT EXISTS {$table} (
                version TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )";
        } elseif ($this->db->isMysql()) {
            $sql = "CREATE TABLE IF NOT EXISTS {$table} (
                version VARCHAR(190) PRIMARY KEY,
                applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
        } else {
            $sql = "CREATE TABLE IF NOT EXISTS {$table} (
                version TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )";
        }

        $this->db->execute($sql);
    }

    /**
     * @return list<string>
     */
    public function applied(): array
    {
        $this->ensureTable();
        $sql = \sprintf('SELECT version, applied_at FROM %s ORDER BY version', $this->db->quoteIdent($this->table));
        return \array_keys($this->db->fetchPairs($sql));
    }

    /**
     * Apply migrations sequentially.
     *
     * @param list<array{id:string,run:callable}> $migrations
     * @return list<string> Versions applied in this invocation.
     */
    public function apply(array $migrations, int $statementTimeoutMs = 10_000, int $retries = 0): array
    {
        $this->ensureTable();
        $finished = $this->applied();
        $applied  = [];

        foreach ($migrations as $migration) {
            $id  = (string)($migration['id'] ?? '');
            $run = $migration['run'] ?? null;

            if ($id === '' || !\is_callable($run)) {
                throw new \InvalidArgumentException('Migration must have id and callable run()');
            }
            if (\in_array($id, $finished, true)) {
                continue;
            }

            $this->logger?->info('migration-start', ['id' => $id]);
            $attempt = 0;

            while (true) {
                try {
                    $this->db->txWithMeta(
                        function (Database $db) use ($run, $statementTimeoutMs): void {
                            $db->withStatementTimeout(
                                $statementTimeoutMs,
                                static function () use ($db, $run): void {
                                    $run($db);
                                }
                            );
                        },
                        ['component' => 'migration', 'id' => $id]
                    );

                    $this->db->execute(
                        \sprintf('INSERT INTO %s (version) VALUES (:v)', $this->db->quoteIdent($this->table)),
                        [':v' => $id]
                    );

                    $applied[] = $id;
                    $this->logger?->info('migration-commit', ['id' => $id]);
                    break;
                } catch (\Throwable $e) {
                    if ($attempt++ < $retries) {
                        $this->logger?->warning('migration-retry', ['id' => $id, 'attempt' => $attempt, 'error' => $e->getMessage()]);
                        continue;
                    }

                    $this->logger?->error('migration-failed', ['id' => $id, 'error' => $e->getMessage()]);
                    throw $e;
                }
            }
        }

        return $applied;
    }
}
