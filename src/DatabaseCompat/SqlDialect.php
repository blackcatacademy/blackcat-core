<?php
declare(strict_types=1);

namespace BlackCat\Database;

/**
 * SQL dialect utilities shared across the BlackCat ecosystem.
 *
 * NOTE: This lives in `blackcat-core` so kernel-only deployments can still use
 * `BlackCat\\Core\\Database` without requiring the full `blackcat-database` module.
 */
enum SqlDialect: string
{
    case mysql    = 'mysql';
    case postgres = 'postgres';

    public function isMysql(): bool { return $this === self::mysql; }
    public function isPg(): bool    { return $this === self::postgres; }

    /**
     * Helper for positional parameter placeholders.
     * - MySQL/MariaDB should always use '?'
     * - PostgreSQL expects $1, $2, ...
     *
     * Note: Callers must start indexing at 1 for PostgreSQL.
     */
    public function placeholder(int $index): string
    {
        if ($this->isPg()) {
            $i = max(1, $index);
            return '$' . $i;
        }
        return '?';
    }

    // --- flags & normalization ---

    /** Normalizes a dialect name to {mysql|postgres}; 'mariadb' is treated as 'mysql'. */
    public static function normalize(string $name): string
    {
        $n = strtolower($name);
        return $n === 'mariadb' ? 'mysql' : $n;
    }

    /**
     * Conservative default: only PostgreSQL is assumed to support RETURNING.
     * For more granular behavior use the statement-specific helpers below.
     */
    public static function supportsReturning(string $dialect): bool
    {
        return self::normalize($dialect) === 'postgres';
    }

    /**
     * Version-aware detection for RETURNING support in general.
     * Returns true only when the server supports any DML with RETURNING.
     * Prefer the INSERT/UPDATE/DELETE-specific helpers for precise checks.
     *
     * - postgres: always true
     * - mysql:    true from 8.0.21+ (UPDATE/DELETE ... RETURNING; INSERT is not supported)
     * - mariadb:  true from 10.5+ (INSERT/UPDATE/DELETE RETURNING)
     */
    public static function supportsReturningVersioned(string $dialect, ?string $serverVersion): bool
    {
        $d = self::normalize($dialect);
        if ($d === 'postgres') return true;
        if ($d !== 'mysql' || $serverVersion === null) return false;

        if (self::looksLikeMariaDb($serverVersion)) {
            return version_compare(self::extractMariaVersion($serverVersion), '10.5.0', '>=');
        }
        return version_compare(self::extractMysqlVersion($serverVersion), '8.0.21', '>=');
    }

    /**
     * Fine-grained helpers for individual DML statements.
     */

    /** INSERT ... RETURNING */
    public static function supportsInsertReturningVersioned(string $dialect, ?string $serverVersion): bool
    {
        $d = self::normalize($dialect);
        if ($d === 'postgres') return true;
        if ($d !== 'mysql' || $serverVersion === null) return false;

        if (self::looksLikeMariaDb($serverVersion)) {
            // MariaDB 10.5+ supports INSERT ... RETURNING
            return version_compare(self::extractMariaVersion($serverVersion), '10.5.0', '>=');
        }
        // MySQL: intentionally false – INSERT ... RETURNING is not supported
        return false;
    }

    /** UPDATE ... RETURNING */
    public static function supportsUpdateReturningVersioned(string $dialect, ?string $serverVersion): bool
    {
        $d = self::normalize($dialect);
        if ($d === 'postgres') return true;
        if ($d !== 'mysql' || $serverVersion === null) return false;

        if (self::looksLikeMariaDb($serverVersion)) {
            return version_compare(self::extractMariaVersion($serverVersion), '10.5.0', '>=');
        }
        // MySQL 8.0.21+ (UPDATE ... RETURNING)
        return version_compare(self::extractMysqlVersion($serverVersion), '8.0.21', '>=');
    }

    /** DELETE ... RETURNING */
    public static function supportsDeleteReturningVersioned(string $dialect, ?string $serverVersion): bool
    {
        $d = self::normalize($dialect);
        if ($d === 'postgres') return true;
        if ($d !== 'mysql' || $serverVersion === null) return false;

        if (self::looksLikeMariaDb($serverVersion)) {
            return version_compare(self::extractMariaVersion($serverVersion), '10.5.0', '>=');
        }
        // MySQL 8.0.21+ (DELETE ... RETURNING)
        return version_compare(self::extractMysqlVersion($serverVersion), '8.0.21', '>=');
    }

    /**
     * SKIP LOCKED support flag (Postgres, MySQL 8+, MariaDB 10.3+).
     * MariaDB is mapped to the mysql branch.
     */
    public static function supportsSkipLocked(string $dialect): bool
    {
        return in_array(self::normalize($dialect), ['postgres','mysql'], true);
    }

    /** Version-aware SKIP LOCKED detection. */
    public static function supportsSkipLockedVersioned(string $dialect, ?string $serverVersion): bool
    {
        $d = self::normalize($dialect);
        if ($d === 'postgres') return true;
        if ($d !== 'mysql' || $serverVersion === null) return false;

        if (self::looksLikeMariaDb($serverVersion)) {
            return version_compare(self::extractMariaVersion($serverVersion), '10.3.0', '>=');
        }
        return version_compare(self::extractMysqlVersion($serverVersion), '8.0.0', '>=');
    }

    /** Conservative default: only PostgreSQL has NOWAIT semantics. */
    public static function supportsNoWait(string $dialect): bool
    {
        return self::normalize($dialect) === 'postgres';
    }

    /** Version-aware NOWAIT detection. */
    public static function supportsNoWaitVersioned(string $dialect, ?string $serverVersion): bool
    {
        $d = self::normalize($dialect);
        if ($d === 'postgres') return true;
        if ($d !== 'mysql' || $serverVersion === null) return false;

        if (self::looksLikeMariaDb($serverVersion)) {
            return version_compare(self::extractMariaVersion($serverVersion), '10.3.0', '>=');
        }
        return version_compare(self::extractMysqlVersion($serverVersion), '8.0.0', '>=');
    }

    public static function hasILike(string $dialect): bool
    {
        return self::normalize($dialect) === 'postgres';
    }

    /** "Native JSON" includes both the data type and full JSON function set. */
    public static function hasNativeJson(string $dialect): bool
    {
        return in_array(self::normalize($dialect), ['postgres','mysql'], true);
    }

    public static function supportsPartialUnique(string $dialect): bool
    {
        return self::normalize($dialect) === 'postgres';
    }

    public static function supportsTransactionalDdl(string $dialect): bool
    {
        return self::normalize($dialect) === 'postgres';
    }

    /** Statement timeouts (PG: statement_timeout; MySQL: max_execution_time; MariaDB: max_statement_time). */
    public static function hasStatementTimeout(string $dialect): bool
    {
        return in_array(self::normalize($dialect), ['postgres','mysql'], true);
    }

    // --- Additional helper methods (optional) -------------------------------------------------

    /** DISTINCT ON is native to PostgreSQL only. */
    public static function supportsDistinctOn(string $dialect): bool
    {
        return self::normalize($dialect) === 'postgres';
    }

    /** Window functions: PostgreSQL always, MySQL 8+/MariaDB 10.2+ with version checks. */
    public static function supportsWindowFunctionsVersioned(string $dialect, ?string $serverVersion): bool
    {
        $d = self::normalize($dialect);
        if ($d === 'postgres') return true;
        if ($d !== 'mysql' || $serverVersion === null) return false;

        if (self::looksLikeMariaDb($serverVersion)) {
            return version_compare(self::extractMariaVersion($serverVersion), '10.2.0', '>=');
        }
        return version_compare(self::extractMysqlVersion($serverVersion), '8.0.0', '>=');
    }

    /** UPSERT support flag (syntax differs per platform). */
    public static function supportsUpsert(string $dialect): bool
    {
        $d = self::normalize($dialect);
        return in_array($d, ['postgres','mysql'], true);
    }

    /** Version-aware JSON_PATH/JSON_TABLE support. */
    public static function supportsJsonPathVersioned(string $dialect, ?string $serverVersion): bool
    {
        $d = self::normalize($dialect);
        if ($d === 'postgres') {
            if ($serverVersion === null) return false;
            return version_compare(self::extractPgVersion($serverVersion), '12.0', '>=');
        }
        if ($d !== 'mysql' || $serverVersion === null) return false;

        if (self::looksLikeMariaDb($serverVersion)) {
            // MariaDB: JSON_TABLE since 10.5+
            return version_compare(self::extractMariaVersion($serverVersion), '10.5.0', '>=');
        }
        // MySQL: JSON_TABLE since 8.0.4+
        return version_compare(self::extractMysqlVersion($serverVersion), '8.0.4', '>=');
    }

    /** From "16.3 (Debian 16.3-1.pgdg120+1)" or "12.11" => "16.3"/"12.11". */
    private static function extractPgVersion(string $serverVersion): string
    {
        if (preg_match('~(\\d+\\.\\d+)~', $serverVersion, $m)) return $m[1];
        return $serverVersion;
    }

    // --- Internal utilities -------------------------------------------------------------------

    /** Detects MariaDB by inspecting the version string returned by PDO. */
    private static function looksLikeMariaDb(string $serverVersion): bool
    {
        return stripos($serverVersion, 'mariadb') !== false;
    }

    /** Extracts a MariaDB version, e.g. "10.4.32-MariaDB-1~xxx" => "10.4.32". */
    private static function extractMariaVersion(string $serverVersion): string
    {
        if (preg_match('~(\\d+\\.\\d+\\.\\d+)~', $serverVersion, $m)) return $m[1];
        if (preg_match('~(\\d+\\.\\d+)~', $serverVersion, $m)) return $m[1] . '.0';
        return $serverVersion;
    }

    /** Extracts a MySQL version, e.g. "8.0.36" or "8.0.36-cl" => "8.0.36". */
    private static function extractMysqlVersion(string $serverVersion): string
    {
        if (preg_match('~(\\d+\\.\\d+\\.\\d+)~', $serverVersion, $m)) return $m[1];
        if (preg_match('~(\\d+\\.\\d+)~', $serverVersion, $m)) return $m[1] . '.0';
        return $serverVersion;
    }
}

