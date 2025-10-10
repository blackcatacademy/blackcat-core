<?php

declare(strict_types=1);

namespace BlackCat\Core\Security;

use BlackCat\Core\Database;
use BlackCat\Core\Log\Logger;
use BlackCat\Core\Helpers\DeferredHelper;

final class LoginLimiter
{
    private const DEFAULT_MAX_ATTEMPTS = 5;
    private const DEFAULT_WINDOW_SEC   = 300; // 5 minut

    private function __construct() {}

    /**
     * Prepare 32-byte binary or 64-char hex for storage (same semantics as Logger).
     */
    private static function prepareBin32ForStorage(?string $val): ?string
    {
        if ($val === null) return null;
        if (is_string($val) && strlen($val) === 32) return $val;
        if (is_string($val) && ctype_xdigit($val) && strlen($val) === 64) {
            $bin = @hex2bin($val);
            return $bin === false ? null : $bin;
        }
        return null;
    }

    /**
     * Zaregistruje login pokus.
     *
     * @param string|null $ip Plain IP or null (Logger::getClientIp used if null)
     * @param bool $success  true = successful login, false = failure
     * @param int|null $userId optional user id
     * @param string|null $usernameHash optional binary-32 or 64-hex of username/email (HMAC, never plaintext)
     */
    public static function registerAttempt(?string $ip = null, bool $success = false, ?int $userId = null, ?string $usernameHash = null): void
    {
        $ipResult = Logger::getHashedIp($ip);
        $ipHashBin = self::prepareBin32ForStorage($ipResult['hash']);

        // if table requires NOT NULL ip_hash and we don't have a valid hash, skip writing
        if ($ipHashBin === null) {
            return;
        }

        $usernameHashBin = self::prepareBin32ForStorage($usernameHash);

        $sql = "INSERT INTO login_attempts (ip_hash, attempted_at, success, user_id, username_hash)
                VALUES (:ip_hash, UTC_TIMESTAMP(6), :success, :user_id, :username_hash)";

        $params = [
            ':ip_hash'       => $ipHashBin,
            ':success'       => $success ? 1 : 0,
            ':user_id'       => $userId,
            ':username_hash' => $usernameHashBin,
        ];

        if (Database::isInitialized()) {
            DeferredHelper::flush();
            try {
                Database::getInstance()->execute($sql, $params);
            } catch (\Throwable $_) {
                // silent fail — limiter nesmí shodit aplikaci
            }
            return;
        }

        DeferredHelper::enqueue(function() use ($sql, $params) {
            try {
                Database::getInstance()->execute($sql, $params);
            } catch (\Throwable $_) {
                // silent fail
            }
        });
    }

    /**
     * Vrací true, pokud má IP příliš mnoho neúspěšných pokusů ve window (count >= maxAttempts).
     *
     * @param string|null $ip Plain IP or null
     */
    public static function isBlocked(?string $ip = null, int $maxAttempts = self::DEFAULT_MAX_ATTEMPTS, int $windowSec = self::DEFAULT_WINDOW_SEC): bool
    {
        if (!Database::isInitialized()) {
            return false; // bez DB neblokujeme
        }

        $ipResult = Logger::getHashedIp($ip);
        $ipHashBin = self::prepareBin32ForStorage($ipResult['hash']);
        if ($ipHashBin === null) {
            return false;
        }

        $cutoff = gmdate('Y-m-d H:i:s', time() - $windowSec);

        $sql = "SELECT COUNT(*) AS cnt
                FROM login_attempts
                WHERE ip_hash = :ip_hash
                  AND attempted_at >= :cutoff
                  AND success = 0";

        $params = [
            ':ip_hash' => $ipHashBin,
            ':cutoff'  => $cutoff,
        ];

        try {
            $row = Database::getInstance()->fetch($sql, $params);
            $cnt = $row && isset($row['cnt']) ? (int)$row['cnt'] : 0;
            return $cnt >= $maxAttempts;
        } catch (\Throwable $_) {
            // fail-open: při chybě neblokujeme
            return false;
        }
    }

    /**
     * Vrací počet neúspěšných pokusů v daném window (pro IP).
     */
    public static function getAttemptsCount(?string $ip = null, int $windowSec = self::DEFAULT_WINDOW_SEC): int
    {
        if (!Database::isInitialized()) return 0;
        $ipHashBin = self::prepareBin32ForStorage(Logger::getHashedIp($ip)['hash']);
        if ($ipHashBin === null) return 0;

        $cutoff = gmdate('Y-m-d H:i:s', time() - $windowSec);
        $sql = "SELECT COUNT(*) AS cnt
                FROM login_attempts
                WHERE ip_hash = :ip_hash
                  AND attempted_at >= :cutoff
                  AND success = 0";
        try {
            $row = Database::getInstance()->fetch($sql, [':ip_hash' => $ipHashBin, ':cutoff' => $cutoff]);
            return $row && isset($row['cnt']) ? (int)$row['cnt'] : 0;
        } catch (\Throwable $_) {
            return 0;
        }
    }

    /**
     * Vrací, kolik pokusů ještě zbývá (>=0).
     */
    public static function getRemainingAttempts(?string $ip = null, int $maxAttempts = self::DEFAULT_MAX_ATTEMPTS, int $windowSec = self::DEFAULT_WINDOW_SEC): int
    {
        $count = self::getAttemptsCount($ip, $windowSec);
        $remaining = $maxAttempts - $count;
        return $remaining > 0 ? $remaining : 0;
    }

    /**
     * Vrací počet sekund do odblokování (0 = není blokováno).
     * Pokud je IP blokována (count >= maxAttempts), vypočítá, kolik sekund zbývá do vypršení nejstaršího ze
     * posledních $maxAttempts neúspěšných pokusů.
     */
    public static function getSecondsUntilUnblock(?string $ip = null, int $maxAttempts = self::DEFAULT_MAX_ATTEMPTS, int $windowSec = self::DEFAULT_WINDOW_SEC): int
    {
        if (!Database::isInitialized()) return 0;
        $ipHashBin = self::prepareBin32ForStorage(Logger::getHashedIp($ip)['hash']);
        if ($ipHashBin === null) return 0;

        $cutoff = gmdate('Y-m-d H:i:s', time() - $windowSec);

        // LIMIT cannot be bound reliably with ATTR_EMULATE_PREPARES = false, so inline integer safely
        $limit = (int)$maxAttempts;
        $sql = "SELECT attempted_at
                FROM login_attempts
                WHERE ip_hash = :ip_hash
                  AND attempted_at >= :cutoff
                  AND success = 0
                ORDER BY attempted_at DESC
                LIMIT $limit";

        try {
            $rows = Database::getInstance()->fetchAll($sql, [':ip_hash' => $ipHashBin, ':cutoff' => $cutoff]);
            $count = is_array($rows) ? count($rows) : 0;
            if ($count < $maxAttempts) {
                return 0; // není blokováno
            }

            // nejstarší z posledních N pokusů je poslední prvek v result setu (ORDER BY attempted_at DESC)
            $oldest = $rows[$count - 1]['attempted_at'] ?? null;
            if (!$oldest) return 0;

            $oldestTs = strtotime($oldest . ' UTC');
            if ($oldestTs === false) return 0;

            $elapsed = time() - $oldestTs;
            $remaining = $windowSec - $elapsed;
            return $remaining > 0 ? $remaining : 0;
        } catch (\Throwable $_) {
            return 0;
        }
    }

    /**
     * Zaregistruje registrační pokus do tabulky register_events.
     *
     * Poznámka: IP se bere přímo z Logger::getHashedIp() (tj. ze skutečného klienta).
     *
     * @param bool $success true = success, false = failure
     * @param int|null $userId optional user id (if known)
     * @param string|null $userAgent optional user agent string
     * @param array|null $meta optional associative meta (will be merged and stored as JSON if provided)
     * @param string|null $error optional error message to include in meta
     */
    public static function registerRegisterAttempt(bool $success = false, ?int $userId = null, ?string $userAgent = null, ?array $meta = null, ?string $error = null): void
    {
        if (!Database::isInitialized()) {
            return;
        }

        // ZÍSKAT IP INFO PŘÍMO Z LOGGERU (nepoužíváme předaný $ip)
        $ipResult = Logger::getHashedIp(); // getClientIp() inside Logger použije skutečnou klientskou IP
        $ipHashBin    = self::prepareBin32ForStorage($ipResult['hash'] ?? null);
        $ipHashKeyVer = $ipResult['key_id'] ?? null;
        $ipUsed       = $ipResult['used'] ?? 'none';

        // pokud není k dispozici hash (např. KeyManager chybí), přerušujeme (tabulka může mít NOT NULL)
        if ($ipHashBin === null) {
            return;
        }

        $type = $success ? 'register_success' : 'register_failure';
        $ua   = $userAgent ?? ($_SERVER['HTTP_USER_AGENT'] ?? null);

        // základní meta obsahující informace o IP-hash
        $baseMeta = [
            '_ip_hash_used' => $ipUsed,
            '_ip_hash_key'  => $ipHashKeyVer,
        ];

        // bezpečné sloučení volitelného $meta (povolit jen scalar, null nebo array)
        if (!empty($meta) && is_array($meta)) {
            $filtered = [];
            foreach ($meta as $k => $v) {
                if (!is_string($k)) continue;
                if (is_scalar($v) || is_null($v) || is_array($v)) {
                    $filtered[$k] = $v;
                } else {
                    $filtered[$k] = (string)$v;
                }
            }
            $baseMeta = array_merge($baseMeta, $filtered);
        }

        // přidat volitelnou chybovou hlášku
        if (!empty($error) || $error === '0') {
            $baseMeta['error'] = (string)$error;
        }

        // encode meta (pokud selže -> NULL)
        $metaJson = null;
        try {
            $metaJson = json_encode($baseMeta, JSON_UNESCAPED_UNICODE);
            if ($metaJson === false) $metaJson = null;
        } catch (\Throwable $_) {
            $metaJson = null;
        }

        $sql = "INSERT INTO register_events (user_id, type, ip_hash, ip_hash_key, user_agent, occurred_at, meta)
                VALUES (:user_id, :type, :ip_hash, :ip_hash_key, :user_agent, UTC_TIMESTAMP(6), :meta)";

        $params = [
            ':user_id'     => $userId,
            ':type'        => $type,
            ':ip_hash'     => $ipHashBin,
            ':ip_hash_key' => $ipHashKeyVer,
            ':user_agent'  => $ua,
            ':meta'        => $metaJson,
        ];

        try {
            DeferredHelper::flush();
            Database::getInstance()->execute($sql, $params);
        } catch (\Throwable $_) {
            // silent fail (limiter nesmí shodit aplikaci)
        }
    }

    /**
     * Vrací true pokud je IP blokována z hlediska registrací (count >= maxAttempts v daném window).
     * Stejná semantika jako isBlocked() - ale čte z register_events a pouze typ 'register_failure'.
     *
     * @param string|null $ip Plain IP or null
     */
    public static function isRegisterBlocked(?string $ip = null, int $maxAttempts = self::DEFAULT_MAX_ATTEMPTS, int $windowSec = self::DEFAULT_WINDOW_SEC): bool
    {
        if (!Database::isInitialized()) {
            return false;
        }

        $ipResult = Logger::getHashedIp($ip);
        $ipHashBin = self::prepareBin32ForStorage($ipResult['hash']);
        if ($ipHashBin === null) {
            return false;
        }

        $cutoff = gmdate('Y-m-d H:i:s', time() - $windowSec);

        $sql = "SELECT COUNT(*) AS cnt
                FROM register_events
                WHERE ip_hash = :ip_hash
                  AND occurred_at >= :cutoff
                  AND type = 'register_failure'";

        try {
            $row = Database::getInstance()->fetch($sql, [':ip_hash' => $ipHashBin, ':cutoff' => $cutoff]);
            $cnt = $row && isset($row['cnt']) ? (int)$row['cnt'] : 0;
            return $cnt >= $maxAttempts;
        } catch (\Throwable $_) {
            return false;
        }
    }

    /**
     * Vrací počet neúspěšných registračních pokusů v daném window (pro IP).
     */
    public static function getRegisterAttemptsCount(?string $ip = null, int $windowSec = self::DEFAULT_WINDOW_SEC): int
    {
        if (!Database::isInitialized()) return 0;
        $ipHashBin = self::prepareBin32ForStorage(Logger::getHashedIp($ip)['hash']);
        if ($ipHashBin === null) return 0;

        $cutoff = gmdate('Y-m-d H:i:s', time() - $windowSec);
        $sql = "SELECT COUNT(*) AS cnt
                FROM register_events
                WHERE ip_hash = :ip_hash
                  AND occurred_at >= :cutoff
                  AND type = 'register_failure'";
        try {
            $row = Database::getInstance()->fetch($sql, [':ip_hash' => $ipHashBin, ':cutoff' => $cutoff]);
            return $row && isset($row['cnt']) ? (int)$row['cnt'] : 0;
        } catch (\Throwable $_) {
            return 0;
        }
    }

    /**
     * Vrací zbývající počet pokusů pro registraci (>=0).
     */
    public static function getRegisterRemainingAttempts(?string $ip = null, int $maxAttempts = self::DEFAULT_MAX_ATTEMPTS, int $windowSec = self::DEFAULT_WINDOW_SEC): int
    {
        $count = self::getRegisterAttemptsCount($ip, $windowSec);
        $remaining = $maxAttempts - $count;
        return $remaining > 0 ? $remaining : 0;
    }

    /**
     * Vrací počet sekund do odblokování (0 = není blokováno) pro registrace.
     */
    public static function getRegisterSecondsUntilUnblock(?string $ip = null, int $maxAttempts = self::DEFAULT_MAX_ATTEMPTS, int $windowSec = self::DEFAULT_WINDOW_SEC): int
    {
        if (!Database::isInitialized()) return 0;
        $ipHashBin = self::prepareBin32ForStorage(Logger::getHashedIp($ip)['hash']);
        if ($ipHashBin === null) return 0;

        $cutoff = gmdate('Y-m-d H:i:s', time() - $windowSec);

        $limit = (int)$maxAttempts;
        $sql = "SELECT occurred_at
                FROM register_events
                WHERE ip_hash = :ip_hash
                  AND occurred_at >= :cutoff
                  AND type = 'register_failure'
                ORDER BY occurred_at DESC
                LIMIT $limit";

        try {
            $rows = Database::getInstance()->fetchAll($sql, [':ip_hash' => $ipHashBin, ':cutoff' => $cutoff]);
            $count = is_array($rows) ? count($rows) : 0;
            if ($count < $maxAttempts) return 0;

            $oldest = $rows[$count - 1]['occurred_at'] ?? null;
            if (!$oldest) return 0;

            $oldestTs = strtotime($oldest . ' UTC');
            if ($oldestTs === false) return 0;

            $elapsed = time() - $oldestTs;
            $remaining = $windowSec - $elapsed;
            return $remaining > 0 ? $remaining : 0;
        } catch (\Throwable $_) {
            return 0;
        }
    }

    /**
     * Úklid starých pokusů – doporučeno volat z CRONu.
     *
     * @param int $olderThanSec smazat záznamy starší než tento počet sekund
     */
    public static function cleanup(int $olderThanSec = 86400): void
    {
        if (!Database::isInitialized()) {
            return;
        }

        $cutoff = gmdate('Y-m-d H:i:s', time() - $olderThanSec);

        $sql = "DELETE FROM login_attempts WHERE attempted_at < :cutoff";
        $params = [':cutoff' => $cutoff];

        try {
            Database::getInstance()->execute($sql, $params);
        } catch (\Throwable $_) {
            // ignore
        }
    }
}