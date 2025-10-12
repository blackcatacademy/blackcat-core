<?php

declare(strict_types=1);

namespace BlackCat\Core;

use BlackCat\Core\Log\Logger;
use BlackCat\Core\Cache\FileCache;
use BlackCat\Core\Security\CSRF;

/**
 * TrustedShared - improved
 *
 * - fixes logger detection bug
 * - masks common sensitive user fields by default
 * - more robust categories fetching (cachedFetchAll, fallback to fetchAll, optional APCu)
 * - safer purchased-books enrichment (supports fetchAll/fetchColumn results)
 * - non-throwing: always returns array (best-effort)
 */
final class TrustedShared
{
    private function __construct() {}

    /**
     * Create the trusted shared array.
     *
     * Known opts:
     *   - database
     *   - user
     *   - userId
     *   - gopayAdapter
     *   - enrichUser (bool)         // enrich user with purchased_books
     *   - maskUserSensitive (bool)  // default true - remove password/token fields
     *   - categories_ttl (int|null) // seconds for APCu fallback cache (null = no apcu caching)
     *
     * @param array $opts
     * @return array
     */
    public static function create(array $opts = []): array
    {
        // opts (extended)
        $db = $opts['database'] ?? null;
        $user = $opts['user'] ?? null;
        $userId = $opts['userId'] ?? null;
        $gopayAdapter = $opts['gopayAdapter'] ?? ($opts['gopay'] ?? null);
        $enrichUser = $opts['enrichUser'] ?? false;

        // --- ensure PSR-16 cache: prefer opts['cache'], otherwise try to auto-create FileCache (no encryption) ---
        $cache = $opts['cache'] ?? null;
        $cacheDir = $opts['cache_dir'] ?? null;
        $categoriesTtl = array_key_exists('categories_ttl', $opts) ? $opts['categories_ttl'] : 300; // default 5 min
        // mask sensitive fields in user array before returning to templates (default true)
        $maskUserSensitive = $opts['maskUserSensitive'] ?? true;

        if ($cache === null && class_exists(FileCache::class, true)) {
            try {
                // create FileCache with provided cacheDir (no encryption)
                $cache = new FileCache($cacheDir ?? null, false, null);
            } catch (\Throwable $e) {
                self::logWarn('TrustedShared: FileCache init failed', ['exception' => (string)$e]);
                $cache = null;
            }
        }

        // try to obtain Database singleton if not provided
        if ($db === null) {
            try {
                if (class_exists(Database::class, true)) {
                    $db = Database::getInstance();
                }
            } catch (\Throwable $e) {
                self::logWarn('TrustedShared: Database not available', ['exception' => (string)$e]);
                $db = null;
            }
        }

        // CSRF token helper (check method exists)
        $csrfToken = null;
        try {
            if (class_exists(CSRF::class, true) && method_exists(CSRF::class, 'token')) {
                $csrfToken = CSRF::token();
            }
        } catch (\Throwable $e) {
            self::logWarn('TrustedShared: failed to get CSRF token', ['exception' => (string)$e]);
            $csrfToken = null;
        }

        // categories (best-effort, prefer PSR-16 cache, fallback to DB)
        $categories = [];

        if ($db !== null) {
            $cacheKey = 'trustedshared_categories_v1';

            // 1) Try PSR-16 cache if available
            if ($cache !== null && $categoriesTtl !== null) {
                try {
                    $cached = $cache->get($cacheKey, null);
                    if ($cached !== null) {
                        $categories = is_array($cached) ? $cached : [];
                    }
                } catch (\Throwable $e) {
                    self::logWarn('TrustedShared: cache get failed for categories', ['exception' => (string)$e]);
                }
            }

            // 2) If miss -> fetch from DB (single place)
            if ($categories === []) {
                $rows = self::fetchCategoryRows($db);
                if (is_array($rows)) $categories = $rows;

                // 3) store to PSR-16 cache (if present) — store even empty arrays to avoid repeated DB hits
                if ($cache !== null && $categoriesTtl !== null && is_array($categories)) {
                    try {
                        $cache->set($cacheKey, $categories, (int)$categoriesTtl);
                    } catch (\Throwable $e) {
                        self::logWarn('TrustedShared: cache set failed for categories', ['exception' => (string)$e]);
                    }
                }
            }
        }

        // try to enrich $user (purchased books) if requested
        if ($enrichUser && $db !== null && $userId !== null) {
            try {
                // attempt to fetch user if not provided
                if ($user === null && method_exists($db, 'fetch')) {
                    $user = $db->fetch('SELECT * FROM pouzivatelia WHERE id = :id LIMIT 1', ['id' => $userId]);
                }

                if ($user !== null && isset($user['id'])) {
                    // purchased books as integer IDs (best-effort; support multiple DB helper signatures)
                    $pbookIds = [];
                    if (method_exists($db, 'fetchAll')) {
                        $rows = $db->fetchAll(
                            'SELECT DISTINCT oi.book_id FROM orders o INNER JOIN order_items oi ON oi.order_id = o.id WHERE o.user_id = :uid AND o.status = :paid_status',
                            ['uid' => $userId, 'paid_status' => 'paid']
                        );
                        // rows might be array of arrays [['book_id'=>1], ...] or flat ints
                        if (is_array($rows)) {
                            foreach ($rows as $r) {
                                if (is_array($r)) {
                                    $val = $r['book_id'] ?? reset($r);
                                } else {
                                    $val = $r;
                                }
                                $pbookIds[] = (int)$val;
                            }
                        }
                    } elseif (method_exists($db, 'fetchColumn')) {
                        $col = $db->fetchColumn(
                            'SELECT DISTINCT oi.book_id FROM orders o INNER JOIN order_items oi ON oi.order_id = o.id WHERE o.user_id = :uid AND o.status = :paid_status',
                            ['uid' => $userId, 'paid_status' => 'paid']
                        );
                        if (is_array($col)) {
                            $pbookIds = array_map('intval', $col);
                        } elseif ($col !== null) {
                            $pbookIds[] = (int)$col;
                        }
                    }

                    $user['purchased_books'] = array_values(array_unique($pbookIds));
                }
            } catch (\Throwable $e) {
                self::logWarn('TrustedShared: failed to enrich user', ['exception' => (string)$e]);
            }
        }

        // mask sensitive user fields (best-effort)
        if ($maskUserSensitive && is_array($user)) {
            $user = self::sanitizeUser($user);
        }

        // current server timestamp (UTC)
        $nowUtc = gmdate('Y-m-d H:i:s');

        $trustedShared = [
            'user'         => $user,
            'csrfToken'    => $csrfToken,
            'csrf'         => $csrfToken,
            'categories'   => $categories,
            'db'           => $db,
            'gopayAdapter' => $gopayAdapter,
            'now_utc'      => $nowUtc,
        ];

        return $trustedShared;
    }

    /**
     * Select a subset of $trustedShared according to $shareSpec.
     * $shareSpec: true -> return all keys
     *             false -> return []
     *             array -> return only listed keys (if exist)
     *
     * @param array $trustedShared
     * @param bool|array $shareSpec
     * @return array
     */
    public static function select(array $trustedShared, bool|array $shareSpec): array
    {
        if ($shareSpec === true) return $trustedShared;
        if ($shareSpec === false) return [];

        $out = [];
        foreach ($shareSpec as $k) {
            if (array_key_exists($k, $trustedShared)) $out[$k] = $trustedShared[$k];
        }
        return $out;
    }

    /**
     * Merge handler vars with shared vars for template, protecting shared values.
     * Handler vars first, shared last (shared wins).
     *
     * @param array $handlerVars
     * @param array $sharedForTemplate
     * @return array
     */
    public static function composeTemplateVars(array $handlerVars, array $sharedForTemplate): array
    {
        return array_merge($handlerVars, $sharedForTemplate);
    }

    /**
     * Sanitize user array by removing common sensitive fields.
     * Does not try to be exhaustive, but removes common passwords/tokens.
     *
     * @param array $user
     * @return array
     */
    private static function sanitizeUser(array $user): array
    {
        $sensitive = ['password', 'password_hash', 'pwd', 'token', 'remember_token', 'ssn', 'secret'];
        foreach ($sensitive as $k) {
            if (array_key_exists($k, $user)) unset($user[$k]);
        }
        // also mask email if required? keep full email by default but you can change here
        return $user;
    }

    /**
     * Fetch categories:
     * - prefer DB->cachedFetchAll()
     * - fallback to DB->fetchAll()
     * - fallback to DB->query->fetchAll()
     *
     * @param mixed $db
     * @return array
     */
    private static function fetchCategoryRows($db): array
    {
        try {
            if (method_exists($db, 'cachedFetchAll')) {
                return (array) $db->cachedFetchAll('SELECT * FROM categories ORDER BY nazov ASC');
            }
            if (method_exists($db, 'fetchAll')) {
                return (array) $db->fetchAll('SELECT * FROM categories ORDER BY nazov ASC');
            }
            if (method_exists($db, 'query')) {
                $stmt = $db->query('SELECT * FROM categories ORDER BY nazov ASC');
                return ($stmt !== false && method_exists($stmt, 'fetchAll')) ? (array)$stmt->fetchAll() : [];
            }
        } catch (\Throwable $e) {
            self::logWarn('TrustedShared: fetchCategoryRows DB error', ['exception' => (string)$e]);
        }
        return [];
    }

    /**
     * Safe logger helper (silent if Logger isn't available).
     *
     * @param string $msg
     * @param array|null $ctx
     * @return void
     */
    private static function logWarn(string $msg, ?array $ctx = null): void
    {
        try {
            if (class_exists(Logger::class, true)) {
                // prefer structured systemMessage/systemError if available
                if (method_exists(Logger::class, 'systemMessage')) {
                    try {
                        Logger::systemMessage('warning', $msg, null, $ctx ?? ['component' => 'TrustedShared']);
                        return;
                    } catch (\Throwable $_) {
                        // swallow and try other
                    }
                }
                if (method_exists(Logger::class, 'warn')) {
                    try {
                        Logger::warn($msg, null, $ctx);
                        return;
                    } catch (\Throwable $_) {
                        // swallow
                    }
                }
            }
            // last resort
            error_log('[TrustedShared][warning] ' . $msg . ($ctx ? ' | ' . json_encode($ctx) : ''));
        } catch (\Throwable $_) {
            // deliberately silent
        }
    }
}