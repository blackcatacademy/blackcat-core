<?php
declare(strict_types=1);

/**
 * TrustedShared
 *
 * Central helper to build and manage the per-request "trusted shared" array
 * used by index.php to pass safe variables into handlers and templates.
 *
 * Goals:
 *  - build the canonical array (categories, db, user, csrfToken, adapters, ...)
 *  - provide helper to select which keys are exposed to includes / templates
 *  - keep failures silent (log when Logger exists) and avoid throwing
 *
 * Usage (example from index.php):
 *   require_once __DIR__ . '/libs/TrustedShared.php';
 *   $trustedShared = TrustedShared::create([
 *       'database'     => $database,        // optional — will try Database::getInstance()
 *       'user'         => $user,            // optional
 *       'userId'       => $currentUserId,   // optional
 *       'gopayAdapter' => $gopayAdapter,    // optional
 *       'enrichUser'   => true,             // optional: fetch purchased books etc
 *   ]);
 *
 *   // select subset for include/template
 *   $sharedForInclude   = TrustedShared::select($trustedShared, $shareSpec);
 *   $sharedForTemplate  = TrustedShared::select($trustedShared, $shareSpec);
 */

final class TrustedShared
{
    private function __construct() {}

    /**
     * Create the trusted shared array.
     *
     * Accepts optional dependencies to avoid global lookups in tests.
     * Known keys in $opts: database, user, userId, gopayAdapter, enrichUser (bool)
     *
     * Always returns an array (never throws). On error it logs via Logger if available.
     *
     * @param array $opts
     * @return array
     */
    public static function create(array $opts = []): array
    {
        $db = $opts['database'] ?? null;
        $user = $opts['user'] ?? null;
        $userId = $opts['userId'] ?? null;
        $gopayAdapter = $opts['gopayAdapter'] ?? ($opts['gopay'] ?? null);
        $enrichUser = $opts['enrichUser'] ?? false;

        // try to obtain Database singleton if not provided
        if ($db === null) {
            try {
                if (class_exists('Database') && method_exists('Database', 'getInstance')) {
                    $db = \Database::getInstance();
                }
            } catch (Throwable $e) {
                self::logWarn('TrustedShared: Database not available', ['exception' => (string)$e]);
                $db = null;
            }
        }

        // CSRF token helper
        $csrfToken = null;
        try {
            if (class_exists('CSRF') && method_exists('CSRF', 'token')) {
                $csrfToken = \CSRF::token();
            }
        } catch (Throwable $e) {
            self::logWarn('TrustedShared: failed to get CSRF token', ['exception' => (string)$e]);
            $csrfToken = null;
        }

        // categories (best-effort, cachedFetchAll if available)
        $categories = [];
        if ($db !== null) {
            try {
                if (method_exists($db, 'cachedFetchAll')) {
                    $categories = $db->cachedFetchAll('SELECT * FROM categories ORDER BY nazov ASC');
                } elseif (method_exists($db, 'fetchAll')) {
                    $categories = $db->fetchAll('SELECT * FROM categories ORDER BY nazov ASC');
                }
            } catch (Throwable $e) {
                self::logWarn('TrustedShared: failed to fetch categories', ['exception' => (string)$e]);
                $categories = [];
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
                    // purchased books as integer IDs (best-effort; don't fail on error)
                    if (method_exists($db, 'fetchColumn')) {
                        $pbooks = $db->fetchColumn(
                            'SELECT DISTINCT oi.book_id FROM orders o INNER JOIN order_items oi ON oi.order_id = o.id WHERE o.user_id = :uid AND o.status = :paid_status',
                            ['uid' => $userId, 'paid_status' => 'paid']
                        );
                        $user['purchased_books'] = array_map('intval', (array)$pbooks);
                    }
                }
            } catch (Throwable $e) {
                self::logWarn('TrustedShared: failed to enrich user', ['exception' => (string)$e]);
            }
        }

        // current server timestamp (UTC) may be handy in templates
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
     * This mirrors the selection logic in your front controller.
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
     * We want handler vars first, and then shared vars so shared wins on key collisions.
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
     * Safe logger helper (silent if Logger isn't available).
     * @param string $msg
     * @param array|null $ctx
     * @return void
     */
    private static function logWarn(string $msg, ?array $ctx = null): void
    {
        try {
            if (class_exists('Logger') && method_exists('Logger', 'warn')) {
                \Logger::warn($msg, null, $ctx);
            }
        } catch (Throwable $_) {
            // deliberately silent
        }
    }
}