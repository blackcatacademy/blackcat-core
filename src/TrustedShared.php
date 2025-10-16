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

        // safe subset of config for handlers (avoid passing full config)
        $configMin = [];
        try {
            $appConfig = $opts['config'] ?? ($opts['database']->config ?? ($GLOBALS['config'] ?? []));
            if (is_array($appConfig)) {
                $configMin['capchav3'] = $appConfig['capchav3'] ?? [];
                $configMin['paths'] = $appConfig['paths'] ?? [];
                // další bezpečné klíče pokud potřebuješ (smtp, paths, app_url apod.)
                $configMin['smtp_from'] = $appConfig['smtp']['from'] ?? ($appConfig['smtp_from'] ?? null);
            }
        } catch (\Throwable $_) {
            $configMin = [];
        }

        $trustedShared = [
            'user'         => $user,
            'csrfToken'    => $csrfToken,
            'csrf'         => $csrfToken,
            'categories'   => $categories,
            'db'           => $db,
            'gopayAdapter' => $gopayAdapter,
            'now_utc'      => $nowUtc,
            'config_min'   => $configMin,
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
     * Prepare mapping of shareSpec -> concrete variables for handler include scope.
     *
     * @param array $trustedShared  The array returned by create()
     * @param bool|array $shareSpec The share specification from routes (true|false|array)
     * @param array $opts           Optional extra opts: ['config'=>array]
     * @return array                Mapped variables to extract() into handler
     */
    public static function prepareForHandler(array $trustedShared, bool|array $shareSpec, array $opts = []): array
    {
        if ($shareSpec === true) {
            // provide conservative set (but still don't pass whole raw config)
            // map common keys from trustedShared
            $out = $trustedShared;
            // replace full config with config_min if present
            if (isset($trustedShared['config_min'])) {
                $out['config'] = $trustedShared['config_min'];
            }
            return $out;
        }

        if ($shareSpec === false) return [];

        $mapped = [];
        foreach ($shareSpec as $key) {
            switch ($key) {
                case 'config':
                    $mapped['config'] = $opts['config'] ?? $trustedShared['config_min'] ?? [];
                    break;

                // Logger / logging
                case 'Logger':
                    if (class_exists(\BlackCat\Core\Log\Logger::class)) $mapped['Logger'] = \BlackCat\Core\Log\Logger::class;
                    break;
                case 'AuditLogger':
                    if (class_exists(\BlackCat\Core\Log\AuditLogger::class)) $mapped['AuditLogger'] = \BlackCat\Core\Log\AuditLogger::class;
                    break;
                case 'LoggerPsrAdapter':
                    if (class_exists(\BlackCat\Core\Adapter\LoggerPsrAdapter::class)) $mapped['LoggerPsrAdapter'] = \BlackCat\Core\Adapter\LoggerPsrAdapter::class;
                    break;

                // Database / DB instance
                case 'db':
                case 'Database':
                    if (!empty($trustedShared['db'])) {
                        $mapped['db'] = $trustedShared['db'];
                        $mapped['Database'] = $trustedShared['db'];
                    } elseif (class_exists(\BlackCat\Core\Database::class)) {
                        $mapped['Database'] = \BlackCat\Core\Database::class;
                    }
                    break;

                // Cache
                case 'cache':
                case 'FileCache':
                case 'Cache':
                    if (!empty($trustedShared['cache'])) {
                        $mapped['cache'] = $trustedShared['cache'];
                    } elseif (class_exists(\BlackCat\Core\Cache\FileCache::class)) {
                        $mapped['FileCache'] = \BlackCat\Core\Cache\FileCache::class;
                    }
                    break;

                // Mail
                case 'MailHelper':
                    if (class_exists(\BlackCat\Core\Helpers\MailHelper::class)) $mapped['MailHelper'] = \BlackCat\Core\Helpers\MailHelper::class;
                    break;
                case 'Mailer':
                    if (class_exists(\BlackCat\Core\Mail\Mailer::class)) $mapped['Mailer'] = \BlackCat\Core\Mail\Mailer::class;
                    break;

                // Templates & helpers for rendering
                case 'Templates':
                    if (class_exists(\BlackCat\Core\Templates\Templates::class)) $mapped['Templates'] = \BlackCat\Core\Templates\Templates::class;
                    break;
                case 'EmailTemplates':
                    if (class_exists(\BlackCat\Core\Templates\EmailTemplates::class)) $mapped['EmailTemplates'] = \BlackCat\Core\Templates\EmailTemplates::class;
                    break;
                case 'SafeHtml':
                    if (class_exists(\BlackCat\Core\Templates\SafeHtml::class)) $mapped['SafeHtml'] = \BlackCat\Core\Templates\SafeHtml::class;
                    break;

                // Security / Crypto / Keys / CSRF
                case 'KeyManager':
                    if (class_exists(\BlackCat\Core\Security\KeyManager::class)) $mapped['KeyManager'] = \BlackCat\Core\Security\KeyManager::class;
                    break;
                case 'Crypto':
                    if (class_exists(\BlackCat\Core\Security\Crypto::class)) $mapped['Crypto'] = \BlackCat\Core\Security\Crypto::class;
                    break;
                case 'FileVault':
                    if (class_exists(\BlackCat\Core\Security\FileVault::class)) $mapped['FileVault'] = \BlackCat\Core\Security\FileVault::class;
                    break;
                case 'CSRF':
                    if (class_exists(\BlackCat\Core\Security\CSRF::class)) $mapped['CSRF'] = \BlackCat\Core\Security\CSRF::class;
                    break;
                case 'Recaptcha':
                    if (class_exists(\BlackCat\Core\Security\Recaptcha::class)) $mapped['Recaptcha'] = \BlackCat\Core\Security\Recaptcha::class;
                    break;
                case 'LoginLimiter':
                    if (class_exists(\BlackCat\Core\Security\LoginLimiter::class)) $mapped['LoginLimiter'] = \BlackCat\Core\Security\LoginLimiter::class;
                    break;
                case 'Auth':
                    if (class_exists(\BlackCat\Core\Security\Auth::class)) $mapped['Auth'] = \BlackCat\Core\Security\Auth::class;
                    break;

                // Session
                case 'Session':
                case 'SessionManager':
                    if (!empty($trustedShared['session'])) {
                        $mapped['session'] = $trustedShared['session'];
                    } elseif (class_exists(\BlackCat\Core\Session\SessionManager::class)) {
                        $mapped['SessionManager'] = \BlackCat\Core\Session\SessionManager::class;
                    }
                    break;

                // Validation
                case 'Validator':
                    if (class_exists(\BlackCat\Core\Validation\Validator::class)) $mapped['Validator'] = \BlackCat\Core\Validation\Validator::class;
                    break;

                // Helpers namespace / specific helpers
                case 'DeferredHelper':
                    if (class_exists(\BlackCat\Core\Helpers\DeferredHelper::class)) $mapped['DeferredHelper'] = \BlackCat\Core\Helpers\DeferredHelper::class;
                    break;
                case 'EnforcePasswordChange':
                    if (class_exists(\BlackCat\Core\Helpers\EnforcePasswordChange::class)) $mapped['EnforcePasswordChange'] = \BlackCat\Core\Helpers\EnforcePasswordChange::class;
                    break;
                case 'GoPayAdapter':
                    if (!empty($trustedShared['gopayAdapter'])) {
                        $mapped['gopayAdapter'] = $trustedShared['gopayAdapter'];
                        $mapped['GoPayAdapter'] = $trustedShared['gopayAdapter'];
                    } elseif (class_exists(\BlackCat\Core\Payment\GoPayAdapter::class)) {
                        $mapped['GoPayAdapter'] = \BlackCat\Core\Payment\GoPayAdapter::class;
                    }
                    break;
                case 'GoPaySdkWrapper':
                    if (class_exists(\BlackCat\Core\Payment\GoPaySdkWrapper::class)) $mapped['GoPaySdkWrapper'] = \BlackCat\Core\Payment\GoPaySdkWrapper::class;
                    break;
                case 'PaymentGatewayInterface':
                    if (interface_exists(\BlackCat\Core\Payment\PaymentGatewayInterface::class)) $mapped['PaymentGatewayInterface'] = \BlackCat\Core\Payment\PaymentGatewayInterface::class;
                    break;
                case 'GoPayStatus':
                    if (class_exists(\BlackCat\Core\Payment\GoPayStatus::class)) $mapped['GoPayStatus'] = \BlackCat\Core\Payment\GoPayStatus::class;
                    break;

                // Exceptions (map class-strings so handlers can catch/type-hint)
                case 'DatabaseException':
                    if (class_exists(\BlackCat\Core\DatabaseException::class)) $mapped['DatabaseException'] = \BlackCat\Core\DatabaseException::class;
                    break;
                case 'KeyManagerException':
                    if (class_exists(\BlackCat\Core\Security\KeyManagerException::class)) $mapped['KeyManagerException'] = \BlackCat\Core\Security\KeyManagerException::class;
                    break;
                case 'GoPayHttpException':
                    if (class_exists(\BlackCat\Core\Payment\GoPayHttpException::class)) $mapped['GoPayHttpException'] = \BlackCat\Core\Payment\GoPayHttpException::class;
                    break;
                case 'GoPayPaymentException':
                    if (class_exists(\BlackCat\Core\Payment\GoPayPaymentException::class)) $mapped['GoPayPaymentException'] = \BlackCat\Core\Payment\GoPayPaymentException::class;
                    break;
                case 'GoPayTokenException':
                    if (class_exists(\BlackCat\Core\Payment\GoPayTokenException::class)) $mapped['GoPayTokenException'] = \BlackCat\Core\Payment\GoPayTokenException::class;
                    break;

                // TrustedShared itself if requested
                case 'TrustedShared':
                    $mapped['TrustedShared'] = $trustedShared;
                    break;

                // KEYS_DIR and csrf value (legacy)
                case 'KEYS_DIR':
                    $mapped['KEYS_DIR'] = defined('KEYS_DIR') ? KEYS_DIR : ($trustedShared['config_min']['paths']['keys'] ?? null);
                    break;
                case 'csrf':
                    $mapped['csrf'] = $trustedShared['csrf'] ?? $trustedShared['csrfToken'] ?? null;
                    break;

                // Generic passthrough: if key exists in trustedShared, forward it
                default:
                    if (array_key_exists($key, $trustedShared)) {
                        $mapped[$key] = $trustedShared[$key];
                    }
                    break;
            }
        }

        return $mapped;

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
        $sensitive = [
        'password', 'password_hash', 'pwd', 'token', 'remember_token', 'ssn', 'secret',
        // local / slovak/czech keys in your dump:
        'heslo', 'heslo_hash', 'heslo_algo', 'heslo_key_version',
        'email_enc', 'email_hash', 'email_hash_key_version',
        'last_login_ip_hash', 'last_login_ip_key',
        // other internal keys you don't want in templates
        'failed_logins', 'must_change_password'
        ];
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