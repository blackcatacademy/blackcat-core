<?php
declare(strict_types=1);

namespace BlackCat\Core\Log;

use BlackCat\Core\Database;
use BlackCat\Core\Security\KeyManager;
use BlackCat\Core\Helpers\DeferredHelper;

/**
 * Production-ready Logger
 *
 * - No debug output, no echo, no error_log debug messages.
 * - Deferred queue for writes before Database is initialized.
 * - Silent fail-on-error behaviour (design choice): logging must not break app flow.
 *
 * * After Database::init() in bootstrap, call DeferredHelper::flush();
 */

final class Logger
{
    private function __construct() {}
    // -------------------------
    // HELPERS
    // -------------------------
    private static function truncateUserAgent(?string $ua): ?string
    {
        if ($ua === null) return null;
        if (function_exists('mb_substr')) {
            return mb_substr($ua, 0, 255);
        }
        return substr($ua, 0, 255);
    }

    /**
     * Prepare IP hash for database storage.
     * - Accepts either raw 32-byte binary or 64-char hex string (for backward robustness).
     * - Returns binary 32-bytes on success, or null if input is invalid.
     *
     * Database expects VARBINARY(32) — we enforce that here.
     */
    private static function prepareIpForStorage(?string $ipHash): ?string
    {
        if ($ipHash === null) return null;

        // If already binary 32 bytes, accept it
        if (is_string($ipHash) && strlen($ipHash) === 32) {
            return $ipHash;
        }

        // If given as 64-char hex, convert to binary
        if (is_string($ipHash) && ctype_xdigit($ipHash) && strlen($ipHash) === 64) {
            $bin = @hex2bin($ipHash);
            return $bin === false ? null : $bin;
        }

        // Anything else -> reject
        return null;
    }

    public static function getClientIp(): ?string
    {
        $trusted = $_ENV['TRUSTED_PROXIES'] ?? '';
        $trustedList = $trusted ? array_map('trim', explode(',', $trusted)) : [];
        $remote = $_SERVER['REMOTE_ADDR'] ?? null;
        $useForwarded = $remote && in_array($remote, $trustedList, true);

        $headers = ['HTTP_CF_CONNECTING_IP','HTTP_X_REAL_IP','HTTP_X_FORWARDED_FOR'];
        if ($useForwarded) {
            foreach ($headers as $h) {
                if (!empty($_SERVER[$h])) {
                    $ips = explode(',', $_SERVER[$h]);
                    foreach ($ips as $candidate) {
                        $candidate = trim($candidate);
                        if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                            return $candidate;
                        }
                    }
                }
            }
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? null;
        if ($ip && filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
        return null;
    }

    /**
     * Compute HMAC-SHA256 of IP using dedicated IP_HASH_KEY from KeyManager.
     * Returns binary 32-byte hash, key version and used='keymanager' or 'none'.
     *
     * If the dedicated key is not available, we return ['hash' => null, 'key_id' => null, 'used' => 'none']
     * — no fallback to APP_SALT or plain sha256.
     */
    public static function getHashedIp(?string $ip = null): array
    {
        $ipRaw = $ip ?? self::getClientIp();
        if ($ipRaw === null) {
            return ['hash' => null, 'key_id' => null, 'used' => 'none'];
        }

        try {
            if (!class_exists(KeyManager::class, true)) {
                return ['hash' => null, 'key_id' => null, 'used' => 'none'];
            }

            $keysDir = defined('KEYS_DIR') ? KEYS_DIR : ($_ENV['KEYS_DIR'] ?? null);
            $info = KeyManager::getIpHashKeyInfo($keysDir);
            $keyRaw = $info['raw'] ?? null;
            $keyVer = isset($info['version']) && is_string($info['version']) ? $info['version'] : null;

            if (!is_string($keyRaw) || strlen($keyRaw) !== KeyManager::keyByteLen()) {
                // unexpected key format -> return none
                return ['hash' => null, 'key_id' => null, 'used' => 'none'];
            }

            // compute raw binary HMAC (32 bytes)
            $hmacBin = hash_hmac('sha256', $ipRaw, $keyRaw, true);

            // best-effort memzero of key material
            if (method_exists('KeyManager', 'memzero')) {
                try { KeyManager::memzero($keyRaw); } catch (\Throwable $_) {}
            } elseif (function_exists('sodium_memzero')) {
                @sodium_memzero($keyRaw);
                $keyRaw = null;
            }

            // best-effort: purge KeyManager per-request cache for this env so no copies remain
            if (method_exists('KeyManager', 'purgeCacheFor')) {
                try { KeyManager::purgeCacheFor('IP_HASH_KEY'); } catch (\Throwable $_) {}
            }

            return ['hash' => $hmacBin, 'key_id' => $keyVer, 'used' => 'keymanager'];
        } catch (\Throwable $_) {
            // any error -> no hash
            return ['hash' => null, 'key_id' => null, 'used' => 'none'];
        }
    }

    private static function getUserAgent(): ?string
    {
        return $_SERVER['HTTP_USER_AGENT'] ?? null;
    }

    private static function safeJsonEncode($data): ?string
    {
        if ($data === null) return null;
        $json = @json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        return $json === false ? null : $json;
    }

    private static function filterSensitive(?array $meta): ?array
    {
        if ($meta === null) return null;
        $blacklist = ['csrf','token','validator','password','pwd','pass','card_number','cardnum','cc_number','ccnum','cvv','cvc','authorization','auth_token','api_key','secret','g-recaptcha-response','recaptcha_token','recaptcha', 'authorization_bearer', 'refresh_token', 'id_token'];
        $clean = [];
        foreach ($meta as $k => $v) {
            $lk = strtolower((string)$k);
            if (in_array($lk, $blacklist, true)) {
                $clean[$k] = '[REDACTED]';
                continue;
            }
            if (is_array($v)) {
                $nested = [];
                foreach ($v as $nk => $nv) {
                    $nlk = strtolower((string)$nk);
                    $nested[$nk] = in_array($nlk, $blacklist, true) ? '[REDACTED]' : $nv;
                }
                $clean[$k] = $nested;
                continue;
            }
            $clean[$k] = $v;
        }
        return $clean;
    }

    private static function validateAuthType(string $type): string
    {
        // Keep in sync with `blackcat-database` package `auth-events` ENUM.
        $allowed = [
            'login_success',
            'login_failure',
            'logout',
            'password_reset',
            'lockout',
            'magic_link_request',
            'magic_link_throttled',
            'magic_link_email_queued',
            'device_code_issue',
            'device_code_issue_failure',
            'device_code_activate_success',
            'device_code_activate_failure',
            'device_code_poll_success',
            'device_code_poll_failure',
            'webauthn_register_success',
            'webauthn_register_failure',
            'webauthn_login_success',
            'webauthn_login_failure',
        ];
        return in_array($type, $allowed, true) ? $type : 'login_failure';
    }

    private static function validateRegisterType(string $type): string
    {
        $allowed = ['register_success','register_failure'];
        return in_array($type, $allowed, true) ? $type : 'register_failure';
    }

    private static function validateVerifyType(string $type): string
    {
        $allowed = ['verify_success','verify_failure'];
        return in_array($type, $allowed, true) ? $type : 'verify_failure';
    }

    // -------------------------
    // AUTH / REGISTER / VERIFY
    // -------------------------

    /**
     * Best-effort crypto criteria transform (HMAC) via blackcat-database-crypto (when present).
     *
     * @param array<string,mixed> $criteria
     * @return array<string,mixed>|null
     */
    private static function criteriaTransform(string $table, array $criteria): ?array
    {
        $locatorClass = 'BlackCat\\Database\\Crypto\\IngressLocator';
        if (!class_exists($locatorClass)) {
            return null;
        }

        try {
            $adapter = $locatorClass::adapter();
        } catch (\Throwable) {
            return null;
        }
        if (!is_object($adapter) || !method_exists($adapter, 'criteria')) {
            return null;
        }

        try {
            /** @var mixed $out */
            $out = $adapter->criteria($table, $criteria);
        } catch (\Throwable) {
            return null;
        }
        return is_array($out) ? $out : null;
    }

    /**
     * @return array{hash: ?string, key_version: ?string, used: string}
     */
    private static function resolveIpHash(?string $ip, string $table): array
    {
        $ip = $ip ?? self::getClientIp();
        $ip = is_string($ip) ? trim($ip) : null;
        if ($ip === null || $ip === '') {
            return ['hash' => null, 'key_version' => null, 'used' => 'none'];
        }

        $criteria = self::criteriaTransform($table, ['ip_hash' => $ip]);
        if (is_array($criteria)) {
            $hash = self::prepareIpForStorage($criteria['ip_hash'] ?? null);
            $keyVersion = isset($criteria['ip_hash_key_version']) && is_string($criteria['ip_hash_key_version'])
                ? $criteria['ip_hash_key_version']
                : null;
            if ($hash !== null) {
                return ['hash' => $hash, 'key_version' => $keyVersion, 'used' => 'ingress'];
            }
        }

        $fallback = self::getHashedIp($ip);
        return [
            'hash' => self::prepareIpForStorage($fallback['hash'] ?? null),
            'key_version' => isset($fallback['key_id']) && is_string($fallback['key_id']) ? $fallback['key_id'] : null,
            'used' => isset($fallback['used']) && is_string($fallback['used']) ? $fallback['used'] : 'none',
        ];
    }

    private static function noopIngressAdapter(): ?object
    {
        if (!class_exists(\BlackCat\Core\Adapter\NoopIngressAdapter::class)) {
            return null;
        }
        try {
            return new \BlackCat\Core\Adapter\NoopIngressAdapter();
        } catch (\Throwable) {
            return null;
        }
    }

    private static function isDuplicateError(\Throwable $e): bool
    {
        $msg = strtolower($e->getMessage() ?? '');
        return str_contains($msg, 'duplicate') || str_contains($msg, 'unique') || str_contains($msg, 'constraint');
    }

    private static function repoInstance(string $repoClass, string $ingressTable): ?object
    {
        if (!Database::isInitialized()) {
            return null;
        }
        if (!class_exists($repoClass)) {
            return null;
        }
        try {
            $db = Database::getInstance();
            $repo = new $repoClass($db);
        } catch (\Throwable) {
            return null;
        }

        if (method_exists($repo, 'setIngressAdapter')) {
            $noop = self::noopIngressAdapter();
            if ($noop !== null) {
                try {
                    $repo->setIngressAdapter($noop, $ingressTable);
                } catch (\Throwable) {
                }
            }
        }

        return is_object($repo) ? $repo : null;
    }

    private static function safeJsonOrNull(array $data): ?string
    {
        if ($data === []) {
            return null;
        }
        return self::safeJsonEncode($data);
    }

    private static function hex32(?string $bin32): ?string
    {
        if (!is_string($bin32) || strlen($bin32) !== 32) {
            return null;
        }
        return strtoupper(bin2hex($bin32));
    }

    private static function sessionId(): ?string
    {
        if (!function_exists('session_id')) {
            return null;
        }
        $sid = session_id();
        $sid = is_string($sid) ? trim($sid) : null;
        return $sid !== '' ? $sid : null;
    }

    public static function auth(string $type, ?int $userId = null, ?array $meta = null, ?string $ip = null, ?string $userAgent = null): void
    {
        $type = self::validateAuthType($type);
        $userAgent = self::truncateUserAgent($userAgent ?? self::getUserAgent());

        $ipResult = self::resolveIpHash($ip, 'auth_events');
        $ipHash = $ipResult['hash'];
        $ipKeyVersion = $ipResult['key_version'];
        $ipUsed = $ipResult['used'];

        // sanitize meta (remove sensitive values)
        $filteredMeta = self::filterSensitive($meta) ?? [];

        // --- protect against accidental plaintext email logging ---
        // If caller passed plaintext 'email', remove it entirely.
        if (isset($filteredMeta['email'])) {
            unset($filteredMeta['email']);
        }

        // If caller provided a precomputed email hash (bin32/hex64), store it under meta.email
        // so the generated meta_email column remains queryable without plaintext.
        if (isset($filteredMeta['email_hash']) && is_string($filteredMeta['email_hash'])) {
            $bin = self::prepareIpForStorage($filteredMeta['email_hash']);
            $hex = self::hex32($bin);
            if ($hex !== null) {
                $filteredMeta['email'] = $hex;
            }
            unset($filteredMeta['email_hash']);
        }

        // add ip metadata
        $filteredMeta['_ip_hash_used'] = $ipUsed;
        if ($ipKeyVersion !== null) {
            $filteredMeta['_ip_hash_key_version'] = $ipKeyVersion;
        }

        $metaJson = self::safeJsonOrNull($filteredMeta);
        $row = [
            'user_id' => $userId,
            'type' => $type,
            'ip_hash' => $ipHash,
            'ip_hash_key_version' => $ipKeyVersion,
            'user_agent' => $userAgent,
            'meta' => $metaJson,
        ];

        if (Database::isInitialized()) {
            // flush earlier items to try to preserve ordering
            DeferredHelper::flush();
            try {
                $repo = self::repoInstance('BlackCat\\Database\\Packages\\AuthEvents\\Repository\\AuthEventRepository', 'auth_events');
                if ($repo !== null && method_exists($repo, 'insert')) {
                    $repo->insert($row);
                }
            } catch (\Throwable $e) {
                // Silent fail in production — logger must not crash the app.
                return;
            }
            return;
        }

        // DB not ready -> enqueue safe, pre-sanitized row
        DeferredHelper::enqueue(function() use ($row) {
            try {
                $repo = self::repoInstance('BlackCat\\Database\\Packages\\AuthEvents\\Repository\\AuthEventRepository', 'auth_events');
                if ($repo !== null && method_exists($repo, 'insert')) {
                    $repo->insert($row);
                }
            } catch (\Throwable $e) {
                // Silent fail — logger must never crash the app.
            }
        });
    }

    public static function verify(string $type, ?int $userId = null, ?array $meta = null, ?string $ip = null, ?string $userAgent = null): void
    {
        $type = self::validateVerifyType($type);
        $userAgent = self::truncateUserAgent($userAgent ?? self::getUserAgent());

        $ipResult = self::resolveIpHash($ip, 'verify_events');
        $ipHash = $ipResult['hash'];
        $ipKeyVersion = $ipResult['key_version'];
        $ipUsed = $ipResult['used'];

        $filteredMeta = self::filterSensitive($meta) ?? [];
        $filteredMeta['_ip_hash_used'] = $ipUsed;
        if ($ipKeyVersion !== null) {
            $filteredMeta['_ip_hash_key_version'] = $ipKeyVersion;
        }
        $metaJson = self::safeJsonOrNull($filteredMeta);
        $row = [
            'user_id' => $userId,
            'type' => $type,
            'ip_hash' => $ipHash,
            'ip_hash_key_version' => $ipKeyVersion,
            'user_agent' => $userAgent,
            'meta' => $metaJson,
        ];

        if (Database::isInitialized()) {
            DeferredHelper::flush();
            try {
                $repo = self::repoInstance('BlackCat\\Database\\Packages\\VerifyEvents\\Repository\\VerifyEventRepository', 'verify_events');
                if ($repo !== null && method_exists($repo, 'insert')) {
                    $repo->insert($row);
                }
            } catch (\Throwable $e) {
                return;
            }
            return;
        }

        DeferredHelper::enqueue(function() use ($row) {
            try {
                $repo = self::repoInstance('BlackCat\\Database\\Packages\\VerifyEvents\\Repository\\VerifyEventRepository', 'verify_events');
                if ($repo !== null && method_exists($repo, 'insert')) {
                    $repo->insert($row);
                }
            } catch (\Throwable $e) {
                // Silent fail — logger must never crash the app.
            }
        });
    }

    /**
     * Records an event into session_audit.
     *
     * @param string $event          event key (validated against allow-list)
     * @param int|null $userId
     * @param array|null $meta       associative array (sensitive fields are filtered)
     * @param string|null $ip
     * @param string|null $userAgent
     * @param string|null $outcome
     * @param string|null $tokenHashBin  binary token_hash (BINARY(32)) - if available
     */
    public static function session(string $event, ?int $userId = null, ?array $meta = null, ?string $ip = null, ?string $userAgent = null, ?string $outcome = null, ?string $tokenHashBin = null): void
    {
        // Extended allow-list (add additional internal events you use).
        $allowed = [
            'session_created','session_destroyed','session_regenerated',
            'csrf_valid','csrf_invalid','session_expired','session_activity',
            'decrypt_failed','revoked','revoked_manual','session_login','session_logout','audit'
        ];
        $event = in_array($event, $allowed, true) ? $event : 'session_activity';

        $ipResult = self::resolveIpHash($ip, 'session_audit');
        $ipHash = $ipResult['hash'];
        $ipKeyVersion = $ipResult['key_version'];
        $ipUsed = $ipResult['used'];

        $ua = self::truncateUserAgent($userAgent ?? self::getUserAgent());
        $filteredMeta = self::filterSensitive($meta) ?? [];
        // Add metadata (does not contain raw sensitive data).
        $filteredMeta['_ip_hash_used'] = $ipUsed;
        if ($ipKeyVersion !== null) {
            $filteredMeta['_ip_hash_key_version'] = $ipKeyVersion;
        }
        $metaJson = self::safeJsonOrNull($filteredMeta);

        $sessId = self::sessionId();

        // Read key versions from metadata if present.
        $sessionTokenKeyVersion = $filteredMeta['session_token_key_version'] ?? null;
        $csrfKeyVersion = $filteredMeta['csrf_key_version'] ?? null;

        $tokenHashBin = self::prepareIpForStorage($tokenHashBin);
        $csrfTokenHash = null;
        if (isset($filteredMeta['csrf_token_hash']) && is_string($filteredMeta['csrf_token_hash'])) {
            $csrfTokenHash = self::prepareIpForStorage($filteredMeta['csrf_token_hash']);
        }

        $row = [
            'session_token_hash' => $tokenHashBin,
            'session_token_key_version' => is_string($sessionTokenKeyVersion) ? $sessionTokenKeyVersion : null,
            'csrf_token_hash' => $csrfTokenHash,
            'csrf_key_version' => is_string($csrfKeyVersion) ? $csrfKeyVersion : null,
            'session_id' => $sessId,
            'event' => $event,
            'user_id' => $userId,
            'ip_hash' => $ipHash,
            'ip_hash_key_version' => $ipKeyVersion,
            'user_agent' => $ua,
            'meta_json' => $metaJson,
            'outcome' => $outcome,
        ];

        if (Database::isInitialized()) {
            DeferredHelper::flush();
            try {
                $repo = self::repoInstance('BlackCat\\Database\\Packages\\SessionAudit\\Repository\\SessionAuditRepository', 'session_audit');
                if ($repo !== null && method_exists($repo, 'insert')) {
                    $repo->insert($row);
                }
            } catch (\Throwable $e) {
                // Silent fail — audit logging must not crash the app.
                return;
            }
            return;
        }

        DeferredHelper::enqueue(function() use ($row) {
            try {
                $repo = self::repoInstance('BlackCat\\Database\\Packages\\SessionAudit\\Repository\\SessionAuditRepository', 'session_audit');
                if ($repo !== null && method_exists($repo, 'insert')) {
                    $repo->insert($row);
                }
            } catch (\Throwable $e) {
                // Silent fail — logger must never crash the app.
            }
        });
    }

    // -------------------------
    // SYSTEM MESSAGE / ERROR (with fingerprint aggregation)
    // -------------------------
    public static function systemMessage(string $level, string $message, ?int $userId = null, ?array $context = null, ?string $token = null, bool $aggregateByFingerprint = false): void
    {
        $level = in_array($level, ['notice','warning','error','critical'], true) ? $level : 'error';
        $ipResult = self::resolveIpHash(null, 'system_errors');
        $ipHash = $ipResult['hash'];
        $ipKeyVersion = $ipResult['key_version'];
        $ipUsed = $ipResult['used'];
        $ua = self::truncateUserAgent(self::getUserAgent());
        $context = $context ?? [];
        $file = $context['file'] ?? null;
        $line = $context['line'] ?? null;
        $baseFingerprint = hash('sha256', $level . '|' . $message . '|' . ($file ?? '') . ':' . ($line ?? ''));
        $fingerprint = $baseFingerprint;
        if (!$aggregateByFingerprint) {
            $entropy = microtime(true) . '|' . (string)(function_exists('getmypid') ? getmypid() : 0) . '|' . uniqid('', true);
            $fingerprint = hash('sha256', $baseFingerprint . '|' . $entropy);
        }
        $context['_ip_hash_used'] = $ipUsed;
        if ($ipKeyVersion !== null) {
            $context['_ip_hash_key_version'] = $ipKeyVersion;
        }
        $jsonContext = self::safeJsonEncode($context);
        $rawUrl = $_SERVER['REQUEST_URI'] ?? null;
        if ($rawUrl !== null) {
            $parts = parse_url($rawUrl);
            if (isset($parts['query'])) {
                parse_str($parts['query'], $q);
                $qClean = self::filterSensitive($q); // reuse the existing sanitizer
                $parts['query'] = http_build_query($qClean);
                // Build the URL back.
                $cleanUrl = (isset($parts['path']) ? $parts['path'] : '')
                        . (isset($parts['query']) ? '?' . $parts['query'] : '')
                        . (isset($parts['fragment']) ? '#' . $parts['fragment'] : '');
            } else {
                $cleanUrl = $rawUrl;
            }
        } else {
            $cleanUrl = null;
        }

        $status = http_response_code() ?: null;
        $payload = [
            'level' => $level,
            'message' => $message,
            'exception_class' => null,
            'file' => is_string($file) ? $file : null,
            'line' => is_numeric($line) ? (int)$line : null,
            'stack_trace' => null,
            'token' => $token,
            'context' => $jsonContext,
            'fingerprint' => $fingerprint,
            'occurrences' => 1,
            'user_id' => $userId,
            'ip_hash' => $ipHash,
            'ip_hash_key_version' => $ipKeyVersion,
            'user_agent' => $ua,
            'url' => $cleanUrl,
            'method' => $_SERVER['REQUEST_METHOD'] ?? null,
            'http_status' => is_int($status) && $status > 0 ? $status : null,
        ];

        if (Database::isInitialized()) {
            DeferredHelper::flush();
            try {
                self::writeSystemError($payload, $aggregateByFingerprint);
            } catch (\Throwable $e) {
                return;
            }
            return;
        }

        DeferredHelper::enqueue(function() use ($payload, $aggregateByFingerprint) {
            try {
                self::writeSystemError($payload, $aggregateByFingerprint);
            } catch (\Throwable $e) {
                // Silent fail — logger must never crash the app.
            }
        });
    }

    public static function systemError(\Throwable $e, ?int $userId = null, ?string $token = null, ?array $context = null, bool $aggregateByFingerprint = true): void
    {
        if ($e instanceof \PDOException) {
            $message = 'Database error';
        } else {
            $message = (string)$e->getMessage();
        }

        $exceptionClass = get_class($e);
        $file = $e->getFile();
        $line = $e->getLine();
        $stack = !empty($_ENV['DEBUG']) ? $e->getTraceAsString() : null;

        $ipResult = self::resolveIpHash(null, 'system_errors');
        $ipHash = $ipResult['hash'];
        $ipKeyVersion = $ipResult['key_version'];
        $ipUsed = $ipResult['used'];

        $ua = self::truncateUserAgent(self::getUserAgent());
        $baseFingerprint = hash('sha256', $message . '|' . $exceptionClass . '|' . $file . ':' . $line);
        $fingerprint = $baseFingerprint;
        if (!$aggregateByFingerprint) {
            $entropy = microtime(true) . '|' . (string)(function_exists('getmypid') ? getmypid() : 0) . '|' . uniqid('', true);
            $fingerprint = hash('sha256', $baseFingerprint . '|' . $entropy);
        }

        $context = $context ?? [];
        $context['_ip_hash_used'] = $ipUsed;
        if ($ipKeyVersion !== null) {
            $context['_ip_hash_key_version'] = $ipKeyVersion;
        }
        $jsonContext = self::safeJsonEncode($context);
        $rawUrl = $_SERVER['REQUEST_URI'] ?? null;
        if ($rawUrl !== null) {
            $parts = parse_url($rawUrl);
            if (isset($parts['query'])) {
                parse_str($parts['query'], $q);
                $qClean = self::filterSensitive($q); // reuse the existing sanitizer
                $parts['query'] = http_build_query($qClean);
                // Build the URL back.
                $cleanUrl = (isset($parts['path']) ? $parts['path'] : '')
                        . (isset($parts['query']) ? '?' . $parts['query'] : '')
                        . (isset($parts['fragment']) ? '#' . $parts['fragment'] : '');
            } else {
                $cleanUrl = $rawUrl;
            }
        } else {
            $cleanUrl = null;
        }

        $status = http_response_code() ?: null;
        $payload = [
            'level' => 'error',
            'message' => $message,
            'exception_class' => $exceptionClass,
            'file' => $file,
            'line' => $line,
            'stack_trace' => $stack,
            'token' => $token,
            'context' => $jsonContext,
            'fingerprint' => $fingerprint,
            'occurrences' => 1,
            'user_id' => $userId,
            'ip_hash' => $ipHash,
            'ip_hash_key_version' => $ipKeyVersion,
            'user_agent' => $ua,
            'url' => $cleanUrl,
            'method' => $_SERVER['REQUEST_METHOD'] ?? null,
            'http_status' => is_int($status) && $status > 0 ? $status : null,
        ];

        if (Database::isInitialized()) {
            DeferredHelper::flush();
            try {
                self::writeSystemError($payload, $aggregateByFingerprint);
            } catch (\Throwable $ex) {
                return;
            }
            return;
        }

        DeferredHelper::enqueue(function() use ($payload, $aggregateByFingerprint) {
            try {
                self::writeSystemError($payload, $aggregateByFingerprint);
            } catch (\Throwable $e) {
                // Silent fail — logger must never crash the app.
            }
        });
    }

    /**
     * Insert into `system_errors` with optional fingerprint aggregation (occurrences++).
     *
     * @param array<string,mixed> $row
     */
    private static function writeSystemError(array $row, bool $aggregateByFingerprint): void
    {
        $repo = self::repoInstance('BlackCat\\Database\\Packages\\SystemErrors\\Repository\\SystemErrorRepository', 'system_errors');
        if ($repo === null || !method_exists($repo, 'insert')) {
            return;
        }

        $fingerprint = $row['fingerprint'] ?? null;
        $fingerprint = is_string($fingerprint) ? trim($fingerprint) : '';
        if ($fingerprint === '') {
            return;
        }

        if (!$aggregateByFingerprint) {
            $repo->insert($row);
            return;
        }

        try {
            $repo->insert($row);
            return;
        } catch (\Throwable $e) {
            if (!self::isDuplicateError($e)) {
                throw $e;
            }
        }

        if (!method_exists($repo, 'getByFingerprint') || !method_exists($repo, 'updateById')) {
            return;
        }

        $existing = $repo->getByFingerprint($fingerprint, false);
        if (!is_array($existing) || !isset($existing['id'])) {
            return;
        }

        $occ = isset($existing['occurrences']) ? (int)$existing['occurrences'] : 1;
        $occ = max(1, $occ + 1);

        $update = [
            'occurrences' => $occ,
            'last_seen' => (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s.u'),
        ];
        if (isset($row['message'])) {
            $update['message'] = $row['message'];
        }
        if (isset($row['stack_trace']) && $row['stack_trace'] !== null) {
            $update['stack_trace'] = $row['stack_trace'];
        }

        $repo->updateById($existing['id'], $update);
    }

    // Convenience aliases
    public static function error(string $message, ?int $userId = null, ?array $context = null, ?string $token = null): void
    {
        self::systemMessage('error', $message, $userId, $context, $token, false);
    }

    public static function warn(string $message, ?int $userId = null, ?array $context = null): void
    {
        self::systemMessage('warning', $message, $userId, $context, null, false);
    }

    public static function info(string $message, ?int $userId = null, ?array $context = null): void
    {
        self::systemMessage('notice', $message, $userId, $context, null, false);
    }

    public static function critical(string $message, ?int $userId = null, ?array $context = null): void
    {
        self::systemMessage('critical', $message, null, $context, null, false);
    }
}
