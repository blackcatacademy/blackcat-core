<?php
declare(strict_types=1);

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
        return mb_substr($ua, 0, 255);
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
            if (!class_exists('KeyManager') || !method_exists('KeyManager', 'getIpHashKeyInfo')) {
                return ['hash' => null, 'key_id' => null, 'used' => 'none'];
            }

            $keysDir = defined('KEYS_DIR') ? KEYS_DIR : ($_ENV['KEYS_DIR'] ?? null);
            $info = \KeyManager::getIpHashKeyInfo($keysDir);
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
                try { \KeyManager::memzero($keyRaw); } catch (\Throwable $_) {}
            } elseif (function_exists('sodium_memzero')) {
                @sodium_memzero($keyRaw);
                $keyRaw = null;
            }

            // best-effort: purge KeyManager per-request cache for this env so no copies remain
            if (method_exists('KeyManager', 'purgeCacheFor')) {
                try { \KeyManager::purgeCacheFor('IP_HASH_KEY'); } catch (\Throwable $_) {}
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
        $allowed = ['login_success','login_failure','logout','password_reset','lockout'];
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
    public static function auth(string $type, ?int $userId = null, ?array $meta = null, ?string $ip = null, ?string $userAgent = null): void
    {
        $type = self::validateAuthType($type);
        $userAgent = self::truncateUserAgent($userAgent ?? self::getUserAgent());

        $ipResult = self::getHashedIp($ip);
        $ipHash = self::prepareIpForStorage($ipResult['hash']);
        $ipKeyId = $ipResult['key_id'];
        $ipUsed = $ipResult['used'];

        // sanitize meta (remove sensitive values)
        $filteredMeta = self::filterSensitive($meta) ?? [];

        // --- protect against accidental plaintext email logging ---
        // If caller passed plaintext 'email', remove it entirely.
        if (isset($filteredMeta['email'])) {
            unset($filteredMeta['email']);
        }

        // If caller provided a precomputed email hash (binary or base64/text), use it for meta_email.
        $metaEmail = null;
        if (isset($filteredMeta['email_hash'])) {
            $eh = $filteredMeta['email_hash'];
            // if binary (non-printable), base64 encode for storage
            if (is_string($eh)) {
                if (preg_match('/[^\x20-\x7E]/', $eh)) {
                    // binary -> base64
                    $metaEmail = base64_encode($eh);
                } else {
                    // printable -> store as-is (expected base64 or hex or textual token)
                    $metaEmail = $eh;
                }
            } elseif (is_scalar($eh)) {
                $metaEmail = (string)$eh;
            }
            // remove from meta JSON to avoid duplication of sensitive-ish value
            unset($filteredMeta['email_hash']);
        }

        // add ip metadata
        $filteredMeta['_ip_hash_used'] = $ipUsed;
        if ($ipKeyId !== null) $filteredMeta['_ip_hash_key'] = $ipKeyId;

        $json = self::safeJsonEncode($filteredMeta);

        // include meta_email column (stores email_hash token/base64) to avoid saving plaintext email in meta JSON
        $sql = "INSERT INTO auth_events (user_id, type, ip_hash, ip_hash_key, user_agent, occurred_at, meta, meta_email)
                VALUES (:user_id, :type, :ip_hash, :ip_hash_key, :ua, UTC_TIMESTAMP(), :meta, :meta_email)";

        $params = [
            ':user_id'    => $userId,
            ':type'       => $type,
            ':ip_hash'    => $ipHash,
            ':ip_hash_key'=> $ipKeyId,
            ':ua'         => $userAgent,
            ':meta'       => $json,
            ':meta_email' => $metaEmail,
        ];

        if (\Database::isInitialized()) {
            // flush earlier items to try to preserve ordering
            DeferredHelper::flush();
            try {
                \Database::getInstance()->execute($sql, $params);
            } catch (\Throwable $e) {
                // silent fail in production — logger nesmí shodit aplikaci
                return;
            }
            return;
        }

        // DB not ready -> enqueue safe, pre-sanitized SQL/params
        DeferredHelper::enqueue(function() use ($sql, $params) {
            try {
                \Database::getInstance()->execute($sql, $params);
            } catch (\Throwable $e) {
                // silent fail – logger nikdy nesmí shodit aplikaci
            }
        });
    }

    public static function verify(string $type, ?int $userId = null, ?array $meta = null, ?string $ip = null, ?string $userAgent = null): void
    {
        $type = self::validateVerifyType($type);
        $userAgent = self::truncateUserAgent($userAgent ?? self::getUserAgent());

        $ipResult = self::getHashedIp($ip);
        $ipHash = self::prepareIpForStorage($ipResult['hash']);
        $ipKeyId = $ipResult['key_id'];
        $ipUsed = $ipResult['used'];

        $filteredMeta = self::filterSensitive($meta) ?? [];
        $filteredMeta['_ip_hash_used'] = $ipUsed;
        if ($ipKeyId !== null) $filteredMeta['_ip_hash_key'] = $ipKeyId;
        $json = self::safeJsonEncode($filteredMeta);

        $sql = "INSERT INTO verify_events (user_id, type, ip_hash, ip_hash_key, user_agent, occurred_at, meta)
                VALUES (:user_id, :type, :ip_hash, :ip_hash_key, :ua, UTC_TIMESTAMP(), :meta)";
        $params = [
            ':user_id' => $userId,
            ':type' => $type,
            ':ip_hash' => $ipHash,
            ':ip_hash_key' => $ipKeyId,
            ':ua' => $userAgent,
            ':meta' => $json,
        ];

        if (\Database::isInitialized()) {
            DeferredHelper::flush();
            try {
                \Database::getInstance()->execute($sql, $params);
            } catch (\Throwable $e) {
                return;
            }
            return;
        }

        DeferredHelper::enqueue(function() use ($sql, $params) {
            try {
                \Database::getInstance()->execute($sql, $params);
            } catch (\Throwable $e) {
                // silent fail – logger nikdy nesmí shodit aplikaci
            }
        });
    }

    /**
     * Zaznamená událost do session_audit.
     *
     * @param string $event          event key (validated against allow-list)
     * @param int|null $userId
     * @param array|null $meta       asociativní pole (sensitive fields budou filtrovány)
     * @param string|null $ip
     * @param string|null $userAgent
     * @param string|null $outcome
     * @param string|null $tokenHashBin  binární token_hash (BINARY(32)) - pokud dostupné
     */
    public static function session(string $event, ?int $userId = null, ?array $meta = null, ?string $ip = null, ?string $userAgent = null, ?string $outcome = null, ?string $tokenHashBin = null): void
    {
        // Rozšířený allow-list (přidej další interní eventy, které používáš)
        $allowed = [
            'session_created','session_destroyed','session_regenerated',
            'csrf_valid','csrf_invalid','session_expired','session_activity',
            'decrypt_failed','revoked','revoked_manual','session_login','session_logout','audit'
        ];
        $event = in_array($event, $allowed, true) ? $event : 'session_activity';

        $ipResult = self::getHashedIp($ip);
        $ipHash = self::prepareIpForStorage($ipResult['hash']);
        $ipKeyId = $ipResult['key_id'];
        $ipUsed = $ipResult['used'];

        $ua = self::truncateUserAgent($userAgent ?? self::getUserAgent());
        $filteredMeta = self::filterSensitive($meta) ?? [];
        // doplníme info do meta (neobsahuje raw sensitive data)
        $filteredMeta['_ip_hash_used'] = $ipUsed;
        if ($ipKeyId !== null) $filteredMeta['_ip_hash_key'] = $ipKeyId;
        $json = self::safeJsonEncode($filteredMeta);

        $sessId = null;
        if (function_exists('session_id')) {
            $sid = session_id();
            if ($sid !== '' && $sid !== null) $sessId = $sid;
        }

        // z meta si vyzobneme verze pokud tam jsou
        $sessionTokenKeyVersion = $filteredMeta['session_token_key_version'] ?? null;
        $csrfKeyVersion = $filteredMeta['csrf_key_version'] ?? null;

        $sql = "INSERT INTO session_audit (
                    session_token,
                    session_token_key_version,
                    csrf_key_version,
                    session_id,
                    event,
                    user_id,
                    ip_hash,
                    ip_hash_key,
                    ua,
                    meta_json,
                    outcome,
                    created_at
                ) VALUES (
                    :session_token,
                    :session_token_key_version,
                    :csrf_key_version,
                    :session_id,
                    :event,
                    :user_id,
                    :ip_hash,
                    :ip_hash_key,
                    :ua,
                    :meta,
                    :outcome,
                    UTC_TIMESTAMP()
                )";

        $params = [
            ':session_token' => $tokenHashBin, // necháváme binární data (Database wrapper musí to umět)
            ':session_token_key_version' => $sessionTokenKeyVersion,
            ':csrf_key_version' => $csrfKeyVersion,
            ':session_id' => $sessId,
            ':event' => $event,
            ':user_id' => $userId,
            ':ip_hash' => $ipHash,
            ':ip_hash_key' => $ipKeyId,
            ':ua' => $ua,
            ':meta' => $json,
            ':outcome' => $outcome,
        ];

        // Pokud máš vlastní Database wrapper, který správně váže nibinární hodnoty – ok.
        // Jinak níže nabízím přímý PDO fallback.
        if (\Database::isInitialized()) {
            DeferredHelper::flush();
            try {
                \Database::getInstance()->execute($sql, $params);
            } catch (\Throwable $e) {
                // silent fail — nechceme shodit aplikaci kvůli auditu
                return;
            }
            return;
        }

        DeferredHelper::enqueue(function() use ($sql, $params) {
            try {
                \Database::getInstance()->execute($sql, $params);
            } catch (\Throwable $e) {
                // silent fail – logger nikdy nesmí shodit aplikaci
            }
        });
    }

    // -------------------------
    // SYSTEM MESSAGE / ERROR (with fingerprint aggregation)
    // -------------------------
    public static function systemMessage(string $level, string $message, ?int $userId = null, ?array $context = null, ?string $token = null, bool $aggregateByFingerprint = false): void
    {
        $level = in_array($level, ['notice','warning','error','critical'], true) ? $level : 'error';
        $ipResult = self::getHashedIp(null);
        $ipHash = self::prepareIpForStorage($ipResult['hash']);
        $ipKeyId = $ipResult['key_id'];
        $ipUsed = $ipResult['used'];
        $ua = self::truncateUserAgent(self::getUserAgent());
        $context = $context ?? [];
        $file = $context['file'] ?? null;
        $line = $context['line'] ?? null;
        $fingerprint = hash('sha256', $level . '|' . $message . '|' . ($file ?? '') . ':' . ($line ?? ''));
        $context['_ip_hash_used'] = $ipUsed;
        if ($ipKeyId !== null) $context['_ip_hash_key'] = $ipKeyId;
        $jsonContext = self::safeJsonEncode($context);
        $rawUrl = $_SERVER['REQUEST_URI'] ?? null;
        if ($rawUrl !== null) {
            $parts = parse_url($rawUrl);
            if (isset($parts['query'])) {
                parse_str($parts['query'], $q);
                $qClean = self::filterSensitive($q); // použij tvou funkci
                $parts['query'] = http_build_query($qClean);
                // složíme URL zpět
                $cleanUrl = (isset($parts['path']) ? $parts['path'] : '')
                        . (isset($parts['query']) ? '?' . $parts['query'] : '')
                        . (isset($parts['fragment']) ? '#' . $parts['fragment'] : '');
            } else {
                $cleanUrl = $rawUrl;
            }
        } else {
            $cleanUrl = null;
        }

        // Upsert style: requires UNIQUE index on fingerprint in DB
        $sql = "INSERT INTO system_error
            (level, message, exception_class, file, line, stack_trace, token, context, fingerprint, occurrences, user_id, ip_hash, ip_hash_key, user_agent, url, method, http_status, created_at, last_seen)
            VALUES (:level, :message, NULL, :file, :line, NULL, :token, :context, :fingerprint, 1, :user_id, :ip_hash, :ip_hash_key, :ua, :url, :method, :status, UTC_TIMESTAMP(), UTC_TIMESTAMP())
            ON DUPLICATE KEY UPDATE occurrences = occurrences + 1, last_seen = UTC_TIMESTAMP(), message = VALUES(message)";

        $params = [
            ':level' => $level,
            ':message' => $message,
            ':file' => $file,
            ':line' => $line,
            ':token' => $token,
            ':context' => $jsonContext,
            ':fingerprint' => $fingerprint,
            ':user_id' => $userId,
            ':ip_hash' => $ipHash,
            ':ip_hash_key' => $ipKeyId,
            ':ua' => $ua,
            ':url' => $cleanUrl,
            ':method' => $_SERVER['REQUEST_METHOD'] ?? null,
            ':status' => http_response_code() ?: null,
        ];

        if (\Database::isInitialized()) {
            DeferredHelper::flush();
            try {
                \Database::getInstance()->execute($sql, $params);
            } catch (\Throwable $e) {
                return;
            }
            return;
        }

        DeferredHelper::enqueue(function() use ($sql, $params) {
            try {
                \Database::getInstance()->execute($sql, $params);
            } catch (\Throwable $e) {
                // silent fail – logger nikdy nesmí shodit aplikaci
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

        $ipResult = self::getHashedIp(null);
        $ipHash = self::prepareIpForStorage($ipResult['hash']);
        $ipKeyId = $ipResult['key_id'];
        $ipUsed = $ipResult['used'];

        $ua = self::truncateUserAgent(self::getUserAgent());
        $fingerprint = hash('sha256', $message . '|' . $exceptionClass . '|' . $file . ':' . $line);

        $context = $context ?? [];
        $context['_ip_hash_used'] = $ipUsed;
        if ($ipKeyId !== null) $context['_ip_hash_key'] = $ipKeyId;
        $jsonContext = self::safeJsonEncode($context);
        $rawUrl = $_SERVER['REQUEST_URI'] ?? null;
        if ($rawUrl !== null) {
            $parts = parse_url($rawUrl);
            if (isset($parts['query'])) {
                parse_str($parts['query'], $q);
                $qClean = self::filterSensitive($q); // použij tvou funkci
                $parts['query'] = http_build_query($qClean);
                // složíme URL zpět
                $cleanUrl = (isset($parts['path']) ? $parts['path'] : '')
                        . (isset($parts['query']) ? '?' . $parts['query'] : '')
                        . (isset($parts['fragment']) ? '#' . $parts['fragment'] : '');
            } else {
                $cleanUrl = $rawUrl;
            }
        } else {
            $cleanUrl = null;
        }

        $sql = "INSERT INTO system_error
            (level, message, exception_class, file, line, stack_trace, token, context, fingerprint, occurrences, user_id, ip_hash, ip_hash_key, user_agent, url, method, http_status, created_at, last_seen)
            VALUES ('error', :message, :exception_class, :file, :line, :stack_trace, :token, :context, :fingerprint, 1, :user_id, :ip_hash, :ip_hash_key, :ua, :url, :method, :status, UTC_TIMESTAMP(), UTC_TIMESTAMP())
            ON DUPLICATE KEY UPDATE occurrences = occurrences + 1, last_seen = UTC_TIMESTAMP(), stack_trace = VALUES(stack_trace)";

        $params = [
            ':message' => $message,
            ':exception_class' => $exceptionClass,
            ':file' => $file,
            ':line' => $line,
            ':stack_trace' => $stack,
            ':token' => $token,
            ':context' => $jsonContext,
            ':fingerprint' => $fingerprint,
            ':user_id' => $userId,
            ':ip_hash' => $ipHash,
            ':ip_hash_key' => $ipKeyId,
            ':ua' => $ua,
            ':url' => $cleanUrl,
            ':method' => $_SERVER['REQUEST_METHOD'] ?? null,
            ':status' => http_response_code() ?: null,
        ];

        if (\Database::isInitialized()) {
            DeferredHelper::flush();
            try {
                \Database::getInstance()->execute($sql, $params);
            } catch (\Throwable $ex) {
                return;
            }
            return;
        }

        DeferredHelper::enqueue(function() use ($sql, $params) {
            try {
                \Database::getInstance()->execute($sql, $params);
            } catch (\Throwable $e) {
                // silent fail – logger nikdy nesmí shodit aplikaci
            }
        });
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