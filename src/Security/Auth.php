<?php

declare(strict_types=1);

namespace BlackCat\Core\Security;

use BlackCat\Auth\AuthManager as AuthSdkManager;
use BlackCat\Auth\Config\AuthConfig;
use BlackCat\Auth\Identity\DatabaseUserProvider;
use BlackCat\Auth\Password\PasswordHasher;
use BlackCat\Auth\Token\TokenPair;
use BlackCat\Core\Database;
use BlackCat\Core\Log\Logger;
use BlackCat\Core\Security\EmailHasher\KeyManagerEmailHasher;
use BlackCat\Core\Security\Pepper\KeyManagerPepperProvider;

final class Auth
{
    private static ?PasswordHasher $passwordHasher = null;
    private static ?DatabaseUserProvider $userProvider = null;
    private static ?AuthSdkManager $authManager = null;

    private static function passwordHasher(): PasswordHasher
    {
        if (self::$passwordHasher === null) {
            $keysDir = defined('KEYS_DIR') ? KEYS_DIR : null;
            self::$passwordHasher = new PasswordHasher(new KeyManagerPepperProvider($keysDir));
        }
        return self::$passwordHasher;
    }

    private static function emailHasher(): KeyManagerEmailHasher
    {
        $keysDir = defined('KEYS_DIR') ? KEYS_DIR : null;
        return new KeyManagerEmailHasher($keysDir);
    }

    private static function userProvider(): DatabaseUserProvider
    {
        if (self::$userProvider === null) {
            $pdo = Database::getInstance()->getPdo();
            $options = [
                'table' => $_ENV['BLACKCAT_AUTH_USERS_TABLE'] ?? 'pouzivatelia',
                'id_column' => $_ENV['BLACKCAT_AUTH_ID_COLUMN'] ?? 'id',
                'email_column' => $_ENV['BLACKCAT_AUTH_EMAIL_COLUMN'] ?? 'email',
                'email_hash_column' => $_ENV['BLACKCAT_AUTH_EMAIL_HASH_COLUMN'] ?? 'email_hash',
                'password_column' => $_ENV['BLACKCAT_AUTH_PASSWORD_COLUMN'] ?? 'heslo_hash',
                'pepper_version_column' => $_ENV['BLACKCAT_AUTH_PEPPER_VERSION_COLUMN'] ?? 'heslo_key_version',
                'roles_column' => $_ENV['BLACKCAT_AUTH_ROLES_COLUMN'] ?? 'role',
                'status_column' => $_ENV['BLACKCAT_AUTH_STATUS_COLUMN'] ?? 'is_active',
                'status_active_value' => $_ENV['BLACKCAT_AUTH_STATUS_ACTIVE_VALUE'] ?? 1,
            ];
            self::$userProvider = new DatabaseUserProvider($pdo, self::passwordHasher(), self::emailHasher(), $options);
        }
        return self::$userProvider;
    }

    private static function authManager(): AuthSdkManager
    {
        if (self::$authManager === null) {
            $config = AuthConfig::fromEnv();
            $logger = Database::isInitialized() ? Database::getInstance()->getLogger() : null;
            self::$authManager = AuthSdkManager::boot($config, self::userProvider(), $logger);
        }
        return self::$authManager;
    }
    private static function getDummyHash(): string {
        static $dh = null;
        if ($dh === null) {
            // Use hex string so the input never contains null bytes (bcrypt dislikes NUL)
            try {
                $seed = bin2hex(random_bytes(16)); // 32 ASCII hex chars, no NUL
            } catch (\Throwable $_) {
                // fallback when random_bytes fails: time-based seed (slightly less ideal but safe for dummy)
                $seed = bin2hex(uniqid((string)mt_rand(), true));
            }

            $dh = password_hash($seed, PASSWORD_DEFAULT);
            // extra fallback when password_hash itself fails (returns false)
            if ($dh === false) {
                $dh = password_hash('dummy_fallback_seed', PASSWORD_DEFAULT);
                if ($dh === false) {
                    // emergency fixed hash (only for extreme failure scenarios)
                    $dh = '$2y$10$usesomesillystringforsalt$'; // valid bcrypt-like string for safe comparison
                }
            }
        }
        return $dh;
    }
    /**
     * Safe wrappers for LoginLimiter to avoid fatal errors if limiter API is missing or throws.
     */
    private static function limiterIsBlocked(?string $clientIp): bool
    {
        if (!class_exists(LoginLimiter::class, true) || !method_exists(LoginLimiter::class, 'isBlocked')) {
            return false; // fail-open
        }
        try {
            return (bool) LoginLimiter::isBlocked($clientIp);
        } catch (\Throwable $_) {
            return false; // fail-open
        }
    }

    private static function limiterGetSecondsUntilUnblock(?string $clientIp): int
    {
        if (!class_exists(LoginLimiter::class, true) || !method_exists(LoginLimiter::class, 'getSecondsUntilUnblock')) {
            return 0;
        }
        try {
            return (int) LoginLimiter::getSecondsUntilUnblock($clientIp);
        } catch (\Throwable $_) {
            return 0;
        }
    }

    /**
     * @param string|null $clientIp
     * @param bool $success
     * @param int|null $userId
     * @param string|resource|null $usernameHashBinForAttempt Binary string or null
     */
    private static function limiterRegisterAttempt(?string $clientIp, bool $success, ?int $userId, $usernameHashBinForAttempt): void
    {
        if (!class_exists(LoginLimiter::class, true) || !method_exists(LoginLimiter::class, 'registerAttempt')) {
            return;
        }
        try {
            LoginLimiter::registerAttempt($clientIp, $success, $userId, $usernameHashBinForAttempt);
        } catch (\Throwable $_) {
            // best-effort: ignore limiter failures
        }
    }

    private static function getArgon2Options(): array
    {
        // Defaults (reasonable safe baseline)
        $defaultMemory = 1 << 16; // 64 MiB
        $defaultTime   = 4;
        $defaultThreads= 2;

        // Read env / sanitize
        $mem = isset($_ENV['ARGON_MEMORY_KIB']) ? (int)$_ENV['ARGON_MEMORY_KIB'] : $defaultMemory;
        $time = isset($_ENV['ARGON_TIME_COST']) ? (int)$_ENV['ARGON_TIME_COST'] : $defaultTime;
        $threads = isset($_ENV['ARGON_THREADS']) ? (int)$_ENV['ARGON_THREADS'] : $defaultThreads;

        // Safety caps - tune to your infra
        $maxMemory = 1 << 20; // 1 GiB (in KiB -> 1048576)
        $maxTime = 10;
        $maxThreads = 8;

        // enforce minimums and maximums
        $mem = max(1 << 12, min($mem, $maxMemory)); // min 4 MiB
        $time = max(1, min($time, $maxTime));
        $threads = max(1, min($threads, $maxThreads));

        return [
            'memory_cost' => $mem,
            'time_cost'   => $time,
            'threads'     => $threads,
        ];
    }

    private static function updateEmailHashIdempotent(\PDO $db, int $userId, string $hashBin, string $hashVer): bool
    {
        // update if missing OR version differs
        $sql = 'UPDATE pouzivatelia
                SET email_hash = :h, email_hash_key_version = :v
                WHERE id = :id AND (email_hash IS NULL OR LENGTH(email_hash) = 0 OR email_hash_key_version <> :v_check)';
        $stmt = $db->prepare($sql);

        // bind LOB and strings; bind both :v and :v_check (some PDO drivers don't like reusing same named param)
        $stmt->bindValue(':h', $hashBin, \PDO::PARAM_LOB);
        $stmt->bindValue(':v', $hashVer, \PDO::PARAM_STR);
        $stmt->bindValue(':v_check', $hashVer, \PDO::PARAM_STR);
        $stmt->bindValue(':id', $userId, \PDO::PARAM_INT);

        try {
            $stmt->execute();
            return ($stmt->rowCount() > 0);
        } catch (\Throwable $e) {
            if (class_exists(Logger::class, true)) {
                Logger::error('Auth: email_hash idempotent update failed (likely race)', $userId, ['err' => $e->getMessage()]);
            }
            // swallow - race is acceptable
            return false;
        }
    }

    /**
     * Require KEYS_DIR to be defined and non-empty. Throws RuntimeException otherwise.
     *
     * Use this when the code cannot operate without keys (production behaviour).
     *
     * @return string absolute path to keys dir
     * @throws \RuntimeException if KEYS_DIR isn't defined or is empty
     */
    private static function requireKeysDir(): string
    {
        if (defined('KEYS_DIR') && is_string(KEYS_DIR) && KEYS_DIR !== '') {
            return KEYS_DIR;
        }

        // If you sometimes use environment variable instead of define(), and you want the strict behaviour
        // remove the env check below. For strictness as you requested, we *do not* fallback to env.
        // If you *do* want to accept $_ENV['KEYS_DIR'] as well, uncomment the following lines:
        // $env = $_ENV['KEYS_DIR'] ?? null;
        // if (is_string($env) && $env !== '') return $env;

        throw new \RuntimeException('KEYS_DIR is not defined. Set KEYS_DIR constant in config before calling Auth.');
    }
    /**
     * Get pepper raw bytes + version or throw if unavailable.
     * Production requirement: KeyManager must be present and provide the key.
     *
     * Return: ['raw'=>binary32, 'version'=>'vN']
     * Throws RuntimeException on any missing/invalid key.
     */
    public static function getPepperVersionForStorage(): string
    {
        return 'v1';
    }

    /**
     * Create password hash. Returns hash string (same as password_hash).
     * The caller should store also heslo_algo (see below) — this method returns only the hash.
     */
    public static function hashPassword(string $password): string
    {
        return self::passwordHasher()->hash($password);
    }

    /**
     * Build heslo_algo metadata string to store in DB alongside heslo_hash.
     * Now returns only algorithm name (e.g. "argon2id").
     */
    public static function buildHesloAlgoMetadata(string $hash): string
    {
        return self::passwordHasher()->algorithmName($hash);
    }
    
    public static function verifyPasswordWithVersion(string $password, string $storedHash, ?string $hesloKeyVersion = null): array
    {
        $result = self::passwordHasher()->verify($password, $storedHash, $hesloKeyVersion);
        return ['ok' => $result->isValid(), 'matched_version' => $result->matchedVersion()];
    }

    /**
     * Lookup user by normalized email using HMAC candidates (supports key rotation).
     *
     * Returns:
     *  [
     *    'user' => array|null,                       // DB row or null
     *    'usernameHashBinForAttempt' => string|null, // latest HMAC binary (for LoginLimiter)
     *    'matched_email_hash_version' => string|null // which candidate version matched (if any)
     *  ]
     *
     * This function is defensive: KeyManager or DB failures are logged (if Logger exists)
     * and result in a safe "no user found" rather than a fatal error.
     */
    private static function lookupUserByEmail(\PDO $db, string $emailNormalized): array
    {
        return self::userProvider()->lookupByEmail($emailNormalized);
    }

    /**
     * Login by email + password.
     * Returns associative result:
     *  ['success' => bool, 'user' => array|null, 'message' => string]
     *
     * Note: does NOT create session/cookies - leave that to controller (or integrate SessionManager / JWT here).
     */
    public static function login(\PDO $db, string $email, string $password, int $maxFailed = 5): array
    {
        // basic format validation (NEVER log or persist the plain email)
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            if (class_exists(Logger::class, true)) {
                Logger::auth('login_failure', null);
            }
            usleep(150_000);
            return ['success' => false, 'user' => null, 'message' => 'Invalid login'];
        }

        // Normalise email
        $emailNormalized = trim($email);
        if (class_exists(\Normalizer::class, true)) {
            $emailNormalized = \Normalizer::normalize($emailNormalized, \Normalizer::FORM_C) ?: $emailNormalized;
        }
        $emailNormalized = mb_strtolower($emailNormalized, 'UTF-8');

        // get client IP once (best-effort)
        $clientIp = null;
        try {
            if (class_exists(Logger::class, true) && method_exists(Logger::class, 'getClientIp')) {
                $clientIp = Logger::getClientIp();
            }
        } catch (\Throwable $_) {
            $clientIp = null;
        }

        // limiter check using clientIp (defensive + anonymized logging)
        try {
            if (self::limiterIsBlocked($clientIp)) {
                $secs = self::limiterGetSecondsUntilUnblock($clientIp);

                // anonymize IP for logs: short prefix of HMAC (if available)
                $ipShort = null;
                try {
                    if (class_exists(Logger::class, true) && method_exists(Logger::class, 'getHashedIp')) {
                        $r = Logger::getHashedIp($clientIp);
                        $hb = $r['hash'] ?? null;
                        if (is_string($hb) && strlen($hb) >= 4) {
                            $ipShort = substr(bin2hex($hb), 0, 8); // first 8 hex chars
                        }
                    }
                } catch (\Throwable $_) {
                    $ipShort = null;
                }
                if (class_exists(Logger::class, true)) {
                    if (method_exists(Logger::class, 'info')) {
                        Logger::info('Auth: login blocked by limiter', null, ['ip_sh' => $ipShort, 'wait_s' => $secs]);
                    }
                    if (method_exists(Logger::class, 'auth')) {
                        Logger::auth('login_failure', null);
                    }
                }
                $msg = $secs > 0 ? "Too many attempts. Try again in {$secs} seconds." : "Too many attempts. Try again later.";
                return ['success' => false, 'user' => null, 'message' => $msg];
            }
        } catch (\Throwable $_) {
            // fail-open: if the limiter fails, continue the login flow
        }

// 1) HMAC-based lookup (supports rotation) via centralized helper
$u = null;
$usernameHashBinForAttempt = null;
try {
    // keep the sanity check: KeyManager must exist in production
    if (!class_exists(KeyManager::class, true) || !method_exists(KeyManager::class, 'deriveHmacWithLatest')) {
        // critical misconfiguration -> log and return server error
        if (class_exists(Logger::class, true)) {
            Logger::systemError(new \RuntimeException('KeyManager deriveHmac helpers missing (EMAIL_HASH_KEY)'));
            return ['success' => false, 'user' => null, 'message' => 'Chyba serveru'];
        } else {
            throw new \RuntimeException('KeyManager deriveHmac helpers missing (EMAIL_HASH_KEY)');
        }
    }

    // use the new helper (it is defensive and cached per-request)
    $lookup = self::lookupUserByEmail($db, $emailNormalized);
    $usernameHashBinForAttempt = $lookup['usernameHashBinForAttempt'] ?? null;
    $u = $lookup['user'] ?? null;
} catch (\Throwable $e) {
    if (class_exists(Logger::class, true)) {
        try { Logger::systemError($e); } catch (\Throwable $_) {}
    }
    return ['success' => false, 'user' => null, 'message' => 'Chyba serveru'];
}

        // 2) If user not found or not active/locked -> register failed attempt and return generic failure
        if (!$u || empty($u['is_active']) || !empty($u['is_locked'])) {
            $userId = is_array($u) && isset($u['id']) ? (int)$u['id'] : null;
            // register IP attempt (failure) - best-effort
            self::limiterRegisterAttempt($clientIp, false, $userId, $usernameHashBinForAttempt);

            if (class_exists(Logger::class, true)) {
                if (method_exists(Logger::class, 'auth')) {
                    Logger::auth('login_failure', $userId);
                }
            } else {
                throw new \RuntimeException('Logger required for auth logging');
            }
            usleep(150_000);
            return ['success' => false, 'user' => null, 'message' => 'Invalid login'];
        }

        // 3) Verify password (may require pepper)
        $storedHash = (string)($u['heslo_hash'] ?? '');
        $hesloKeyVersion = isset($u['heslo_key_version']) && $u['heslo_key_version'] !== '' ? (string)$u['heslo_key_version'] : null;

        try {
            $verif = self::verifyPasswordWithVersion($password, $storedHash, $hesloKeyVersion);
            $ok = $verif['ok'];
            $matchedVersion = $verif['matched_version']; // can be used when deciding on rehash

        } catch (\Throwable $e) {
            // critical error (pepper missing etc.)
            if (class_exists(Logger::class, true)) Logger::systemError($e, $u['id'] ?? null);
            return ['success' => false, 'user' => null, 'message' => 'Chyba serveru'];
        }

        if (!$ok) {
            // password incorrect -> increment failed_logins and possibly lock account
            try {
            $stmt = $db->prepare('UPDATE pouzivatelia
                                SET failed_logins = failed_logins + 1,
                                    is_locked = CASE WHEN failed_logins + 1 >= :max THEN 1 ELSE is_locked END
                                WHERE id = :id');
            $stmt->execute([':max' => $maxFailed, ':id' => $u['id']]);

            $stmt = $db->prepare('SELECT failed_logins, is_locked FROM pouzivatelia WHERE id = :id LIMIT 1');
            $stmt->execute([':id' => $u['id']]);
            $row = $stmt->fetch(\PDO::FETCH_ASSOC);
            $failed = (int)($row['failed_logins'] ?? 0);
            $isLocked = !empty($row['is_locked']);
            if ($isLocked) {
                if (class_exists(Logger::class, true)) Logger::auth('lockout', $u['id']);
            } else {
                if (class_exists(Logger::class, true)) Logger::auth('login_failure', $u['id']);
            }
            } catch (\Throwable $e) {
                if (class_exists(Logger::class, true)) Logger::systemError($e, $u['id'] ?? null);
            }

            // register IP limiter failure
            self::limiterRegisterAttempt($clientIp, false, (int)$u['id'], $usernameHashBinForAttempt);

            return ['success' => false, 'user' => null, 'message' => 'Invalid login'];
        }

        // 4) Successful login: reset failed counters, update last_login, and record success in limiter
        $ipHashBin = null;
        $ipKeyId = null;
        try {
            // get IP hash info for storing in users table
            if (!class_exists(Logger::class, true)) throw new \RuntimeException('Logger required for IP hashing helper');
            $ipResult = ['hash' => null, 'key_id' => null];
            if (class_exists(Logger::class, true) && method_exists(Logger::class,'getHashedIp')) {
                try { $ipResult = Logger::getHashedIp($clientIp); } catch (\Throwable $_) { /* keep defaults */ }
            }
            $ipHashBin = $ipResult['hash'] ?? null;
            $ipKeyId = $ipResult['key_id'] ?? null;

            $stmt = $db->prepare('UPDATE pouzivatelia
                                    SET failed_logins = 0,
                                        last_login_at = UTC_TIMESTAMP(),
                                        last_login_ip_hash = :ip_hash,
                                        last_login_ip_key = :ip_key
                                    WHERE id = :id');

            if ($ipHashBin !== null) {
                $stmt->bindValue(':ip_hash', $ipHashBin, \PDO::PARAM_LOB);
            } else {
                $stmt->bindValue(':ip_hash', null, \PDO::PARAM_NULL);
            }
            $stmt->bindValue(':ip_key', $ipKeyId, $ipKeyId !== null ? \PDO::PARAM_STR : \PDO::PARAM_NULL);
            $stmt->bindValue(':id', $u['id'], \PDO::PARAM_INT);
            $stmt->execute();
        } catch (\Throwable $e) {
            if (class_exists(Logger::class, true)) Logger::systemError($e, $u['id'] ?? null);
        }

        // register success attempt in limiter (best-effort)
        self::limiterRegisterAttempt($clientIp, true, (int)$u['id'], $usernameHashBinForAttempt);

        // --- simplified automatic email migration (trusted input: re-encrypt directly) ---
            try {
                $emailToMigrate = $emailNormalized; // already normalized via mb_strtolower(trim(...))
                $keysDir = self::requireKeysDir();

                // 1) email_hash (HMAC) - derive latest and idempotently update
                if ($emailToMigrate !== '' && class_exists(KeyManager::class, true)) {
                    try {
                        $hinfo = KeyManager::deriveHmacWithLatest('EMAIL_HASH_KEY', $keysDir, 'email_hash_key', $emailToMigrate);
                        $hashBin = $hinfo['hash'] ?? null;
                        $hashVer = $hinfo['version'] ?? 'v1';

                        if ($hashBin !== null) {
                            // updateEmailHashIdempotent should be idempotent (uses LENGTH(...) checks)
                            // if your function still doesn't return bool, you can keep it void — we still call it.
                            $didUpdate = self::updateEmailHashIdempotent($db, (int)$u['id'], $hashBin, $hashVer);
                            if ($didUpdate) {
                                if (class_exists(Logger::class, true)) {
                                    Logger::info('Auth: email_hash updated', $u['id'], ['ver' => $hashVer]);
                                }
                            }
                        }
                    } catch (\Throwable $e) {
                        if (class_exists(Logger::class, true)) Logger::error('Auth: email_hash derive failed', $u['id'] ?? null, ['exception' => (string)$e]);
                        // non-fatal
                    }
                }

                // 2) email_enc (AEAD) - simple re-encrypt of trusted normalized email with current key
                if ($emailToMigrate !== '' && class_exists(KeyManager::class, true) && class_exists(Crypto::class, true) && function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')) {
                    try {
                        $ek = null;
                        try {
                            $ek = KeyManager::getEmailKeyInfo($keysDir); // ['raw','version']
                        } catch (\Throwable $_) {
                            $ek = null;
                        }

                        $curEmailKeyRaw = $ek['raw'] ?? null;
                        $curEmailKeyVer = $ek['version'] ?? null;
                        $dbEmailKeyVer = $u['email_key_version'] ?? null;
                        $hasEnc = isset($u['email_enc']) && $u['email_enc'] !== null && strlen((string)$u['email_enc']) > 0;

                        // If current key available and either missing enc or version mismatch, re-encrypt directly
                        if (is_string($curEmailKeyRaw) && strlen($curEmailKeyRaw) === KeyManager::keyByteLen()
                            && ($hasEnc === false || $dbEmailKeyVer !== $curEmailKeyVer)) {

                            // encrypt normalized email (we trust it's the same email verified earlier)
                            try {
                                $encPayload = Crypto::encryptWithKeyBytes($emailToMigrate, $curEmailKeyRaw, 'binary');

                                $upd = $db->prepare('UPDATE pouzivatelia
                                                    SET email_enc = :enc, email_key_version = :kv
                                                    WHERE id = :id AND (email_enc IS NULL OR LENGTH(email_enc) = 0 OR email_key_version <> :kv_check)');

                                $upd->bindValue(':enc', $encPayload, \PDO::PARAM_LOB);

                                // bind both versions because :kv was used twice in SQL originally
                                if ($curEmailKeyVer === null) {
                                    $upd->bindValue(':kv', null, \PDO::PARAM_NULL);
                                    $upd->bindValue(':kv_check', null, \PDO::PARAM_NULL);
                                } else {
                                    $upd->bindValue(':kv', $curEmailKeyVer, \PDO::PARAM_STR);
                                    $upd->bindValue(':kv_check', $curEmailKeyVer, \PDO::PARAM_STR);
                                }
                                $upd->bindValue(':id', $u['id'], \PDO::PARAM_INT);

                                try {
                                    $upd->execute();
                                    if (class_exists(Logger::class, true)) {
                                        if ($upd->rowCount() > 0) {
                                            Logger::info('Auth: email_enc re-encrypted (simple path)', $u['id'], ['ver' => $curEmailKeyVer]);
                                        } else {
                                            Logger::info('Auth: email_enc re-encrypt not needed', $u['id'], ['db_ver' => $dbEmailKeyVer, 'cur_ver' => $curEmailKeyVer]);
                                        }
                                    }
                                } catch (\Throwable $e) {
                                    if (class_exists(Logger::class, true)) Logger::error('Auth: email_enc DB update failed', $u['id'], ['exception' => (string)$e]);
                                }
                            } catch (\Throwable $e) {
                                if (class_exists(Logger::class, true)) Logger::error('Auth: email encryption failed (simple path)', $u['id'] ?? null, ['exception' => (string)$e]);
                            } finally {
                                try { KeyManager::memzero($curEmailKeyRaw); } catch (\Throwable $_) {}
                            }
                        }
                    } catch (\Throwable $e) {
                        if (class_exists(Logger::class, true)) Logger::error('Auth: email simple migration failed', $u['id'] ?? null, ['exception' => (string)$e]);
                    }
                }
            } catch (\Throwable $e) {
                if (class_exists(Logger::class, true)) Logger::error('Auth: email migration on login failed (outer simple path)', $u['id'] ?? null, ['exception' => (string)$e]);
            }
            // --- end simplified migration ---

        // --- perform rehashing outside a transaction when necessary ---
        $needRehash = password_needs_rehash($storedHash, PASSWORD_ARGON2ID, self::getArgon2Options());
        try {
            $currentPepver = self::getPepperVersionForStorage();
        } catch (\Throwable $inner) {
            $currentPepver = $hesloKeyVersion; // fallback
        }
        
        $newHash = null;
        $newAlgoMeta = null;
        $newPepver = null;
        if ($needRehash || $matchedVersion !== $currentPepver) {
            $newHash = self::hashPassword($password);
            $newAlgoMeta = self::buildHesloAlgoMetadata($newHash);
            $newPepver = $currentPepver;
        }

        // --- atomic transaction: reset failed count + last_login + optional password update ---
        try {
            $db->beginTransaction();

            $stmt = $db->prepare('UPDATE pouzivatelia
                                    SET failed_logins = 0,
                                        last_login_at = UTC_TIMESTAMP(),
                                        last_login_ip_hash = :ip_hash,
                                        last_login_ip_key = :ip_key
                                    WHERE id = :id');
            if ($ipHashBin !== null) {
                $stmt->bindValue(':ip_hash', $ipHashBin, \PDO::PARAM_LOB);
            } else {
                $stmt->bindValue(':ip_hash', null, \PDO::PARAM_NULL);
            }
            $stmt->bindValue(':ip_key', $ipKeyId, $ipKeyId !== null ? \PDO::PARAM_STR : \PDO::PARAM_NULL);
            $stmt->bindValue(':id', $u['id'], \PDO::PARAM_INT);
            $stmt->execute();

            if ($newHash !== null) {
                if ($newPepver !== null) {
                    $sth = $db->prepare('UPDATE pouzivatelia SET heslo_hash = :hash, heslo_algo = :meta, heslo_key_version = :pep WHERE id = :id');
                    $sth->bindValue(':hash', $newHash, \PDO::PARAM_STR);
                    $sth->bindValue(':meta', $newAlgoMeta, \PDO::PARAM_STR);
                    $sth->bindValue(':pep', $newPepver, \PDO::PARAM_STR);
                    $sth->bindValue(':id', $u['id'], \PDO::PARAM_INT);
                    $sth->execute();
                } else {
                    $sth = $db->prepare('UPDATE pouzivatelia SET heslo_hash = :hash, heslo_algo = :meta WHERE id = :id');
                    $sth->bindValue(':hash', $newHash, \PDO::PARAM_STR);
                    $sth->bindValue(':meta', $newAlgoMeta, \PDO::PARAM_STR);
                    $sth->bindValue(':id', $u['id'], \PDO::PARAM_INT);
                    $sth->execute();
                }
            }

            $db->commit();
            // wipe sensitive temporaries
            if (isset($newHash)) { unset($newHash); }
            if (isset($newAlgoMeta)) { unset($newAlgoMeta); }
            if (isset($newPepver)) { unset($newPepver); }
        } catch (\Throwable $e) {
            if ($db->inTransaction()) { try { $db->rollBack(); } catch (\Throwable $_) {} }
            if (class_exists(Logger::class, true)) Logger::systemError($e, $u['id'] ?? null);
        }

        if (class_exists(Logger::class, true)) Logger::auth('login_success', $u['id']);

        $allowed = ['id','actor_type','is_active','last_login_at']; // extend intentionally
        $uSafe = [];
        foreach ($allowed as $k) {
            if (array_key_exists($k, $u)) $uSafe[$k] = $u[$k];
        }
        // hygiene: remove sensitive temporaries from local scope
        try { unset($password, $emailNormalized, $usernameHashBinForAttempt); } catch (\Throwable $_) {}
        return ['success' => true, 'user' => $uSafe, 'message' => 'OK'];

    }

    /**
     * Check if user is admin by actor_type
     */
    public static function isAdmin(array $userData): bool
    {
        return isset($userData['actor_type']) && $userData['actor_type'] === 'admin';
    }

    public static function issueTokens(string $username, string $password): TokenPair
    {
        return self::authManager()->issueTokens($username, $password);
    }

    public static function verifyAccessToken(string $token): array
    {
        return self::authManager()->verifyAccessToken($token);
    }

    public static function refreshTokens(string $refreshToken): TokenPair
    {
        return self::authManager()->refresh($refreshToken);
    }
}
