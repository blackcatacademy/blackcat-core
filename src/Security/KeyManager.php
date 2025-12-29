<?php
declare(strict_types=1);

namespace BlackCat\Core\Security;

use Psr\Log\LoggerInterface;
use BlackCat\Core\Database;

class KeyManagerException extends \RuntimeException {}

final class KeyManager
{
    private static ?LoggerInterface $logger = null;
    /** @var null|callable(string):void */
    private static $accessGuard = null;
    private static bool $accessGuardLocked = false;
    private static bool $trustKernelAutoBootAttempted = false;
    private static array $cache = []; // simple per-request cache ['key_<env>_<basename>[_vN]'=> ['raw'=>..., 'version'=>...]]

    private const AGENT_TIMEOUT_SEC = 1;
    private const AGENT_MAX_REQ_BYTES = 8 * 1024;
    private const AGENT_MAX_RESP_BYTES = 256 * 1024;

    private static function cryptoAgentModeFromRuntimeConfig(): ?string
    {
        $socket = self::cryptoAgentSocketPathFromRuntimeConfig();
        if ($socket === null) {
            return null;
        }

        $configClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'Config']);
        if (!class_exists($configClass) || !is_callable([$configClass, 'isInitialized'])) {
            return null;
        }

        $method = 'isInitialized';
        if (!(bool) $configClass::$method()) {
            return null;
        }

        if (!is_callable([$configClass, 'repo'])) {
            return null;
        }

        $repoMethod = 'repo';
        /** @var mixed $repo */
        $repo = $configClass::$repoMethod();

        if (!is_object($repo) || !method_exists($repo, 'get')) {
            return null;
        }

        $get = 'get';
        /** @var mixed $raw */
        $raw = $repo->$get('crypto.agent.mode');
        $mode = is_string($raw) ? strtolower(trim($raw)) : '';
        if ($mode === '') {
            // Security-first default.
            return 'keyless';
        }

        if ($mode === 'keys' || $mode === 'keyless') {
            return $mode;
        }

        return 'keyless';
    }

    private static function cryptoAgentIsKeyless(): bool
    {
        return self::cryptoAgentModeFromRuntimeConfig() === 'keyless';
    }

    private static function cryptoAgentSocketPathFromRuntimeConfig(): ?string
    {
        if (\function_exists('posix_geteuid')) {
            $euid = @\posix_geteuid();
            if (\is_int($euid) && $euid === 0) {
                return null;
            }
        }

        $configClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'Config']);
        if (!class_exists($configClass) || !is_callable([$configClass, 'isInitialized'])) {
            return null;
        }

        $method = 'isInitialized';
        if (!(bool) $configClass::$method()) {
            return null;
        }

        if (!is_callable([$configClass, 'repo'])) {
            return null;
        }

        $repoMethod = 'repo';
        /** @var mixed $repo */
        $repo = $configClass::$repoMethod();

        if (!is_object($repo) || !method_exists($repo, 'get')) {
            return null;
        }

        $get = 'get';
        /** @var mixed $raw */
        $raw = $repo->$get('crypto.agent.socket_path');
        if (!is_string($raw) || trim($raw) === '' || str_contains($raw, "\0")) {
            return null;
        }

        $path = trim($raw);
        if (method_exists($repo, 'resolvePath')) {
            try {
                $path = $repo->resolvePath($path);
            } catch (\Throwable) {
                return null;
            }
        }

        if (!is_string($path)) {
            return null;
        }

        $path = trim($path);
        if ($path === '' || str_contains($path, "\0")) {
            return null;
        }

        return $path;
    }

    /**
     * @param array<string,mixed> $payload
     * @return array<string,mixed>
     */
    private static function agentCall(string $socketPath, array $payload): array
    {
        $socketPath = trim($socketPath);
        if ($socketPath === '' || str_contains($socketPath, "\0")) {
            throw new KeyManagerException('Crypto agent socket path is invalid.');
        }

        $endpoint = 'unix://' . $socketPath;
        $errno = 0;
        $errstr = '';
        $fp = @stream_socket_client($endpoint, $errno, $errstr, (float) self::AGENT_TIMEOUT_SEC, STREAM_CLIENT_CONNECT);
        if (!is_resource($fp)) {
            throw new KeyManagerException('Crypto agent connect failed: ' . ($errstr !== '' ? $errstr : 'unknown'));
        }

        stream_set_timeout($fp, self::AGENT_TIMEOUT_SEC);

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($json)) {
            fclose($fp);
            throw new KeyManagerException('Crypto agent request JSON encode failed.');
        }
        if (strlen($json) > self::AGENT_MAX_REQ_BYTES) {
            fclose($fp);
            throw new KeyManagerException('Crypto agent request is too large.');
        }

        $written = @fwrite($fp, $json . "\n");
        if ($written === false) {
            fclose($fp);
            throw new KeyManagerException('Crypto agent request write failed.');
        }

        $raw = stream_get_contents($fp, self::AGENT_MAX_RESP_BYTES + 1);
        fclose($fp);

        if (!is_string($raw) || $raw === '') {
            throw new KeyManagerException('Crypto agent returned empty response.');
        }
        if (strlen($raw) > self::AGENT_MAX_RESP_BYTES) {
            throw new KeyManagerException('Crypto agent response is too large.');
        }

        $raw = trim($raw);

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new KeyManagerException('Crypto agent returned invalid JSON.', 0, $e);
        }

        if (!is_array($decoded)) {
            throw new KeyManagerException('Crypto agent response must decode to an object/array.');
        }

        /** @var array<string,mixed> $decoded */
        return $decoded;
    }

    /**
     * @return list<array{version:string,raw:string}>
     */
    private static function agentGetAllKeyEntries(?string $socketPath, string $basename, int $wantedLen): array
    {
        if ($socketPath === null) {
            return [];
        }

        if (self::cryptoAgentIsKeyless()) {
            throw new KeyManagerException('Crypto agent is configured in keyless mode; raw key export is forbidden.');
        }

        $basename = trim($basename);
        if ($basename === '') {
            return [];
        }
        if (str_contains($basename, "\0") || !preg_match('/^[a-z0-9_]{1,64}$/', $basename)) {
            throw new KeyManagerException('Invalid key basename for crypto agent.');
        }

        $res = self::agentCall($socketPath, [
            'op' => 'get_all_keys',
            'basename' => $basename,
        ]);

        if (($res['ok'] ?? null) !== true) {
            $err = is_string($res['error'] ?? null) ? (string) $res['error'] : 'unknown';
            throw new KeyManagerException('Crypto agent error: ' . $err);
        }

        $items = $res['keys'] ?? null;
        if (!is_array($items)) {
            throw new KeyManagerException('Crypto agent protocol violation: missing keys list.');
        }

        $out = [];
        foreach ($items as $i => $item) {
            if (!is_array($item)) {
                throw new KeyManagerException('Crypto agent protocol violation: keys[' . $i . '] must be an object.');
            }

            $ver = $item['version'] ?? null;
            $b64 = $item['b64'] ?? null;
            if (!is_string($ver) || !preg_match('/^v[0-9]+$/', $ver)) {
                throw new KeyManagerException('Crypto agent protocol violation: invalid key version.');
            }
            if (!is_string($b64) || $b64 === '' || str_contains($b64, "\0")) {
                throw new KeyManagerException('Crypto agent protocol violation: invalid key b64.');
            }

            $raw = base64_decode($b64, true);
            if (!is_string($raw) || strlen($raw) !== $wantedLen) {
                throw new KeyManagerException('Crypto agent returned key with invalid length.');
            }

            $out[] = ['version' => $ver, 'raw' => $raw];
        }

        return $out;
    }

    /**
     * Keyless agent path: derive a single HMAC using the newest key without exporting key bytes.
     *
     * @return array{hash:string,version:string}
     */
    private static function agentHmacLatest(string $socketPath, string $basename, string $data): array
    {
        if (!self::cryptoAgentIsKeyless()) {
            throw new KeyManagerException('agentHmacLatest called but crypto agent is not in keyless mode.');
        }

        $basename = trim($basename);
        if ($basename === '' || str_contains($basename, "\0") || !preg_match('/^[a-z0-9_]{1,64}$/', $basename)) {
            throw new KeyManagerException('Invalid key basename for crypto agent.');
        }

        $res = self::agentCall($socketPath, [
            'op' => 'hmac_latest',
            'basename' => $basename,
            'data_b64' => base64_encode($data),
        ]);

        if (($res['ok'] ?? null) !== true) {
            $err = is_string($res['error'] ?? null) ? (string) $res['error'] : 'unknown';
            throw new KeyManagerException('Crypto agent error: ' . $err);
        }

        $b64 = $res['hash_b64'] ?? null;
        $ver = $res['key_version'] ?? null;
        if (!is_string($b64) || $b64 === '' || str_contains($b64, "\0")) {
            throw new KeyManagerException('Crypto agent protocol violation: invalid hash_b64.');
        }
        if (!is_string($ver) || !preg_match('/^v[0-9]+$/', $ver)) {
            throw new KeyManagerException('Crypto agent protocol violation: invalid key_version.');
        }

        $hash = base64_decode($b64, true);
        if (!is_string($hash) || strlen($hash) !== 32) {
            throw new KeyManagerException('Crypto agent returned invalid HMAC length.');
        }

        return ['hash' => $hash, 'version' => $ver];
    }

    /**
     * Keyless agent path: derive multiple HMAC candidates (newest->oldest) without exporting key bytes.
     *
     * @return list<array{version:string,hash:string}>
     */
    private static function agentHmacCandidates(string $socketPath, string $basename, string $data, int $maxCandidates): array
    {
        if (!self::cryptoAgentIsKeyless()) {
            throw new KeyManagerException('agentHmacCandidates called but crypto agent is not in keyless mode.');
        }

        $basename = trim($basename);
        if ($basename === '' || str_contains($basename, "\0") || !preg_match('/^[a-z0-9_]{1,64}$/', $basename)) {
            throw new KeyManagerException('Invalid key basename for crypto agent.');
        }

        $maxCandidates = max(1, min(50, $maxCandidates));

        $res = self::agentCall($socketPath, [
            'op' => 'hmac_candidates',
            'basename' => $basename,
            'data_b64' => base64_encode($data),
            'max_candidates' => $maxCandidates,
        ]);

        if (($res['ok'] ?? null) !== true) {
            $err = is_string($res['error'] ?? null) ? (string) $res['error'] : 'unknown';
            throw new KeyManagerException('Crypto agent error: ' . $err);
        }

        $items = $res['hashes'] ?? null;
        if (!is_array($items)) {
            throw new KeyManagerException('Crypto agent protocol violation: missing hashes list.');
        }

        $out = [];
        foreach ($items as $i => $item) {
            if (!is_array($item)) {
                throw new KeyManagerException('Crypto agent protocol violation: hashes[' . $i . '] must be an object.');
            }

            $ver = $item['key_version'] ?? null;
            $b64 = $item['hash_b64'] ?? null;
            if (!is_string($ver) || !preg_match('/^v[0-9]+$/', $ver)) {
                throw new KeyManagerException('Crypto agent protocol violation: invalid key_version.');
            }
            if (!is_string($b64) || $b64 === '' || str_contains($b64, "\0")) {
                throw new KeyManagerException('Crypto agent protocol violation: invalid hash_b64.');
            }

            $hash = base64_decode($b64, true);
            if (!is_string($hash) || strlen($hash) !== 32) {
                throw new KeyManagerException('Crypto agent returned invalid HMAC length.');
            }

            $out[] = ['version' => $ver, 'hash' => $hash];
        }

        return $out;
    }

    public static function setLogger(?LoggerInterface $logger): void
    {
        self::$logger = $logger;
    }

    /**
     * Optional security hook: called before accessing key material.
     *
     * The callable receives an operation string:
     * - "read"  (key reads for decrypt/hmac/etc.)
     * - "write" (key rotation / new key creation)
     *
     * In strict mode the guard should throw to deny access.
     */
    public static function setAccessGuard(?callable $guard): void
    {
        if (self::$accessGuardLocked) {
            throw new KeyManagerException('KeyManager access guard is locked.');
        }
        self::$accessGuard = $guard;
    }

    public static function lockAccessGuard(): void
    {
        if (self::$accessGuard === null) {
            throw new KeyManagerException('KeyManager access guard cannot be locked when not set.');
        }
        self::$accessGuardLocked = true;
    }

    public static function isAccessGuardLocked(): bool
    {
        return self::$accessGuardLocked;
    }

    public static function hasAccessGuard(): bool
    {
        return self::$accessGuard !== null;
    }

    private static function guard(string $operation): void
    {
        if (self::$accessGuardLocked && self::$accessGuard === null) {
            throw new KeyManagerException('KeyManager access guard is locked but missing; restart the process.');
        }

        if (self::$accessGuard === null) {
            self::autoBootTrustKernelIfPossible();
        }

        if (self::$accessGuard === null) {
            return;
        }

        (self::$accessGuard)($operation);
    }

    private static function autoBootTrustKernelIfPossible(): void
    {
        if (self::$trustKernelAutoBootAttempted) {
            return;
        }
        self::$trustKernelAutoBootAttempted = true;

        try {
            // Security-first:
            // - If blackcat-config is installed, treat it as a trust-required deployment and fail-closed.
            // - Otherwise (legacy stacks), best-effort boot when configured.
            $configClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'Config']);
            $repoClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'ConfigRepository']);
            if (class_exists($configClass) && class_exists($repoClass)) {
                \BlackCat\Core\Kernel\KernelBootstrap::bootOrFail(self::getLogger());
                return;
            }

            \BlackCat\Core\Kernel\KernelBootstrap::bootIfConfigured(self::getLogger());
        } catch (\Throwable $e) {
            throw new KeyManagerException('TrustKernel auto-boot failed: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Assert that access is allowed for a security-sensitive operation.
     *
     * This is useful for call sites that use cached key material (e.g. Crypto) and still want
     * fail-closed behavior when the Trust Kernel denies reads/writes.
     *
     * @param 'read'|'write' $operation
     */
    public static function assertAccessAllowed(string $operation): void
    {
        self::guard($operation);
    }

    private static function getLogger(): ?LoggerInterface
    {
        if (self::$logger !== null) {
            return self::$logger;
        }
        if (Database::isInitialized()) {
            try {
                return Database::getInstance()->getLogger();
            } catch (\Throwable $_) {
                return null;
            }
        }
        return null;
    }

    private static function logError(string $message, array $context = []): void
    {
        $logger = self::getLogger();
        if ($logger !== null) {
            try {
                $logger->error($message, $context);
            } catch (\Throwable $_) {}
        }
    }
    /**
     * Return array of all available raw keys (for a basename), newest last.
     * Example return: [binary1, binary2, ...]
     *
     * @param string $envName ENV fallback name (ignored if keysDir+basename used)
     * @param string|null $keysDir directory with keys
     * @param string $basename basename of key files
     * @param int|null $expectedByteLen override expected key length
     * @return array<int,string> raw key bytes
     */
    public static function getAllRawKeys(string $envName, ?string $keysDir, string $basename, ?int $expectedByteLen = null): array
    {
        self::guard('read');
        $wantedLen = $expectedByteLen ?? self::keyByteLen();
        $keys = [];

        $agentSocket = self::cryptoAgentSocketPathFromRuntimeConfig();
        if ($agentSocket !== null && self::cryptoAgentIsKeyless()) {
            throw new KeyManagerException('Crypto agent is configured in keyless mode; raw key export is forbidden.');
        }
        $agentEntries = self::agentGetAllKeyEntries($agentSocket, $basename, $wantedLen);

        // Crypto-agent mode is authoritative (no file/env fallbacks).
        if ($agentSocket !== null) {
            if (trim($basename) === '') {
                throw new KeyManagerException('Key basename is required in crypto-agent mode.');
            }

            foreach ($agentEntries as $e) {
                $keys[] = $e['raw'];
            }

            return $keys;
        }

        if ($keysDir !== null && $basename !== '') {
            $versions = self::listKeyVersions($keysDir, $basename);
            foreach ($versions as $ver => $path) {
                $raw = @file_get_contents($path);
                if ($raw === false || strlen($raw) !== $wantedLen) {
                    throw new KeyManagerException('Key file invalid length: ' . $path);
                }
                $keys[] = $raw;
            }
        }

        // fallback to ENV only if no key files found and env fallback is explicitly allowed
        if (empty($keys) && self::isEnvKeyFallbackAllowed()) {
            $envVal = $_ENV[$envName] ?? '';
            if ($envVal !== '') {
                $raw = base64_decode($envVal, true);
                if ($raw === false || strlen($raw) !== $wantedLen) {
                    throw new KeyManagerException(sprintf('ENV %s invalid base64 or wrong length', $envName));
                }
                $keys[] = $raw;
            }
        }

        return $keys;
    }

    public static function requireSodium(): void
    {
        if (!extension_loaded('sodium')) {
            throw new \RuntimeException('libsodium extension required');
        }
    }

    /**
     * @return int<1, max>
     */
    public static function keyByteLen(): int
    {
        return SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;
    }

    /**
     * Rotate a key file and return metadata.
     *
     * Note: the optional $db parameter (historically a PDO) is ignored.
     * DB logging and key-rotation job orchestration belong to `blackcat-database` and higher-level ops modules.
     */
    public static function rotateKey(string $basename, string $keysDir, mixed $db = null, int $keepVersions = 5, bool $archiveOld = false, ?string $archiveDir = null): array
    {
        self::guard('write');
        self::requireSodium();
        $wantedLen = self::keyByteLen();

        $dir = rtrim($keysDir, '/\\');
        if ($basename === '' || $dir === '') {
            throw new KeyManagerException('rotateKey: basename and keysDir are required');
        }

        // simple lockfile to avoid concurrent rotations
        $lockFile = $dir . '/.keymgr.lock';
        $fp = @fopen($lockFile, 'c');
        if ($fp === false) {
            throw new KeyManagerException('rotateKey: cannot open lockfile ' . $lockFile);
        }
        if (!flock($fp, LOCK_EX)) {
            fclose($fp);
            throw new KeyManagerException('rotateKey: cannot obtain lock');
        }

        try {
            // determine next version
            $versions = self::listKeyVersions($dir, $basename); // oldest->newest
            $next = 1;

            if (!empty($versions)) {
                $max = 0;
                foreach (array_keys($versions) as $k) {
                    if (preg_match('/^v(\d+)$/', $k, $m)) {
                        $num = (int) $m[1];
                        if ($num > $max) $max = $num;
                    }
                }
                $next = $max + 1;
            }

            $target = $dir . '/' . $basename . '_v' . $next . '.key';
            $raw = random_bytes($wantedLen);

            // atomic write (uses existing method)
            self::atomicWriteKeyFile($target, $raw);

            // compute fingerprint for audit (sha256 hex)
            $fingerprint = hash('sha256', $raw);

            // NOTE: DB logging removed (crypto engine must not use raw PDO/SQL). Keep $db only for BC.
            unset($db);

            // optionally cleanup/archive old versions
            try {
                self::cleanupOldVersions($dir, $basename, $keepVersions, $archiveOld, $archiveDir);
            } catch (\Throwable $e) {
                // don't fail rotation; just log
                self::logError('[KeyManager::rotateKey] cleanup failed', ['exception' => $e]);
            }

            // zero raw in memory
            self::memzero($raw);

            // purge cache for the basename (so the next getRawKeyBytes loads the refreshed file)
            self::purgeCacheFor(strtoupper($basename));

            return ['path' => $target, 'version' => 'v' . $next, 'fingerprint' => $fingerprint];
        } finally {
            // release lock
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }

    /**
     * Cleanup or archive old versions, keeping $keepVersions newest.
     * If $archiveOld==true and $archiveDir provided, move older files to archiveDir (create dir if needed),
     * otherwise do nothing (safer default).
     */
    public static function cleanupOldVersions(string $keysDir, string $basename, int $keepVersions = 5, bool $archiveOld = false, ?string $archiveDir = null): void
    {
        $dir = rtrim($keysDir, '/\\');
        $versions = self::listKeyVersions($dir, $basename); // oldest->newest
        if (count($versions) <= $keepVersions) return;

        $toRemove = array_slice(array_keys($versions), 0, count($versions) - $keepVersions);
        foreach ($toRemove as $v) {
            $path = $versions[$v];
            if ($archiveOld) {
                if ($archiveDir === null) {
                    $archiveDir = $dir . '/.archive';
                }
                if (!is_dir($archiveDir)) {
                    if (!@mkdir($archiveDir, 0750, true)) {
                        self::logError('[KeyManager::cleanupOldVersions] archive mkdir failed', ['dir' => $archiveDir]);
                        continue;
                    }
                }
                $dest = rtrim($archiveDir, '/\\') . '/' . basename($path);
                // atomic move
                if (!@rename($path, $dest)) {
                    self::logError('[KeyManager::cleanupOldVersions] archive rename failed', ['path' => $path]);
                    continue;
                }
                @chmod($dest, 0400);
            } else {
                // default SAFE behavior: do NOT delete, only log
                self::logError('[KeyManager::cleanupOldVersions] old key present (not deleted)', ['path' => $path]);
                // Optionally you could check file age and warn
            }
        }
    }

    /**
     * List available versioned key files for a basename (e.g. password_pepper or app_salt).
     * Returns array of versions => fullpath, e.g. ['v1'=>'/keys/app_salt_v1.key','v2'=>...]
     *
     * @param string $keysDir
     * @param string $basename
     * @return array<string,string>
     */
    public static function listKeyVersions(string $keysDir, string $basename): array
    {
        $pattern = rtrim($keysDir, '/\\') . '/' . $basename . '_v*.key';
        $out = [];
        foreach (glob($pattern) ?: [] as $p) {
            if (!is_file($p)) continue;
            if (preg_match('/_v([0-9]+)\.key$/', $p, $m)) {
                $ver = 'v' . (string)(int)$m[1];
                $out[$ver] = $p;
            }
        }
        // natural sort by version number
        if (!empty($out)) {
            uksort($out, function($a, $b){
                return ((int)substr($a,1)) <=> ((int)substr($b,1));
            });
        }
        return $out;
    }

    /**
     * Find latest key file (must be versioned).
     *
     * @return array|null ['path'=>'/full/path','version'=>'v2'] or null
     */
    public static function locateLatestKeyFile(string $keysDir, string $basename): ?array
    {
        $list = self::listKeyVersions($keysDir, $basename);
        if (!empty($list)) {
            $max = 0; $sel = null;
            foreach ($list as $ver => $p) {
                if (preg_match('/^v(\d+)$/', $ver, $m)) {
                    $num = (int)$m[1];
                    if ($num > $max) { $max = $num; $sel = $ver; }
                }
            }
            if ($sel !== null) {
                return ['path' => $list[$sel], 'version' => $sel];
            }
        }

        return null;
    }

    /**
     * Return base64-encoded key (prefer versioned file; else env; optionally generate v1 in dev).
     *
     * @param string $envName name of env var holding base64 encoded key (e.g. 'APP_SALT' or 'PASSWORD_PEPPER')
     * @param string|null $keysDir
     * @param string $basename
     * @param bool $generateIfMissing
     * @return string base64-encoded key
     * @throws \RuntimeException
     */
    public static function getBase64Key(string $envName, ?string $keysDir = null, string $basename = '', bool $generateIfMissing = false, ?int $expectedByteLen = null): string
    {
        self::guard('read');
        self::requireSodium();
        $wantedLen = $expectedByteLen ?? self::keyByteLen();

        $agentSocket = self::cryptoAgentSocketPathFromRuntimeConfig();
        if ($agentSocket !== null && self::cryptoAgentIsKeyless()) {
            throw new KeyManagerException('Crypto agent is configured in keyless mode; base64 key export is forbidden.');
        }
        $agentEntries = self::agentGetAllKeyEntries($agentSocket, $basename, $wantedLen);

        // Crypto-agent mode is authoritative (no file/env fallbacks).
        if ($agentSocket !== null) {
            if (trim($basename) === '') {
                throw new KeyManagerException('Key basename is required in crypto-agent mode.');
            }

            $latest = $agentEntries[count($agentEntries) - 1] ?? null;
            if (is_array($latest) && isset($latest['raw']) && is_string($latest['raw']) && strlen($latest['raw']) === $wantedLen) {
                return base64_encode($latest['raw']);
            }

            throw new KeyManagerException('Key not configured via crypto agent: ' . $envName);
        }

        if ($keysDir !== null && $basename !== '') {
            $info = self::locateLatestKeyFile($keysDir, $basename);
            if ($info !== null) {
                $raw = @file_get_contents($info['path']);
                if ($raw === false || strlen($raw) !== $wantedLen) {
                    throw new KeyManagerException('Key file exists but invalid length: ' . $info['path']);
                }
                return base64_encode($raw);
            }
        }

        $envVal = $_ENV[$envName] ?? '';
        if ($envVal !== '' && self::isEnvKeyFallbackAllowed()) {
            $raw = base64_decode($envVal, true);
            if ($raw === false || strlen($raw) !== $wantedLen) {
                throw new KeyManagerException(sprintf('ENV %s set but invalid base64 or wrong length (expected %d bytes)', $envName, $wantedLen));
            }
            return $envVal;
        }

        if ($generateIfMissing) {
            if ($keysDir === null || $basename === '') {
                throw new KeyManagerException('generateIfMissing requires keysDir and basename');
            }
            // use rotateKey to secure locking + auditing
            $res = self::rotateKey($basename, $keysDir, null, 5, false);
            $raw = @file_get_contents($res['path']);
            if ($raw === false || strlen($raw) !== $wantedLen) {
                throw new KeyManagerException('Failed to read generated key ' . $res['path']);
            }
            return base64_encode($raw);
        }

        throw new KeyManagerException(sprintf('Key not configured: %s (no key file, no env)', $envName));
    }

    /**
     * Return raw key bytes + version. Uses per-request cache to avoid repeated disk reads.
     *
     * @return array{raw:string,version:string}
     */
    public static function getRawKeyBytes(string $envName, ?string $keysDir = null, string $basename = '', bool $generateIfMissing = false, ?int $expectedByteLen = null, ?string $version = null): array
    {
        self::guard('read');
        $wantedLen = $expectedByteLen ?? self::keyByteLen();

        $agentSocket = self::cryptoAgentSocketPathFromRuntimeConfig();
        if ($agentSocket !== null && self::cryptoAgentIsKeyless()) {
            throw new KeyManagerException('Crypto agent is configured in keyless mode; raw key export is forbidden.');
        }
        $agentEntries = self::agentGetAllKeyEntries($agentSocket, $basename, $wantedLen);

        // Crypto-agent mode is authoritative (no file/env fallbacks).
        if ($agentSocket !== null) {
            if (trim($basename) === '') {
                throw new KeyManagerException('Key basename is required in crypto-agent mode.');
            }
            if ($generateIfMissing) {
                throw new KeyManagerException('generateIfMissing is not supported in crypto-agent mode.');
            }

            if ($version !== null) {
                $normalized = 'v' . (string) (int) ltrim($version, 'v');
                foreach ($agentEntries as $e) {
                    if (($e['version'] ?? null) === $normalized) {
                        return ['raw' => $e['raw'], 'version' => $normalized];
                    }
                }

                throw new KeyManagerException('Requested key version not found via crypto agent: ' . $normalized);
            }

            $latest = $agentEntries[count($agentEntries) - 1] ?? null;
            if (is_array($latest) && isset($latest['raw'], $latest['version']) && is_string($latest['raw']) && is_string($latest['version'])) {
                return ['raw' => $latest['raw'], 'version' => $latest['version']];
            }

            throw new KeyManagerException('Key not configured via crypto agent: ' . $envName);
        }

        if ($version !== null && $keysDir !== null && $basename !== '') {
            return self::getRawKeyBytesByVersion($envName, $keysDir, $basename, $version, $expectedByteLen);
        }

        // Obtain base64 representation (files/ENV) — getBase64Key is safe
        $b64 = self::getBase64Key($envName, $keysDir, $basename, $generateIfMissing, $wantedLen);
        $raw = base64_decode($b64, true);
        if ($raw === false) {
            throw new KeyManagerException('Base64 decode failed in KeyManager for ' . $envName);
        }

        // Determine version (metadata) without caching raw bytes
        $ver = null;
        if ($keysDir !== null && $basename !== '') {
            $info = self::locateLatestKeyFile($keysDir, $basename);
            if ($info !== null) $ver = $info['version'];
        }

        // Returns raw bytes — caller MUST memzero + unset after use
        return ['raw' => $raw, 'version' => $ver ?? 'v1'];
    }

    /**
     * Read a specific versioned key file (e.g. 'v2') if present.
     * Returns ['raw'=>'...', 'version'=>'v2'] or throws if not found/invalid.
     *
     * @return array{raw:string,version:string}
     */
    public static function getRawKeyBytesByVersion(string $envName, string $keysDir, string $basename, string $version, ?int $expectedByteLen = null): array
    {
        self::guard('read');
        $version = ltrim($version, 'v'); // accept 'v2' or '2'
        $verStr = 'v' . (string)(int)$version;
        $wantedLen = $expectedByteLen ?? self::keyByteLen();

        $agentSocket = self::cryptoAgentSocketPathFromRuntimeConfig();
        if ($agentSocket !== null && self::cryptoAgentIsKeyless()) {
            throw new KeyManagerException('Crypto agent is configured in keyless mode; raw key export is forbidden.');
        }
        $agentEntries = self::agentGetAllKeyEntries($agentSocket, $basename, $wantedLen);

        // Crypto-agent mode is authoritative (no file/env fallbacks).
        if ($agentSocket !== null) {
            if (trim($basename) === '') {
                throw new KeyManagerException('Key basename is required in crypto-agent mode.');
            }

            foreach ($agentEntries as $e) {
                if (($e['version'] ?? null) === $verStr) {
                    return ['raw' => $e['raw'], 'version' => $verStr];
                }
            }

            throw new KeyManagerException('Requested key version not found via crypto agent: ' . $verStr);
        }

        $path = rtrim($keysDir, '/\\') . '/' . $basename . '_' . $verStr . '.key';
        if (!is_file($path)) {
            throw new KeyManagerException('Requested key version not found: ' . $path);
        }
        $raw = @file_get_contents($path);
        if ($raw === false || strlen($raw) !== $wantedLen) {
            throw new KeyManagerException('Key file invalid or wrong length: ' . $path);
        }

        // NEVER cache raw bytes in self::$cache or any other static property.
        return ['raw' => $raw, 'version' => $verStr];
    }

    /**
     * atomic write + perms (0400) for key files.
     */
    private static function atomicWriteKeyFile(string $path, string $raw): void
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            if (!@mkdir($dir, 0750, true)) {
                throw new \RuntimeException('Failed to create keys directory: ' . $dir);
            }
        }

        $tmp = $path . '.tmp-' . bin2hex(random_bytes(6));
        $written = @file_put_contents($tmp, $raw, LOCK_EX);
        if ($written === false || $written !== strlen($raw)) {
            @unlink($tmp);
            throw new \RuntimeException('Failed to write key temp file');
        }

        @chmod($tmp, 0400);

        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            throw new \RuntimeException('Failed to atomically move key file to destination');
        }

        // ensure correct permissions even after rename
        @chmod($path, 0400);

        clearstatcache(true, $path);
        if (!is_readable($path) || filesize($path) !== strlen($raw)) {
            throw new \RuntimeException('Key file appears corrupted after write');
        }
    }

    /**
     * Overwrite-sensitive string to zeros and clear variable.
     */
    public static function memzero(?string &$s): void
    {
        if ($s === null) {
            return;
        }
        if (function_exists('sodium_memzero')) {
            @sodium_memzero($s);
        } else {
            $s = str_repeat("\0", strlen($s));
        }
        $s = '';
    }

    /**
     * Clear entire per-request key cache and memzero stored raw bytes.
     */
    public static function clearCache(): void
    {
        foreach (self::$cache as $k => &$v) {
            if (is_array($v) && isset($v['raw'])) {
                self::memzero($v['raw']);
            }
            unset(self::$cache[$k]);
        }
        self::$cache = [];
    }

    /**
     * Purge cached keys for a given envName (memzero stored raw bytes).
     * Matches keys by prefix 'key_$envName_...'
     */
    public static function purgeCacheFor(string $envName): void
    {
        $prefix = 'key_' . $envName . '_';
        foreach (self::$cache as $k => &$v) {
            if (strpos($k, $prefix) === 0) {
                if (is_array($v) && isset($v['raw'])) {
                    self::memzero($v['raw']);
                }
                unset(self::$cache[$k]);
            }
        }
    }

    /**
     * Derive single HMAC (binary) using the newest key for the given basename.
     * Returns ['hash' => binary32, 'version' => 'vN'] (throws on error).
     */
    public static function deriveHmacWithLatest(string $envName, ?string $keysDir, string $basename, string $data): array
    {
        self::guard('read');

        $agentSocket = self::cryptoAgentSocketPathFromRuntimeConfig();
        if ($agentSocket !== null && self::cryptoAgentIsKeyless()) {
            $res = self::agentHmacLatest($agentSocket, $basename, $data);
            return ['hash' => $res['hash'], 'version' => $res['version']];
        }

        // key-export mode / file mode: get latest key (fail-fast)
        $info = self::getRawKeyBytes($envName, $keysDir, $basename, false, self::keyByteLen());
        $key = $info['raw'];
        $ver = $info['version'];
        if (!is_string($key) || strlen($key) !== self::keyByteLen()) {
            throw new KeyManagerException('deriveHmacWithLatest: invalid key material');
        }
        $h = hash_hmac('sha256', $data, $key, true);
        // best-effort memzero of copy
        try { self::memzero($key); } catch (\Throwable $_) {}
        return ['hash' => $h, 'version' => $ver];
    }

    /**
     * Produce array of candidate HMACs (binary) computed with available keys (newest -> oldest).
     * Returns array of ['version'=>'vN','hash'=>binary] entries.
     *
     * Added:
     *  - per-request cache (static)
     *  - optional $maxCandidates limit (newest first)
     *  - safer handling of listKeyVersions return types
     *
     * @param string $envName
     * @param string|null $keysDir
     * @param string $basename
     * @param string $data
     * @param int|null $maxCandidates  Max number of candidate hashes to produce (null = no limit)
     * @param bool $useEnvFallback    Whether to attempt ENV fallback if no file keys found
     * @return array
     */
    public static function deriveHmacCandidates(string $envName, ?string $keysDir, string $basename, string $data, ?int $maxCandidates = 20, bool $useEnvFallback = true): array
    {
        self::guard('read');
        static $cache = []; // per-request cache for hashes (we store only result hashes)
        $cacheKey = $envName . '|' . $basename . '|' . hash('sha256', $data);
        if (isset($cache[$cacheKey])) {
            return $cache[$cacheKey];
        }

        $out = [];
        $expectedLen = self::keyByteLen();

        $agentSocket = self::cryptoAgentSocketPathFromRuntimeConfig();
        if ($agentSocket !== null && self::cryptoAgentIsKeyless()) {
            $c = $maxCandidates ?? 20;
            $items = self::agentHmacCandidates($agentSocket, $basename, $data, $c);

            $out = [];
            foreach ($items as $item) {
                $out[] = [
                    'version' => $item['version'],
                    'hash' => $item['hash'],
                ];
            }

            $cache[$cacheKey] = $out;
            return $out;
        }

        $agentEntries = self::agentGetAllKeyEntries($agentSocket, $basename, $expectedLen);

        // Crypto-agent mode is authoritative (no file/env fallbacks).
        if ($agentSocket !== null) {
            if (trim($basename) === '') {
                throw new KeyManagerException('Key basename is required in crypto-agent mode.');
            }

            $count = 0;
            for ($i = count($agentEntries) - 1; $i >= 0; $i--) {
                if ($maxCandidates !== null && $count >= $maxCandidates) {
                    break;
                }

                $entry = $agentEntries[$i] ?? null;
                if (!is_array($entry) || !isset($entry['raw'], $entry['version']) || !is_string($entry['raw']) || !is_string($entry['version'])) {
                    continue;
                }

                $h = hash_hmac('sha256', $data, $entry['raw'], true);
                $out[] = ['version' => $entry['version'], 'hash' => $h];
                $count++;

                try {
                    self::memzero($entry['raw']);
                } catch (\Throwable $_) {
                }
            }

            $cache[$cacheKey] = $out;
            return $out;
        }

        if ($keysDir !== null && $basename !== '') {
            $versions = [];
            try {
                $versions = self::listKeyVersions($keysDir, $basename);
            } catch (\Throwable $_) {
                $versions = [];
            }

            if (!is_array($versions)) $versions = [];
            $vers = array_keys($versions);
            $count = 0;
            for ($i = count($vers) - 1; $i >= 0; $i--) {
                if ($maxCandidates !== null && $count >= $maxCandidates) break;
                $ver = $vers[$i];
                try {
                    // read raw directly (do NOT cache it)
                    $info = self::getRawKeyBytesByVersion($envName, $keysDir, $basename, $ver, $expectedLen);
                    $key = $info['raw'];
                    // compute HMAC
                    $h = hash_hmac('sha256', $data, $key, true);
                    $out[] = ['version' => $ver, 'hash' => $h];
                    $count++;
                    // securely wipe raw bytes from memory
                    try { self::memzero($key); } catch (\Throwable $_) {}
                    unset($key, $info);
                } catch (\Throwable $_) {
                    // skip invalid/errored version
                    continue;
                }
            }
        }

        // fallback to ENV-only (if no files and fallback is explicitly allowed)
        if (empty($out) && $useEnvFallback && self::isEnvKeyFallbackAllowed()) {
            $envVal = $_ENV[$envName] ?? '';
            if ($envVal !== '') {
                $raw = base64_decode($envVal, true);
                if ($raw !== false && strlen($raw) === $expectedLen) {
                    $h = hash_hmac('sha256', $data, $raw, true);
                    $out[] = ['version' => 'env', 'hash' => $h];
                    try { self::memzero($raw); } catch (\Throwable $_) {}
                    unset($raw);
                }
            }
        }

        $cache[$cacheKey] = $out;
        return $out;
    }

    private static function isEnvKeyFallbackAllowed(): bool
    {
        $configClass = implode('\\', ['BlackCat', 'Config', 'Runtime', 'Config']);
        if (!class_exists($configClass) || !is_callable([$configClass, 'repo'])) {
            // Legacy stacks: preserve existing behavior.
            return true;
        }

        try {
            /** @var mixed $repo */
            $repo = $configClass::repo();
            if (!is_object($repo) || !method_exists($repo, 'get')) {
                return false;
            }

            $method = 'get';
            /** @var mixed $val */
            $val = $repo->$method('crypto.allow_env_keys', false);
            return $val === true || $val === 1 || $val === '1';
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Convenience: get binary pepper + version (fail-fast).
     * Returns ['raw'=>binary,'version'=>'vN']
     */
    public static function getPasswordPepperInfo(?string $keysDir = null): array
    {
        $basename = 'password_pepper';
        $info = self::getRawKeyBytes('PASSWORD_PEPPER', $keysDir, $basename, false, 32);
        if (empty($info['raw'])) {
            throw new KeyManagerException('PASSWORD_PEPPER returned empty raw bytes.');
        }
        return $info;
    }

    /**
     * Convenience: legacy getPasswordPepper() for compatibility (returns binary raw only).
     */
    public static function getPasswordPepper(): string
    {
        $info = self::getPasswordPepperInfo();
        return $info['raw'];
    }

    /**
     * Convenience: get SALT (APP_SALT) info (raw bytes + version).
     * Use this for IP hashing.
     */
    public static function getSaltInfo(?string $keysDir = null): array
    {
        $basename = 'app_salt';
        $info = self::getRawKeyBytes('APP_SALT', $keysDir, $basename, false, 32);
        if (empty($info['raw'])) {
            throw new KeyManagerException('APP_SALT returned empty raw bytes.');
        }
        return $info;
    }

    public static function getSessionKeyInfo(?string $keysDir = null): array
    {
        $basename = 'session_key';
        $info = self::getRawKeyBytes('SESSION_KEY', $keysDir, $basename, false, 32);
        if (empty($info['raw'])) {
            throw new KeyManagerException('SESSION_KEY returned empty raw bytes.');
        }
        return $info;
    }

    public static function getIpHashKeyInfo(?string $keysDir = null): array
    {
        $basename = 'ip_hash_key';
        $info = self::getRawKeyBytes('IP_HASH_KEY', $keysDir, $basename, false, 32);
        if (empty($info['raw'])) {
            throw new KeyManagerException('IP_HASH_KEY returned empty raw bytes.');
        }
        return $info;
    }

    public static function getCsrfKeyInfo(?string $keysDir = null): array
    {
        $basename = 'csrf_key';
        $info = self::getRawKeyBytes('CSRF_KEY', $keysDir, $basename, false, 32);
        if (empty($info['raw'])) {
            throw new KeyManagerException('CSRF_KEY returned empty raw bytes.');
        }
        return $info;
    }

    public static function getJwtKeyInfo(?string $keysDir = null): array
    {
        $basename = 'jwt_key';
        $info = self::getRawKeyBytes('JWT_KEY', $keysDir, $basename, false, 32);
        if (empty($info['raw'])) {
            throw new KeyManagerException('JWT_KEY returned empty raw bytes.');
        }
        return $info;
    }

    /**
     * Convenience: get binary key for email content encryption (raw bytes + version).
     * Use for AEAD XChaCha20-Poly1305 encryption of email payloads.
     * Returns ['raw'=>binary,'version'=>'vN']
     */
    public static function getEmailKeyInfo(?string $keysDir = null): array
    {
        $basename = 'email_key';
        $info = self::getRawKeyBytes('EMAIL_KEY', $keysDir, $basename, false, self::keyByteLen());
        if (empty($info['raw'])) {
            throw new KeyManagerException('EMAIL_KEY returned empty raw bytes.');
        }
        return $info;
    }

    /**
     * Convenience: get binary key for email hashing (HMAC) (raw bytes + version).
     * Use for deterministic HMAC-SHA256(email) to allow lookups/uniqueness without plaintext.
     * Returns ['raw'=>binary,'version'=>'vN']
     */
    public static function getEmailHashKeyInfo(?string $keysDir = null): array
    {
        $basename = 'email_hash_key';
        $info = self::getRawKeyBytes('EMAIL_HASH_KEY', $keysDir, $basename, false, self::keyByteLen());
        if (empty($info['raw'])) {
            throw new KeyManagerException('EMAIL_HASH_KEY returned empty raw bytes.');
        }
        return $info;
    }

    public static function getEmailVerificationKeyInfo(?string $keysDir = null): array
    {
        $basename = 'email_verification_key';
        $info = self::getRawKeyBytes('EMAIL_VERIFICATION_KEY', $keysDir, $basename, false, self::keyByteLen());
        if (empty($info['raw'])) {
            throw new KeyManagerException('EMAIL_VERIFICATION_KEY returned empty raw bytes.');
        }
        return $info;
    }

    /**
     * Convenience: get binary key for unsubscribe token HMAC (raw bytes + version).
     * Use for deterministic HMAC-SHA256(unsubscribe_token) to validate unsubscribe links.
     * Returns ['raw'=>binary,'version'=>'vN']
     *
     * @param string|null $keysDir
     * @return array{raw:string,version:string}
     * @throws KeyManagerException
     */
    public static function getUnsubscribeKeyInfo(?string $keysDir = null): array
    {
        $basename = 'unsubscribe_key';
        $info = self::getRawKeyBytes('UNSUBSCRIBE_KEY', $keysDir, $basename, false, self::keyByteLen());
        if (empty($info['raw'])) {
            throw new KeyManagerException('UNSUBSCRIBE_KEY returned empty raw bytes.');
        }
        return $info;
    }

    /**
     * Convenience: get binary key for profile encryption (raw bytes + version).
     * Basename: 'profile_crypto', ENV: 'PROFILE_CRYPTO'.
     * Use this for AEAD encryption of user profile JSON blobs.
     *
     * @param string|null $keysDir
     * @return array{raw:string,version:string}
     * @throws KeyManagerException
     */
    public static function getProfileKeyInfo(?string $keysDir = null): array
    {
        $basename = 'profile_crypto';
        $info = self::getRawKeyBytes('PROFILE_CRYPTO', $keysDir, $basename, false, self::keyByteLen());
        if (empty($info['raw'])) {
            throw new KeyManagerException('PROFILE_CRYPTO returned empty raw bytes.');
        }
        return $info;
    }
}
