<?php
declare(strict_types=1);
// Custom exception for KeyManager errors
class KeyManagerException extends \RuntimeException {}

final class KeyManager
{
    private const DEFAULT_PER_REQUEST_CACHE_TTL = 300; // seconds, but here just per-request static cache

    private static array $cache = []; // simple per-request cache ['key_<env>_<basename>[_vN]'=> ['raw'=>..., 'version'=>...]]
    
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
        $wantedLen = $expectedByteLen ?? self::keyByteLen();
        $keys = [];

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

        // fallback to ENV only if no key files found
        if (empty($keys)) {
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
            throw new RuntimeException('libsodium extension required');
        }
    }

    public static function keyByteLen(): int
    {
        return SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;
    }

    public static function rotateKey(string $basename, string $keysDir, ?PDO $pdo = null, int $keepVersions = 5, bool $archiveOld = false, ?string $archiveDir = null): array
    {
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

            $target = $dir . '/' . $basename . '_v' . $next . '.bin';
            $raw = random_bytes($wantedLen);

            // atomic write (uses existing method)
            self::atomicWriteKeyFile($target, $raw);

            // compute fingerprint for audit (sha256 hex)
            $fingerprint = hash('sha256', $raw);

            // Log to DB key_events / key_rotation_jobs if PDO provided (best-effort)
            if ($pdo !== null) {
                try {
                    // insert key_events
                    $stmt = $pdo->prepare("INSERT INTO key_events (key_id, basename, event_type, actor_id, note, meta, source) VALUES (NULL, :basename, 'rotated', NULL, :note, :meta, 'rotation')");
                    $meta = json_encode(['filename' => basename($target), 'fingerprint' => $fingerprint]);
                    $stmt->execute([':basename' => $basename, ':note' => 'Automatic rotation', ':meta' => $meta]);
                } catch (PDOException $e) {
                    // log but continue — rotation already created file
                    error_log('[KeyManager::rotateKey] DB log failed: ' . $e->getMessage());
                }
            }

            // optionally cleanup/archive old versions
            try {
                self::cleanupOldVersions($dir, $basename, $keepVersions, $archiveOld, $archiveDir);
            } catch (\Throwable $e) {
                // don't fail rotation; just log
                error_log('[KeyManager::rotateKey] cleanup failed: ' . $e->getMessage());
            }

            // zero raw in memory
            self::memzero($raw);

            // purge cache pro daný basename (aby se další getRawKeyBytes načetl nový soubor)
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
                        error_log('[KeyManager::cleanupOldVersions] archive mkdir failed: ' . $archiveDir);
                        continue;
                    }
                }
                $dest = rtrim($archiveDir, '/\\') . '/' . basename($path);
                // atomic move
                if (!@rename($path, $dest)) {
                    error_log('[KeyManager::cleanupOldVersions] archive rename failed: ' . $path);
                    continue;
                }
                @chmod($dest, 0400);
            } else {
                // default SAFE behavior: do NOT delete, only log
                error_log('[KeyManager::cleanupOldVersions] old key present (not deleted): ' . $path);
                // Optionally you could check file age and warn
            }
        }
    }

    /**
     * List available versioned key files for a basename (e.g. password_pepper or app_salt).
     * Returns array of versions => fullpath, e.g. ['v1'=>'/keys/app_salt_v1.bin','v2'=>...]
     *
     * @param string $keysDir
     * @param string $basename
     * @return array<string,string>
     */
    public static function listKeyVersions(string $keysDir, string $basename): array
    {
        $pattern = rtrim($keysDir, '/\\') . '/' . $basename . '_v*.bin';
        $out = [];
        foreach (glob($pattern) as $p) {
            if (!is_file($p)) continue;
            if (preg_match('/_v([0-9]+)\.bin$/', $p, $m)) {
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
     * Find latest key file or fallback exact basename.bin
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

        $exact = rtrim($keysDir, '/\\') . '/' . $basename . '.bin';
        if (is_file($exact)) {
            return ['path' => $exact, 'version' => 'v1'];
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
     * @throws RuntimeException
     */
    public static function getBase64Key(string $envName, ?string $keysDir = null, string $basename = '', bool $generateIfMissing = false, ?int $expectedByteLen = null): string
    {
        self::requireSodium();
        $wantedLen = $expectedByteLen ?? self::keyByteLen();

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
        if ($envVal !== '') {
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
            // použijeme rotateKey pro lock + audit
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
        if ($version !== null && $keysDir !== null && $basename !== '') {
            return self::getRawKeyBytesByVersion($envName, $keysDir, $basename, $version, $expectedByteLen);
        }

        $wantedLen = $expectedByteLen ?? self::keyByteLen();

        // Získáme base64 reprezentaci (soubory/ENV) — getBase64Key je bezpečné
        $b64 = self::getBase64Key($envName, $keysDir, $basename, $generateIfMissing, $wantedLen);
        $raw = base64_decode($b64, true);
        if ($raw === false) {
            throw new KeyManagerException('Base64 decode failed in KeyManager for ' . $envName);
        }

        // Zjistíme verzi (metadata) bez ukládání raw do cache
        $ver = null;
        if ($keysDir !== null && $basename !== '') {
            $info = self::locateLatestKeyFile($keysDir, $basename);
            if ($info !== null) $ver = $info['version'];
        }

        // VRATÍ raw — caller JE POVINEN memzero + unset po použití
        return ['raw' => $raw, 'version' => $ver ?? 'v1'];
    }

    /**
     * Read a specific versioned key file (e.g. 'v2') if present.
     * Returns ['raw'=>'...', 'version'=>'v2'] or throws if not found/invalid.
     */
    public static function getRawKeyBytesByVersion(string $envName, string $keysDir, string $basename, string $version, ?int $expectedByteLen = null): array
    {
        $version = ltrim($version, 'v'); // accept 'v2' or '2'
        $verStr = 'v' . (string)(int)$version;
        $path = rtrim($keysDir, '/\\') . '/' . $basename . '_' . $verStr . '.bin';
        if (!is_file($path)) {
            throw new KeyManagerException('Requested key version not found: ' . $path);
        }
        $raw = @file_get_contents($path);
        $wantedLen = $expectedByteLen ?? self::keyByteLen();
        if ($raw === false || strlen($raw) !== $wantedLen) {
            throw new KeyManagerException('Key file invalid or wrong length: ' . $path);
        }

        // NECACHEUJ raw v self::$cache ani v jiném statickém poli.
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
                throw new RuntimeException('Failed to create keys directory: ' . $dir);
            }
        }

        $tmp = $path . '.tmp-' . bin2hex(random_bytes(6));
        $written = @file_put_contents($tmp, $raw, LOCK_EX);
        if ($written === false || $written !== strlen($raw)) {
            @unlink($tmp);
            throw new RuntimeException('Failed to write key temp file');
        }

        @chmod($tmp, 0400);

        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            throw new RuntimeException('Failed to atomically move key file to destination');
        }

        // zajistíme správná práva i po rename
        @chmod($path, 0400);

        clearstatcache(true, $path);
        if (!is_readable($path) || filesize($path) !== strlen($raw)) {
            throw new RuntimeException('Key file appears corrupted after write');
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
        // get latest key (fail-fast)
        $info = self::getRawKeyBytes($envName, $keysDir, $basename, false, self::keyByteLen());
        $key = $info['raw'];
        $ver = $info['version'] ?? null;
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
        static $cache = []; // per-request cache for hashes (we store only result hashes)
        $cacheKey = $envName . '|' . $basename . '|' . hash('sha256', $data);
        if (isset($cache[$cacheKey])) {
            return $cache[$cacheKey];
        }

        $out = [];
        $expectedLen = self::keyByteLen();

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
                    // načteme raw přímo (NECACHEJME ho)
                    $info = self::getRawKeyBytesByVersion($envName, $keysDir, $basename, $ver, $expectedLen);
                    $key = $info['raw'];
                    // spočteme HMAC
                    $h = hash_hmac('sha256', $data, $key, true);
                    $out[] = ['version' => $ver, 'hash' => $h];
                    $count++;
                    // bezpečně vymažeme raw v paměti
                    try { self::memzero($key); } catch (\Throwable $_) {}
                    unset($key, $info);
                } catch (\Throwable $_) {
                    // skip invalid/errored version
                    continue;
                }
            }
        }

        // fallback to ENV-only (if no files and useEnvFallback is true)
        if (empty($out) && $useEnvFallback) {
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