<?php
declare(strict_types=1);

/**
 * libs/FileVault.php
 *
 * Secure file-at-rest helper using libsodium (PHP 8.1+).
 * - Uses KeyManager for key retrieval (versioned keys supported)
 * - Writes canonical binary payload and .meta including key_version & encryption_algo
 * - Supports streaming (secretstream) for large files
 * - Calls AuditLogger::log() after successful downloads (best-effort)
 *
 * Public API:
 *   FileVault::uploadAndEncrypt(string $srcTmp, string $destEnc): string|false
 *   FileVault::decryptAndStream(string $encPath, string $downloadName, string $mimeType = 'application/octet-stream'): bool
 *   FileVault::deleteFile(string $path): bool
 */

final class FileVault
{
    private const VERSION = 1;
    private const STREAM_THRESHOLD = 20 * 1024 * 1024; // 20 MB
    private const FRAME_SIZE = 1 * 1024 * 1024; // 1 MB

    /* -------- configuration / dependency injection (no getenv / no $GLOBALS) -------- */
    /** @var string|null explicitně nastavený keys dir */
    private static ?string $keysDir = null;
    /** @var string|null explicitně nastavený storage base */
    private static ?string $storageBase = null;
    /** @var string|null explicitně nastavený audit dir */
    private static ?string $auditDir = null;
    /** @var PDO|null explicitně nastavené PDO pro audit (optional) */
    private static ?\PDO $auditPdo = null;
    /**
     * actor provider: callable(): string|null
     * Výchozí null = 'guest' (nevoláme session_start() uvnitř knihovny).
     */
    /** @var callable|null actor provider: callable(): string|null */
    private static $actorProvider = null;

    public static function setKeysDir(string $dir): void
    {
        self::$keysDir = rtrim($dir, DIRECTORY_SEPARATOR);
    }

    public static function setStorageBase(string $dir): void
    {
        self::$storageBase = rtrim($dir, DIRECTORY_SEPARATOR);
    }

    public static function setAuditDir(string $dir): void
    {
        self::$auditDir = rtrim($dir, DIRECTORY_SEPARATOR);
    }

    public static function setAuditPdo(\PDO $pdo): void
    {
        self::$auditPdo = $pdo;
    }

    /**
     * setActorProvider: callable that returns actor id (string) or null.
     * Example: FileVault::setActorProvider(fn() => $_SESSION['user_id'] ?? null);
     */
    public static function setActorProvider(callable $cb): void
    {
        self::$actorProvider = $cb;
    }

    /**
     * Convenience configure() to set multiple options from bootstrap.
     */
    public static function configure(array $opts): void
    {
        if (!empty($opts['keys_dir'])) self::setKeysDir($opts['keys_dir']);
        if (!empty($opts['storage_base'])) self::setStorageBase($opts['storage_base']);
        if (!empty($opts['audit_dir'])) self::setAuditDir($opts['audit_dir']);
        if (!empty($opts['audit_pdo']) && $opts['audit_pdo'] instanceof \PDO) self::setAuditPdo($opts['audit_pdo']);
        if (!empty($opts['actor_provider']) && is_callable($opts['actor_provider'])) self::setActorProvider($opts['actor_provider']);
    }


    /**
     * Resolve keys directory. Priority:
     * 1) $_ENV['FILEVAULT_KEYS_PATH'] or $_ENV['PATH_KEYS'] or $_ENV['KEYS_PATH']
     * 2) $GLOBALS['config']['paths']['keys'] (fallback if present)
     * 3) default __DIR__.'/../secure/keys'
     */
    private static function getKeysDir(): string
    {
        if (self::$keysDir !== null) {
            return self::$keysDir;
        }

        // pokud není explicitně nastaveno, použij bezpečný default relativně k projektu
        $default = __DIR__ . '/../secure/keys';
        return $default;
    }

    private static function getStorageBase(): string
    {
        if (self::$storageBase !== null) {
            return self::$storageBase;
        }

        // bezpečný default
        return __DIR__ . '/../secure/storage';
    }

    private static function getAuditDir(): string
    {
        if (self::$auditDir !== null) {
            return self::$auditDir;
        }

        // pokud není explicitní audit dir, vytvoříme audit pod storage
        $storage = self::getStorageBase();
        return rtrim($storage, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'audit';
    }


    /**
     * Helper: get key raw bytes and version for filevault keys.
     * If $specificVersion provided (like 'v1'), try to load exact file: filevault_key_v1.bin
     * Returns ['raw' => <bytes>, 'version' => 'vN']
     * Throws RuntimeException on failure.
     */
    private static function getFilevaultKeyInfo(?string $specificVersion = null): array
    {
        $keysDir = self::getKeysDir();

        // If specific version requested, attempt to load exact file
        if ($specificVersion !== null && $specificVersion !== '') {
            $verNum = ltrim($specificVersion, 'vV');
            if ($verNum === '') $verNum = '1';
            $path = rtrim($keysDir, '/\\') . '/filevault_key_v' . $verNum . '.bin';
            if (is_readable($path)) {
                $raw = @file_get_contents($path);
                if ($raw !== false && strlen($raw) === SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) {
                    return ['raw' => $raw, 'version' => 'v' . $verNum];
                }
            }
            // fallback: try non-versioned name
            $path2 = rtrim($keysDir, '/\\') . '/filevault_key.bin';
            if (is_readable($path2)) {
                $raw = @file_get_contents($path2);
                if ($raw !== false && strlen($raw) === SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) {
                    return ['raw' => $raw, 'version' => 'v1'];
                }
            }

            if (isset($raw) && strlen($raw) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) {
                throw new RuntimeException('Invalid key length for FileVault');
            }
            // else fallthrough to KeyManager locateLatest
        }

        // Use KeyManager (pass explicit keys dir)
        try {
            $info = KeyManager::getRawKeyBytes('FILEVAULT_KEY', self::getKeysDir(), 'filevault_key', false);
            if (!is_array($info) || !isset($info['raw'])) {
                throw new RuntimeException('KeyManager did not return key info');
            }
            return ['raw' => $info['raw'], 'version' => $info['version'] ?? 'v1'];
        } catch (Throwable $e) {
            // do not leak internal exception messages — rethrow a generic runtime exception
            throw new RuntimeException('getFilevaultKeyInfo failure');
        }
    }

    /**
     * Encrypt uploaded file and write canonical binary payload to destination.
     * Returns destination path on success, or false on error.
     *
     * @param string $srcTmp
     * @param string $destEnc
     * @return string|false
     */
    public static function uploadAndEncrypt(string $srcTmp, string $destEnc)
    {
        if (!is_readable($srcTmp)) {
            self::logError('uploadAndEncrypt: source not readable: ' . $srcTmp);
            return false;
        }

        // try to get key info (throws on fatal)
        try {
            $keyInfo = self::getFilevaultKeyInfo(null);
            $key = $keyInfo['raw'];
            $keyVersion = $keyInfo['version'];
        } catch (Throwable $e) {
            self::logError('uploadAndEncrypt: key retrieval failed: ' . $e->getMessage());
            return false;
        }

        $filesize = filesize($srcTmp) ?: 0;
        $destDir = dirname($destEnc);
        if (!is_dir($destDir)) {
            if (!mkdir($destDir, 0750, true) && !is_dir($destDir)) {
                self::logError('uploadAndEncrypt: failed to create destination directory: ' . $destDir);
                // wipe key before returning
                if (isset($key) && is_string($key)) { KeyManager::memzero($key); }
                return false;
            }
        }

        // place tmp in same dir for atomic rename where possible
        $tmpDest = $destDir . DIRECTORY_SEPARATOR . '.tmp-' . bin2hex(random_bytes(6)) . '.enc';

        $out = fopen($tmpDest, 'wb');
        if ($out === false) {
            self::logError('uploadAndEncrypt: cannot open destination for write: ' . $tmpDest);
            if (isset($key) && is_string($key)) { KeyManager::memzero($key); }
            return false;
        }

        // ensure we wipe key and close handles in all cases
        $in = null;
        $success = false;
        try {
            // write version byte
            if (fwrite($out, chr(self::VERSION)) === false) {
                throw new RuntimeException('failed writing version byte');
            }

            $useStream = ($filesize > self::STREAM_THRESHOLD);

            if ($useStream) {
                // secretstream init_push
                $res = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
                if (!is_array($res) || count($res) !== 2) {
                    throw new RuntimeException('secretstream init_push failed');
                }
                [$state, $header] = $res;
                if (!is_string($header) || strlen($header) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
                    throw new RuntimeException('secretstream header invalid length');
                }

                $iv_len = strlen($header);
                if ($iv_len > 255) throw new RuntimeException('header too long');

                if (fwrite($out, chr($iv_len)) === false || fwrite($out, $header) === false) {
                    throw new RuntimeException('failed writing header');
                }

                // tag_len == 0 marks secretstream mode
                if (fwrite($out, chr(0)) === false) throw new RuntimeException('failed writing tag_len');

                $in = fopen($srcTmp, 'rb');
                if ($in === false) throw new RuntimeException('cannot open source for read: ' . $srcTmp);

                while (!feof($in)) {
                    $chunk = fread($in, self::FRAME_SIZE);
                    if ($chunk === false) throw new RuntimeException('read error from source');
                    $isFinal = feof($in);
                    $tag = $isFinal ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
                    $frame = sodium_crypto_secretstream_xchacha20poly1305_push($state, $chunk, '', $tag);
                    if ($frame === false) throw new RuntimeException('secretstream push failed');

                    $frameLen = strlen($frame);
                    $lenBuf = pack('N', $frameLen);
                    if (fwrite($out, $lenBuf) === false || fwrite($out, $frame) === false) {
                        throw new RuntimeException('write error while writing frame');
                    }
                }

                // flush buffers
                fflush($out);
                fclose($in); $in = null;
                fclose($out); $out = null; // we'll set permissions and rename below

                // write meta atomically
                $meta = [
                    'plain_size' => $filesize,
                    'mode' => 'stream',
                    'version' => self::VERSION,
                    'key_version' => $keyVersion,
                    'encryption_algo' => 'secretstream_xchacha20poly1305'
                ];
                $metaJson = json_encode($meta, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                if ($metaJson === false) throw new RuntimeException('meta json encode failed');

                $metaTmp = $tmpDest . '.meta';
                if (file_put_contents($metaTmp, $metaJson, LOCK_EX) === false) {
                    @unlink($metaTmp);
                    throw new RuntimeException('failed writing meta temp file');
                }
                chmod($metaTmp, 0600);

                chmod($tmpDest, 0600);

                // atomic move with fallback
                if (!@rename($tmpDest, $destEnc)) {
                    // rename might fail across devices — fallback to copy+unlink
                    if (!copy($tmpDest, $destEnc) || !unlink($tmpDest)) {
                        @unlink($tmpDest);
                        @unlink($metaTmp);
                        throw new RuntimeException('failed to move tmp file to destination');
                    }
                }
                // move meta
                if (!@rename($metaTmp, $destEnc . '.meta')) {
                    // try copy+unlink fallback
                    if (!copy($metaTmp, $destEnc . '.meta') || !unlink($metaTmp)) {
                        // non-fatal: data is in place, meta failed — log and continue
                        self::logError('uploadAndEncrypt: meta move failed for ' . $destEnc . '.meta');
                    } else {
                        chmod($destEnc . '.meta', 0600);
                    }
                } else {
                    chmod($destEnc . '.meta', 0600);
                }

                $success = true;
                return $destEnc;
            }

            // SINGLE-PASS small file
            $plaintext = file_get_contents($srcTmp);
            if ($plaintext === false) throw new RuntimeException('failed to read small source into memory');

            // AEAD encrypt
            $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
            $combined = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, '', $nonce, $key);
            if ($combined === false) throw new RuntimeException('AEAD encrypt failed');

            $tagLen = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
            $tag = substr($combined, -$tagLen);
            $cipher = substr($combined, 0, -$tagLen);

            $iv_len = strlen($nonce);
            if ($iv_len > 255 || $tagLen > 255) throw new RuntimeException('iv/tag too long');

            if (fwrite($out, chr($iv_len)) === false || fwrite($out, $nonce) === false) throw new RuntimeException('failed writing iv');
            if (fwrite($out, chr($tagLen)) === false || fwrite($out, $tag) === false) throw new RuntimeException('failed writing tag');
            if (fwrite($out, $cipher) === false) throw new RuntimeException('failed writing ciphertext');

            fflush($out);
            fclose($out); $out = null;

            // meta
            $meta = [
                'plain_size' => strlen($plaintext),
                'mode' => 'single',
                'version' => self::VERSION,
                'key_version' => $keyVersion,
                'encryption_algo' => 'xchacha20poly1305_ietf'
            ];
            $metaJson = json_encode($meta, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if ($metaJson === false) throw new RuntimeException('meta json encode failed');

            $metaTmp = $tmpDest . '.meta';
            if (file_put_contents($metaTmp, $metaJson, LOCK_EX) === false) {
                @unlink($metaTmp);
                throw new RuntimeException('failed writing meta temp file');
            }
            chmod($metaTmp, 0600);
            chmod($tmpDest, 0600);

            if (!@rename($tmpDest, $destEnc)) {
                // fallback copy+unlink
                if (!copy($tmpDest, $destEnc) || !unlink($tmpDest)) {
                    @unlink($tmpDest);
                    @unlink($metaTmp);
                    throw new RuntimeException('failed to move tmp file to destination');
                }
            }
            if (!@rename($metaTmp, $destEnc . '.meta')) {
                if (!copy($metaTmp, $destEnc . '.meta') || !unlink($metaTmp)) {
                    self::logError('uploadAndEncrypt: meta move failed for ' . $destEnc . '.meta');
                } else {
                    chmod($destEnc . '.meta', 0600);
                }
            } else {
                chmod($destEnc . '.meta', 0600);
            }

            $success = true;
            return $destEnc;
        } catch (Throwable $e) {
            // cleanup and log
            if (is_resource($in)) { fclose($in); $in = null; }
            if (is_resource($out)) { fclose($out); $out = null; }
            @unlink($tmpDest);
            @unlink($tmpDest . '.meta');
            self::logError('uploadAndEncrypt: ' . $e->getMessage());
            return false;
        } finally {
            // best-effort memzero key and ensure handles closed
            if (isset($key) && is_string($key) && $key !== '') {
                try { KeyManager::memzero($key); } catch (Throwable $ee) { /* swallow */ }
                $key = null;
            }
            // also try to memzero possible $keyInfo raw (if still in scope)
            if (isset($keyInfo) && is_array($keyInfo) && isset($keyInfo['raw']) && is_string($keyInfo['raw'])) {
                try { KeyManager::memzero($keyInfo['raw']); } catch (Throwable $_) {}
            }
            if (is_resource($in)) { fclose($in); }
            if (is_resource($out)) { fclose($out); }
        }
    }

    /**
     * Decrypt encrypted file and stream to client. Returns true on success, false on error.
     * Does not call exit().
     *
     * Attempts to read .meta for key_version and will try to load the exact key if available.
     *
     * @param string $encPath
     * @param string $downloadName
     * @param string $mimeType
     * @return bool
     */
    public static function decryptAndStream(string $encPath, string $downloadName, string $mimeType = 'application/octet-stream'): bool
    {
        if (!is_readable($encPath)) {
            self::logError('decryptAndStream: encrypted file not readable: ' . $encPath);
            return false;
        }

        $metaPath = $encPath . '.meta';
        $meta = null;
        if (is_readable($metaPath)) {
            $metaJson = file_get_contents($metaPath);
            if ($metaJson !== false) {
                $tmp = json_decode($metaJson, true);
                if (is_array($tmp)) $meta = $tmp;
            }
        }

        $specificKeyVersion = $meta['key_version'] ?? null;
        $contentLength = (is_int($meta['plain_size'] ?? null) || ctype_digit((string)($meta['plain_size'] ?? '')))
            ? (int)$meta['plain_size']
            : null;

        try {
            $keyInfo = self::getFilevaultKeyInfo($specificKeyVersion);
            $key = $keyInfo['raw'];
            $keyVersion = $keyInfo['version'];
        } catch (Throwable $e) {
            self::logError('decryptAndStream: key retrieval failed: ' . $e->getMessage());
            return false;
        }

        $fh = fopen($encPath, 'rb');
        if ($fh === false) {
            self::logError('decryptAndStream: cannot open encrypted file: ' . $encPath);
            // wipe key
            try { KeyManager::memzero($key); } catch (Throwable $_) {}
            return false;
        }

        $success = false;
        $outTotal = 0;
        try {
            // version
            $versionByte = fread($fh, 1);
            if ($versionByte === false || strlen($versionByte) !== 1) {
                throw new RuntimeException('failed reading version byte');
            }
            $version = ord($versionByte);
            if ($version !== self::VERSION) {
                throw new RuntimeException('unsupported version: ' . $version);
            }

            // iv_len
            $b = fread($fh, 1);
            if ($b === false || strlen($b) !== 1) throw new RuntimeException('failed reading iv_len');
            $iv_len = ord($b);
            if ($iv_len < 0 || $iv_len > 255) throw new RuntimeException('unreasonable iv_len: ' . $iv_len);

            $iv = '';
            if ($iv_len > 0) {
                $iv = fread($fh, $iv_len);
                if ($iv === false || strlen($iv) !== $iv_len) throw new RuntimeException('failed reading iv/header');
            }

            // tag_len
            $b = fread($fh, 1);
            if ($b === false || strlen($b) !== 1) throw new RuntimeException('failed reading tag_len');
            $tag_len = ord($b);
            if ($tag_len < 0 || $tag_len > 255) throw new RuntimeException('unreasonable tag_len: ' . $tag_len);

            $tag = '';
            if ($tag_len > 0) {
                $tag = fread($fh, $tag_len);
                if ($tag === false || strlen($tag) !== $tag_len) throw new RuntimeException('failed reading tag');
            }

            // Prepare headers
            if (!headers_sent()) {
                header('Content-Type: ' . $mimeType);
                $safeName = basename((string)$downloadName);
                header('Content-Disposition: attachment; filename="' . $safeName . '"');
                if ($contentLength !== null) {
                    header('Content-Length: ' . (string)$contentLength);
                } else {
                    header('Transfer-Encoding: chunked');
                }
            }

            if ($tag_len > 0) {
                // single-pass: rest is cipher (without tag)
                $cipher = stream_get_contents($fh);
                if ($cipher === false) throw new RuntimeException('failed reading ciphertext');
                $combined = $cipher . $tag;
                $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($combined, '', $iv, $key);
                if ($plain === false) throw new RuntimeException('single-pass decryption failed (auth)');

                // stream plaintext
                $pos = 0;
                $len = strlen($plain);
                while ($pos < $len) {
                    $chunk = substr($plain, $pos, self::FRAME_SIZE);
                    echo $chunk;
                    $pos += strlen($chunk);
                    @ob_flush(); @flush();
                }

                $outTotal = $len;
                $success = true;

                // audit log (best-effort)
                self::maybeAudit($encPath, $downloadName, $contentLength ?? $len, $keyVersion);
                return true;
            }

            // STREAM mode: secretstream frames
            $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($iv, $key);
            $outTotal = 0;
            while (!feof($fh)) {
                $lenBuf = fread($fh, 4);
                if ($lenBuf === false || strlen($lenBuf) === 0) {
                    break; // EOF
                }
                if (strlen($lenBuf) !== 4) throw new RuntimeException('incomplete frame length header');
                $un = unpack('Nlen', $lenBuf);
                $frameLen = $un['len'] ?? 0;
                if ($frameLen <= 0) throw new RuntimeException('invalid frame length: ' . $frameLen);
                $frame = fread($fh, $frameLen);
                if ($frame === false || strlen($frame) !== $frameLen) throw new RuntimeException('failed reading frame payload');

                $res = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $frame);
                if ($res === false || !is_array($res)) throw new RuntimeException('secretstream pull failed (auth?)');
                [$plainChunk, $tagFrame] = $res;
                echo $plainChunk;
                $outTotal += strlen($plainChunk);
                @ob_flush(); @flush();

                if ($tagFrame === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                    break;
                }
            }

            $success = true;
            // audit log (best-effort)
            self::maybeAudit($encPath, $downloadName, $contentLength ?? $outTotal, $keyVersion);
            return true;
        } catch (Throwable $e) {
            self::logError('decryptAndStream: ' . $e->getMessage());
            return false;
        } finally {
            if (is_resource($fh)) fclose($fh);
            if (isset($key) && is_string($key) && $key !== '') {
                try { KeyManager::memzero($key); } catch (Throwable $_) {}
                $key = null;
            }
            if (isset($keyInfo) && is_array($keyInfo) && isset($keyInfo['raw']) && is_string($keyInfo['raw'])) {
                try { KeyManager::memzero($keyInfo['raw']); } catch (Throwable $_) {}
            }
        }
    }

    /**
     * Delete file safely if inside configured storage.
     */
    public static function deleteFile(string $path): bool
    {
        if (!file_exists($path)) return true;
        $real = realpath($path);
        if ($real === false) { self::logError('deleteFile: realpath failed for: ' . $path); return false; }

        $storageBase = self::getStorageBase();
        $storageReal = realpath($storageBase) ?: $storageBase;
        $prefix = rtrim($storageReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if (strncmp($real, $prefix, strlen($prefix)) !== 0) {
            self::logError('deleteFile: refusing to delete outside configured storage: ' . $real);
            return false;
        }

        if (!unlink($real)) {
            self::logError('deleteFile: unlink failed for: ' . $real);
            return false;
        }
        return true;
    }

    /**
     * Best-effort audit call. Does not break streaming on failure.
     * @param string $encPath
     * @param string $downloadName
     * @param int|null $plainSize
     * @param string|null $keyVersion
     */
    private static function maybeAudit(string $encPath, string $downloadName, ?int $plainSize, ?string $keyVersion = null): void
    {
        try {
            if (!class_exists('AuditLogger')) return;

            $pdo = self::$auditPdo ?? null;

            // actor id: use provider if set; otherwise fallback to 'guest'
            $actorId = null;
            if (is_callable(self::$actorProvider)) {
                try {
                    $actorId = call_user_func(self::$actorProvider);
                } catch (Throwable $_) {
                    $actorId = null;
                }
            }

            if ($actorId === null) {
                $actorId = 'guest';
            }

            $details = [
                'enc_path' => $encPath,
                'download_name' => $downloadName,
                'plain_size' => $plainSize,
            ];
            $payload = json_encode($details, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if ($payload === false) $payload = json_encode(['enc_path' => $encPath], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

            // AuditLogger::log(PDO $pdo = null, string $actorId, string $action, string $payloadEnc, string $keyVersion = '', array $meta = [])
            AuditLogger::log($pdo instanceof \PDO ? $pdo : null, (string)$actorId, 'file_download', $payload, $keyVersion ?? '', []);
        } catch (Throwable $e) {
            // swallow — audit is best-effort
            error_log('[FileVault] audit log failed');
        }
    }

    private static function logError(string $msg): void
    {
        if (class_exists('Logger') && method_exists('Logger', 'error')) {
            try {
                Logger::error('[FileVault] ' . $msg);
                return;
            } catch (Throwable $e) {
                // fallback
            }
        }
        error_log('[FileVault] ' . $msg);
    }
}