<?php
declare(strict_types=1);

namespace BlackCat\Core\Security;

use BlackCat\Core\Log\AuditLogger;
use BlackCat\Core\Log\Logger;

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
    private const VERSION = 2;
    private const LEGACY_VERSION = 1;
    private const STREAM_THRESHOLD = 20 * 1024 * 1024; // 20 MB
    private const FRAME_SIZE = 1 * 1024 * 1024; // 1 MB
    private const MAX_META_BYTES = 32 * 1024; // meta is tiny; refuse oversized reads
    private const MAX_SINGLEPASS_CIPHER_BYTES = self::STREAM_THRESHOLD + 1024; // allow small header overhead
    private const MAX_SECRETSTREAM_FRAME_BYTES =
        self::FRAME_SIZE + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

    /* -------- configuration / dependency injection (no getenv / no $GLOBALS) -------- */
    /** @var string|null explicitly configured keys directory */
    private static ?string $keysDir = null;
    /** @var string|null explicitly configured storage base */
    private static ?string $storageBase = null;
    /** @var \PDO|null explicitly configured PDO for audit (optional) */
    private static ?\PDO $auditPdo = null;
    /**
     * actor provider: callable(): string|null
     * Default null = 'guest' (the library does not call session_start()).
     */
    /** @var callable|null actor provider: callable(): string|null */
    private static $actorProvider = null;

    /** @var string slot name inside blackcat-crypto bridge */
    private static string $bridgeSlot = 'core.vault';

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
        AuditLogger::setAuditDir(rtrim($dir, DIRECTORY_SEPARATOR));
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
        if (!empty($opts['bridge_slot'])) self::$bridgeSlot = (string) $opts['bridge_slot'];
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

        // when not set explicitly, use a safe default relative to the project root
        $default = __DIR__ . '/../secure/keys';
        return $default;
    }

    private static function getStorageBase(): string
    {
        if (self::$storageBase !== null) {
            return self::$storageBase;
        }

        // safe default
        return __DIR__ . '/../secure/storage';
    }

    /**
     * Helper: get key raw bytes and version for filevault keys.
     * If $specificVersion provided (like 'v1'), try to load exact file: filevault_key_v1.key
     * Returns ['raw' => <bytes>, 'version' => 'vN']
     * Throws RuntimeException on failure.
     */
    private static function getFilevaultKeyInfo(?string $specificVersion = null): array
    {
        $bridgeClass = 'BlackCat\\Crypto\\Bridge\\CoreCryptoBridge';
        if ($specificVersion === null && class_exists($bridgeClass)) {
            try {
                $slot = self::$bridgeSlot ?: 'core.vault';
                $material = $bridgeClass::deriveKeyMaterial($slot);
                if (!isset($material['bytes'])) {
                    throw new \RuntimeException('Bridge did not return raw key bytes');
                }
                return [
                    'raw' => $material['bytes'],
                    'version' => self::normalizeKeyVersion((string)($material['id'] ?? 'v1')),
                    'id' => (string)($material['id'] ?? 'v1'),
                ];
            } catch (\Throwable $e) {
                self::logError('FileVault bridge key lookup failed: ' . $e->getMessage());
            }
        }

        $keysDir = self::getKeysDir();

        // If specific version requested, attempt to load exact file
        if ($specificVersion !== null && $specificVersion !== '') {
            $info = KeyManager::getRawKeyBytesByVersion(
                'FILEVAULT_KEY',
                $keysDir,
                'filevault_key',
                $specificVersion,
                SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
            );
            return [
                'raw' => $info['raw'],
                'version' => $info['version'],
                'id' => $info['version'],
            ];
        }

        // Use KeyManager (pass explicit keys dir)
        try {
            $info = KeyManager::getRawKeyBytes('FILEVAULT_KEY', self::getKeysDir(), 'filevault_key', false);
            return [
                'raw' => $info['raw'],
                'version' => $info['version'],
                'id' => $info['version'],
            ];
        } catch (\Throwable $e) {
            // do not leak internal exception messages — rethrow a generic runtime exception
            throw new \RuntimeException('getFilevaultKeyInfo failure');
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
        // Basic hardening: do not allow writing into existing symlinks (prevents symlink swap attacks).
        if (file_exists($destEnc) && self::isSymlinkPath($destEnc)) {
            self::logError('uploadAndEncrypt: refusing to write to symlink destination: ' . $destEnc);
            return false;
        }
        if (file_exists($destEnc . '.meta') && self::isSymlinkPath($destEnc . '.meta')) {
            self::logError('uploadAndEncrypt: refusing to write to symlink meta destination: ' . $destEnc . '.meta');
            return false;
        }

        if (FileVaultAgentClient::isConfigured()) {
            return self::uploadAndEncryptViaAgent($srcTmp, $destEnc);
        }

        if (!is_readable($srcTmp)) {
            self::logError('uploadAndEncrypt: source not readable: ' . $srcTmp);
            return false;
        }

        $keyId = null;
        // try to get key info (throws on fatal)
        try {
            $keyInfo = self::getFilevaultKeyInfo(null);
            $key = &$keyInfo['raw'];
            $keyVersion = $keyInfo['version'];
            $keyId = $keyInfo['id'] ?? $keyVersion;
        } catch (\Throwable $e) {
            self::logError('uploadAndEncrypt: key retrieval failed: ' . $e->getMessage());
            return false;
        }

        $filesize = filesize($srcTmp) ?: 0;
        $destDir = dirname($destEnc);
        if (self::isSymlinkPath($destDir)) {
            self::logError('uploadAndEncrypt: refusing to write into symlink directory: ' . $destDir);
            if (isset($key) && is_string($key)) { KeyManager::memzero($key); }
            return false;
        }
        if (!is_dir($destDir)) {
            if (!mkdir($destDir, 0750, true) && !is_dir($destDir)) {
                self::logError('uploadAndEncrypt: failed to create destination directory: ' . $destDir);
                // wipe key before returning
                if (isset($key) && is_string($key)) { KeyManager::memzero($key); }
                return false;
            }
        }

        // place tmp in same dir for atomic rename where possible (use exclusive create to reduce symlink-race risk)
        try {
            $tmpDest = self::createExclusiveTempFile($destDir, '.enc');
        } catch (\Throwable $e) {
            self::logError('uploadAndEncrypt: temp file creation failed: ' . $e->getMessage());
            if (isset($key) && is_string($key)) { KeyManager::memzero($key); }
            return false;
        }

        $out = fopen($tmpDest, 'wb');
        if ($out === false) {
            self::logError('uploadAndEncrypt: cannot open destination for write: ' . $tmpDest);
            @unlink($tmpDest);
            if (isset($key) && is_string($key)) { KeyManager::memzero($key); }
            return false;
        }

        // ensure we wipe key and close handles in all cases
        $in = null;
        $success = false;
        try {
            // write version byte
            if (fwrite($out, chr(self::VERSION)) === false) {
                throw new \RuntimeException('failed writing version byte');
            }
            $keyIdBytes = $keyId ?? '';
            $keyIdLen = strlen($keyIdBytes);
            if ($keyIdLen > 255) {
                $keyIdBytes = substr($keyIdBytes, 0, 255);
                $keyIdLen = 255;
            }

            if (fwrite($out, chr($keyIdLen)) === false || ($keyIdLen > 0 && fwrite($out, $keyIdBytes) === false)) {
                throw new \RuntimeException('failed writing key id');
            }

            $useStream = ($filesize > self::STREAM_THRESHOLD);

            if ($useStream) {
                // secretstream init_push
                $res = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
                if (!is_array($res) || count($res) !== 2) {
                    throw new \RuntimeException('secretstream init_push failed');
                }
                [$state, $header] = $res;
                if (!is_string($header) || strlen($header) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
                    throw new \RuntimeException('secretstream header invalid length');
                }

                $iv_len = strlen($header);

                if (fwrite($out, chr($iv_len)) === false || fwrite($out, $header) === false) {
                    throw new \RuntimeException('failed writing header');
                }

                // tag_len == 0 marks secretstream mode
                if (fwrite($out, chr(0)) === false) throw new \RuntimeException('failed writing tag_len');

                $in = fopen($srcTmp, 'rb');
                if ($in === false) throw new \RuntimeException('cannot open source for read: ' . $srcTmp);

                while (!feof($in)) {
                    $chunk = fread($in, self::FRAME_SIZE);
                    if ($chunk === false) throw new \RuntimeException('read error from source');
                    $isFinal = feof($in);
                    $tag = $isFinal ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
                    $frame = sodium_crypto_secretstream_xchacha20poly1305_push($state, $chunk, '', $tag);

                    $frameLen = strlen($frame);
                    $lenBuf = pack('N', $frameLen);
                    if (fwrite($out, $lenBuf) === false || fwrite($out, $frame) === false) {
                        throw new \RuntimeException('write error while writing frame');
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
                    'context' => self::$bridgeSlot,
                    'key_id' => $keyId ?? $keyVersion,
                    'encryption_algo' => 'secretstream_xchacha20poly1305'
                ];
                $metaJson = json_encode($meta, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                if ($metaJson === false) throw new \RuntimeException('meta json encode failed');

                $metaTmp = $tmpDest . '.meta';
                if (!self::writeFileExclusive($metaTmp, $metaJson)) {
                    throw new \RuntimeException('failed writing meta temp file');
                }
                chmod($metaTmp, 0600);

                chmod($tmpDest, 0600);

                // atomic move with fallback
                if (!@rename($tmpDest, $destEnc)) {
                    // rename might fail across devices — fallback to copy+unlink
                    if (self::isSymlinkPath($destEnc) || !copy($tmpDest, $destEnc) || !unlink($tmpDest)) {
                        @unlink($tmpDest);
                        @unlink($metaTmp);
                        throw new \RuntimeException('failed to move tmp file to destination');
                    }
                }
                // move meta
                if (!@rename($metaTmp, $destEnc . '.meta')) {
                    // try copy+unlink fallback
                    if (self::isSymlinkPath($destEnc . '.meta') || !copy($metaTmp, $destEnc . '.meta') || !unlink($metaTmp)) {
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
            if ($plaintext === false) throw new \RuntimeException('failed to read small source into memory');

            // AEAD encrypt
            $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
            $combined = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, '', $nonce, $key);

            $tagLen = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
            $tag = substr($combined, -$tagLen);
            $cipher = substr($combined, 0, -$tagLen);

            $iv_len = strlen($nonce);

            if (fwrite($out, chr($iv_len)) === false || fwrite($out, $nonce) === false) throw new \RuntimeException('failed writing iv');
            if (fwrite($out, chr($tagLen)) === false || fwrite($out, $tag) === false) throw new \RuntimeException('failed writing tag');
            if (fwrite($out, $cipher) === false) throw new \RuntimeException('failed writing ciphertext');

            fflush($out);
            fclose($out); $out = null;

            // meta
            $meta = [
                'plain_size' => strlen($plaintext),
                'mode' => 'single',
                'version' => self::VERSION,
                'key_version' => $keyVersion,
                'context' => self::$bridgeSlot,
                'key_id' => $keyId ?? $keyVersion,
                'encryption_algo' => 'xchacha20poly1305_ietf'
            ];
            $metaJson = json_encode($meta, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if ($metaJson === false) throw new \RuntimeException('meta json encode failed');

            $metaTmp = $tmpDest . '.meta';
            if (!self::writeFileExclusive($metaTmp, $metaJson)) {
                throw new \RuntimeException('failed writing meta temp file');
            }
            chmod($metaTmp, 0600);
            chmod($tmpDest, 0600);

            if (!@rename($tmpDest, $destEnc)) {
                // fallback copy+unlink
                if (self::isSymlinkPath($destEnc) || !copy($tmpDest, $destEnc) || !unlink($tmpDest)) {
                    @unlink($tmpDest);
                    @unlink($metaTmp);
                    throw new \RuntimeException('failed to move tmp file to destination');
                }
            }
            if (!@rename($metaTmp, $destEnc . '.meta')) {
                if (self::isSymlinkPath($destEnc . '.meta') || !copy($metaTmp, $destEnc . '.meta') || !unlink($metaTmp)) {
                    self::logError('uploadAndEncrypt: meta move failed for ' . $destEnc . '.meta');
                } else {
                    chmod($destEnc . '.meta', 0600);
                }
            } else {
                chmod($destEnc . '.meta', 0600);
            }

            $success = true;
            return $destEnc;
        } catch (\Throwable $e) {
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
                try { KeyManager::memzero($key); } catch (\Throwable $ee) { /* swallow */ }
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
        if (self::isSymlinkPath($encPath)) {
            self::logError('decryptAndStream: refusing to read symlink ciphertext: ' . $encPath);
            return false;
        }

        $meta = self::readMetaBestEffort($encPath);

        $specificKeyVersion = $meta['key_version'] ?? null;
        $contentLength = (is_int($meta['plain_size'] ?? null) || ctype_digit((string)($meta['plain_size'] ?? '')))
            ? (int)$meta['plain_size']
            : null;

        $safeName = self::sanitizeHeaderFilename($downloadName);
        $safeMime = self::sanitizeMimeType($mimeType);

        if (FileVaultAgentClient::isConfigured()) {
            return self::decryptAndStreamViaAgent($encPath, $safeName, $safeMime, $contentLength);
        }

        $fh = fopen($encPath, 'rb');
        if ($fh === false) {
            self::logError('decryptAndStream: cannot open encrypted file: ' . $encPath);
            return false;
        }

        $success = false;
        $outTotal = 0;
        try {
            $cipherSize = filesize($encPath);
            if ($cipherSize === false) {
                throw new \RuntimeException('ciphertext stat failed');
            }

            // version
            $versionByte = fread($fh, 1);
            if ($versionByte === false || strlen($versionByte) !== 1) {
                throw new \RuntimeException('failed reading version byte');
            }
            $version = ord($versionByte);
            if ($version !== self::VERSION && $version !== self::LEGACY_VERSION) {
                throw new \RuntimeException('unsupported version: ' . $version);
            }
            $fileKeyId = null;
            $ivLenByte = null;

            if ($version === self::VERSION) {
                $b = fread($fh, 1);
                if ($b === false || strlen($b) !== 1) {
                    throw new \RuntimeException('failed reading key id len');
                }
                $keyIdLen = ord($b);
                if ($keyIdLen > 0) {
                    $fileKeyId = fread($fh, $keyIdLen);
                    if ($fileKeyId === false || strlen($fileKeyId) !== $keyIdLen) {
                        throw new \RuntimeException('failed reading key id');
                    }
                }
                $ivLenByte = fread($fh, 1);
                if ($ivLenByte === false || strlen($ivLenByte) !== 1) {
                    throw new \RuntimeException('failed reading iv_len');
                }
            } else {
                $posAfterVersion = ftell($fh);
                if ($posAfterVersion === false) {
                    throw new \RuntimeException('failed reading file cursor');
                }

                // Attempt "v1-with-key-id" variant (historical bug) first.
                $b = fread($fh, 1);
                if ($b === false || strlen($b) !== 1) {
                    throw new \RuntimeException('failed reading iv_len/key_id_len');
                }
                $keyIdLen = ord($b);
                $candidateKeyId = null;
                if ($keyIdLen > 0) {
                    $candidateKeyId = fread($fh, $keyIdLen);
                    if ($candidateKeyId === false || strlen($candidateKeyId) !== $keyIdLen) {
                        $candidateKeyId = null;
                    }
                }
                $candidateIvLenByte = fread($fh, 1);
                if ($candidateIvLenByte !== false && strlen($candidateIvLenByte) === 1) {
                    $candidateIvLen = ord($candidateIvLenByte);
                    $expectedIvLen = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
                    if ($candidateIvLen === $expectedIvLen) {
                        $fileKeyId = $candidateKeyId;
                        $ivLenByte = $candidateIvLenByte;
                    }
                }

                if ($ivLenByte === null) {
                    if (fseek($fh, $posAfterVersion, SEEK_SET) !== 0) {
                        throw new \RuntimeException('failed rewinding file cursor');
                    }
                    $ivLenByte = fread($fh, 1);
                    if ($ivLenByte === false || strlen($ivLenByte) !== 1) {
                        throw new \RuntimeException('failed reading iv_len');
                    }
                }
            }

            if (!is_string($specificKeyVersion) || trim($specificKeyVersion) === '' || str_contains($specificKeyVersion, "\0")) {
                $specificKeyVersion = $fileKeyId;
            }
            if (!is_string($specificKeyVersion) || trim($specificKeyVersion) === '' || str_contains($specificKeyVersion, "\0")) {
                $specificKeyVersion = null;
            }

            try {
                $keyInfo = self::getFilevaultKeyInfo($specificKeyVersion);
                $key = &$keyInfo['raw'];
                $keyVersion = $keyInfo['version'];
            } catch (\Throwable $e) {
                self::logError('decryptAndStream: key retrieval failed: ' . $e->getMessage());
                return false;
            }

            // iv_len
            $iv_len = ord($ivLenByte);
            $expectedIvLen = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
            if ($iv_len !== $expectedIvLen) {
                throw new \RuntimeException('unreasonable iv_len: ' . $iv_len);
            }

            $iv = fread($fh, $iv_len);
            if ($iv === false || strlen($iv) !== $iv_len) throw new \RuntimeException('failed reading iv/header');

            // tag_len
            $b = fread($fh, 1);
            if ($b === false || strlen($b) !== 1) throw new \RuntimeException('failed reading tag_len');
            $tag_len = ord($b);
            if ($tag_len !== 0 && $tag_len !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES) {
                throw new \RuntimeException('unreasonable tag_len: ' . $tag_len);
            }

            if ($tag_len > 0 && $cipherSize !== false && $cipherSize > self::MAX_SINGLEPASS_CIPHER_BYTES) {
                throw new \RuntimeException('single-pass ciphertext too large');
            }

            $tag = '';
            if ($tag_len > 0) {
                $tag = fread($fh, $tag_len);
                if ($tag === false || strlen($tag) !== $tag_len) throw new \RuntimeException('failed reading tag');
            }

            // Prepare headers
            if (!headers_sent()) {
                header('Content-Type: ' . $safeMime);
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
                if ($cipher === false) throw new \RuntimeException('failed reading ciphertext');
                $combined = $cipher . $tag;
                $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($combined, '', $iv, $key);
                if ($plain === false) throw new \RuntimeException('single-pass decryption failed (auth)');

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
                $auditKeyId = $fileKeyId ?? (is_string($meta['key_id'] ?? null) ? (string) $meta['key_id'] : null);
                self::maybeAudit($encPath, $downloadName, $contentLength ?? $len, $keyVersion, $auditKeyId);
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
                if (strlen($lenBuf) !== 4) throw new \RuntimeException('incomplete frame length header');
                $un = unpack('Nlen', $lenBuf);
                $frameLen = $un['len'] ?? 0;
                if ($frameLen <= 0) throw new \RuntimeException('invalid frame length: ' . $frameLen);
                if ($frameLen > self::MAX_SECRETSTREAM_FRAME_BYTES) {
                    throw new \RuntimeException('unreasonable frame length: ' . $frameLen);
                }
                $frame = fread($fh, $frameLen);
                if ($frame === false || strlen($frame) !== $frameLen) throw new \RuntimeException('failed reading frame payload');

                $res = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $frame);
                if ($res === false || !is_array($res)) throw new \RuntimeException('secretstream pull failed (auth?)');
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
            $auditKeyId = $fileKeyId ?? (is_string($meta['key_id'] ?? null) ? (string) $meta['key_id'] : null);
            self::maybeAudit($encPath, $downloadName, $contentLength ?? $outTotal, $keyVersion, $auditKeyId);
            return true;
        } catch (\Throwable $e) {
            self::logError('decryptAndStream: ' . $e->getMessage());
            return false;
        } finally {
            if (is_resource($fh)) fclose($fh);
            if (isset($key) && is_string($key) && $key !== '') {
                try { KeyManager::memzero($key); } catch (\Throwable $_) {}
            }
        }
    }

    /**
     * Decrypt encrypted file to a destination file.
     *
     * - Does not send any headers / output.
     * - Uses a temp file + atomic rename when possible.
     */
    public static function decryptToFile(string $encPath, string $destPlain): bool
    {
        if (!is_readable($encPath)) {
            self::logError('decryptToFile: encrypted file not readable: ' . $encPath);
            return false;
        }
        if (self::isSymlinkPath($encPath)) {
            self::logError('decryptToFile: refusing to read symlink ciphertext: ' . $encPath);
            return false;
        }

        if (file_exists($destPlain) && self::isSymlinkPath($destPlain)) {
            self::logError('decryptToFile: refusing to write to symlink destination: ' . $destPlain);
            return false;
        }

        $meta = self::readMetaBestEffort($encPath);

        $fh = fopen($encPath, 'rb');
        if ($fh === false) {
            self::logError('decryptToFile: cannot open encrypted file: ' . $encPath);
            return false;
        }

        $destDir = dirname($destPlain);
        if (self::isSymlinkPath($destDir)) {
            fclose($fh);
            self::logError('decryptToFile: refusing to write into symlink directory: ' . $destDir);
            return false;
        }
        if (!is_dir($destDir)) {
            if (!mkdir($destDir, 0750, true) && !is_dir($destDir)) {
                fclose($fh);
                self::logError('decryptToFile: failed to create destination directory: ' . $destDir);
                return false;
            }
        }

        try {
            $tmpOut = self::createExclusiveTempFile($destDir, '.plain');
        } catch (\Throwable $e) {
            fclose($fh);
            self::logError('decryptToFile: temp file creation failed: ' . $e->getMessage());
            return false;
        }

        $out = fopen($tmpOut, 'wb');
        if ($out === false) {
            fclose($fh);
            self::logError('decryptToFile: cannot open destination for write: ' . $tmpOut);
            @unlink($tmpOut);
            return false;
        }

        try {
            $cipherSize = filesize($encPath);
            if ($cipherSize === false) {
                throw new \RuntimeException('ciphertext stat failed');
            }

            $versionByte = fread($fh, 1);
            if ($versionByte === false || strlen($versionByte) !== 1) {
                throw new \RuntimeException('failed reading version byte');
            }
            $version = ord($versionByte);
            if ($version !== self::VERSION && $version !== self::LEGACY_VERSION) {
                throw new \RuntimeException('unsupported version: ' . $version);
            }

            $specificKeyVersion = is_array($meta) ? ($meta['key_version'] ?? null) : null;
            $fileKeyId = null;
            $ivLenByte = null;
            if ($version === self::VERSION) {
                $b = fread($fh, 1);
                if ($b === false || strlen($b) !== 1) {
                    throw new \RuntimeException('failed reading key id len');
                }
                $keyIdLen = ord($b);
                if ($keyIdLen > 0) {
                    $keyIdRaw = fread($fh, $keyIdLen);
                    if ($keyIdRaw === false || strlen($keyIdRaw) !== $keyIdLen) {
                        throw new \RuntimeException('failed reading key id');
                    }
                    $fileKeyId = $keyIdRaw;
                }
                $ivLenByte = fread($fh, 1);
                if ($ivLenByte === false || strlen($ivLenByte) !== 1) {
                    throw new \RuntimeException('failed reading iv_len');
                }
            } else {
                $ivLenByte = fread($fh, 1);
                if ($ivLenByte === false || strlen($ivLenByte) !== 1) {
                    throw new \RuntimeException('failed reading iv_len');
                }
            }

            if (!is_string($specificKeyVersion) || $specificKeyVersion === '') {
                $specificKeyVersion = $fileKeyId;
            }
            if (!is_string($specificKeyVersion) || trim($specificKeyVersion) === '') {
                $specificKeyVersion = null;
            }

            try {
                $keyInfo = self::getFilevaultKeyInfo(is_string($specificKeyVersion) ? (string) $specificKeyVersion : null);
                $key = &$keyInfo['raw'];
                $keyVersion = $keyInfo['version'];
            } catch (\Throwable $e) {
                throw new \RuntimeException('key retrieval failed');
            }

            $iv_len = ord((string) $ivLenByte);
            $expectedIvLen = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
            if ($iv_len !== $expectedIvLen) {
                throw new \RuntimeException('unreasonable iv_len: ' . $iv_len);
            }

            $iv = fread($fh, $iv_len);
            if ($iv === false || strlen($iv) !== $iv_len) throw new \RuntimeException('failed reading iv/header');

            $b = fread($fh, 1);
            if ($b === false || strlen($b) !== 1) throw new \RuntimeException('failed reading tag_len');
            $tag_len = ord($b);
            if ($tag_len !== 0 && $tag_len !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES) {
                throw new \RuntimeException('unreasonable tag_len: ' . $tag_len);
            }

            if ($tag_len > 0 && $cipherSize !== false && $cipherSize > self::MAX_SINGLEPASS_CIPHER_BYTES) {
                throw new \RuntimeException('single-pass ciphertext too large');
            }

            $tag = '';
            if ($tag_len > 0) {
                $tag = fread($fh, $tag_len);
                if ($tag === false || strlen($tag) !== $tag_len) throw new \RuntimeException('failed reading tag');
            }

            if ($tag_len > 0) {
                $cipher = stream_get_contents($fh);
                if ($cipher === false) throw new \RuntimeException('failed reading ciphertext');
                $combined = $cipher . $tag;
                $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($combined, '', $iv, $key);
                if ($plain === false) throw new \RuntimeException('single-pass decryption failed (auth)');
                if (fwrite($out, $plain) === false) throw new \RuntimeException('write failed');
            } else {
                $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($iv, $key);
                while (!feof($fh)) {
                    $lenBuf = fread($fh, 4);
                    if ($lenBuf === false || strlen($lenBuf) === 0) {
                        break; // EOF
                    }
                    if (strlen($lenBuf) !== 4) throw new \RuntimeException('incomplete frame length header');
                    $un = unpack('Nlen', $lenBuf);
                    $frameLen = $un['len'] ?? 0;
                    if ($frameLen <= 0) throw new \RuntimeException('invalid frame length: ' . $frameLen);
                    if ($frameLen > self::MAX_SECRETSTREAM_FRAME_BYTES) {
                        throw new \RuntimeException('unreasonable frame length: ' . $frameLen);
                    }
                    $frame = fread($fh, $frameLen);
                    if ($frame === false || strlen($frame) !== $frameLen) throw new \RuntimeException('failed reading frame payload');

                    $res = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $frame);
                    if ($res === false || !is_array($res)) throw new \RuntimeException('secretstream pull failed (auth?)');
                    [$plainChunk, $tagFrame] = $res;
                    if ($plainChunk !== '') {
                        if (fwrite($out, $plainChunk) === false) throw new \RuntimeException('write failed');
                    }

                    if ($tagFrame === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                        break;
                    }
                }
            }

            fflush($out);
            fclose($out);
            fclose($fh);
            $out = null;
            $fh = null;

            chmod($tmpOut, 0600);

            if (!@rename($tmpOut, $destPlain)) {
                if (!copy($tmpOut, $destPlain) || !unlink($tmpOut)) {
                    @unlink($tmpOut);
                    throw new \RuntimeException('failed to move tmp file to destination');
                }
            }
            chmod($destPlain, 0600);

            return true;
        } catch (\Throwable $e) {
            self::logError('decryptToFile: ' . $e->getMessage());
            return false;
        } finally {
            if (is_resource($fh)) fclose($fh);
            if (is_resource($out)) fclose($out);
            @unlink($tmpOut);
            if (isset($key) && is_string($key) && $key !== '') {
                try { KeyManager::memzero($key); } catch (\Throwable $_) {}
            }
        }
    }

    private static function uploadAndEncryptViaAgent(string $srcTmp, string $destEnc): string|false
    {
        if (file_exists($destEnc) && self::isSymlinkPath($destEnc)) {
            self::logError('uploadAndEncrypt: refusing to write to symlink destination: ' . $destEnc);
            return false;
        }
        if (file_exists($destEnc . '.meta') && self::isSymlinkPath($destEnc . '.meta')) {
            self::logError('uploadAndEncrypt: refusing to write to symlink meta destination: ' . $destEnc . '.meta');
            return false;
        }

        if (!is_readable($srcTmp)) {
            self::logError('uploadAndEncrypt: source not readable: ' . $srcTmp);
            return false;
        }

        $filesize = filesize($srcTmp);
        if ($filesize === false) {
            self::logError('uploadAndEncrypt: cannot stat source: ' . $srcTmp);
            return false;
        }

        $destDir = dirname($destEnc);
        if (self::isSymlinkPath($destDir)) {
            self::logError('uploadAndEncrypt: refusing to write into symlink directory: ' . $destDir);
            return false;
        }
        if (!is_dir($destDir)) {
            if (!mkdir($destDir, 0750, true) && !is_dir($destDir)) {
                self::logError('uploadAndEncrypt: failed to create destination directory: ' . $destDir);
                return false;
            }
        }

        try {
            $tmpDest = self::createExclusiveTempFile($destDir, '.enc');
        } catch (\Throwable $e) {
            self::logError('uploadAndEncrypt: temp file creation failed: ' . $e->getMessage());
            return false;
        }
        $out = fopen($tmpDest, 'wb');
        if ($out === false) {
            self::logError('uploadAndEncrypt: cannot open destination for write: ' . $tmpDest);
            @unlink($tmpDest);
            return false;
        }

        $in = fopen($srcTmp, 'rb');
        if ($in === false) {
            fclose($out);
            @unlink($tmpDest);
            self::logError('uploadAndEncrypt: cannot open source for read: ' . $srcTmp);
            return false;
        }

        try {
            $meta = FileVaultAgentClient::encryptStream('filevault_key', $filesize, $in, $out, self::$bridgeSlot ?: null);
            fclose($in);
            fclose($out);
            $in = null;
            $out = null;

            $metaJson = json_encode($meta, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if ($metaJson === false) {
                throw new \RuntimeException('meta json encode failed');
            }

            $metaTmp = $tmpDest . '.meta';
            if (!self::writeFileExclusive($metaTmp, $metaJson)) {
                throw new \RuntimeException('failed writing meta temp file');
            }
            chmod($metaTmp, 0600);
            chmod($tmpDest, 0600);

            if (!@rename($tmpDest, $destEnc)) {
                if (self::isSymlinkPath($destEnc) || !copy($tmpDest, $destEnc) || !unlink($tmpDest)) {
                    @unlink($tmpDest);
                    @unlink($metaTmp);
                    throw new \RuntimeException('failed to move tmp file to destination');
                }
            }
            if (!@rename($metaTmp, $destEnc . '.meta')) {
                if (self::isSymlinkPath($destEnc . '.meta') || !copy($metaTmp, $destEnc . '.meta') || !unlink($metaTmp)) {
                    self::logError('uploadAndEncrypt: meta move failed for ' . $destEnc . '.meta');
                } else {
                    chmod($destEnc . '.meta', 0600);
                }
            } else {
                chmod($destEnc . '.meta', 0600);
            }

            return $destEnc;
        } catch (\Throwable $e) {
            self::logError('uploadAndEncrypt (agent): ' . $e->getMessage());
            return false;
        } finally {
            if (is_resource($in)) fclose($in);
            if (is_resource($out)) fclose($out);
            @unlink($tmpDest);
            @unlink($tmpDest . '.meta');
        }
    }

    private static function decryptAndStreamViaAgent(string $encPath, string $downloadName, string $mimeType, ?int $contentLength): bool
    {
        $cipherSize = filesize($encPath);
        if ($cipherSize === false) {
            self::logError('decryptAndStream (agent): cannot stat encrypted file: ' . $encPath);
            return false;
        }

        if (!headers_sent()) {
            header('Content-Type: ' . self::sanitizeMimeType($mimeType));
            header('Content-Disposition: attachment; filename="' . self::sanitizeHeaderFilename($downloadName) . '"');
            if ($contentLength !== null) {
                header('Content-Length: ' . (string)$contentLength);
            } else {
                header('Transfer-Encoding: chunked');
            }
        }

        $in = fopen($encPath, 'rb');
        if ($in === false) {
            self::logError('decryptAndStream (agent): cannot open encrypted file: ' . $encPath);
            return false;
        }

        $out = fopen('php://output', 'wb');
        if ($out === false) {
            fclose($in);
            self::logError('decryptAndStream (agent): cannot open output stream');
            return false;
        }

        try {
            $res = FileVaultAgentClient::decryptStream('filevault_key', $cipherSize, $in, $out);
            @ob_flush();
            @flush();

            // audit log (best-effort)
            $meta = self::readMetaBestEffort($encPath);
            $auditKeyId = is_array($meta) && is_string($meta['key_id'] ?? null) ? (string) $meta['key_id'] : null;
            self::maybeAudit($encPath, $downloadName, $contentLength ?? $res['plain_size'], $res['key_version'], $auditKeyId);

            return true;
        } catch (\Throwable $e) {
            self::logError('decryptAndStream (agent): ' . $e->getMessage());
            return false;
        } finally {
            fclose($in);
            fclose($out);
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
    private static function maybeAudit(string $encPath, string $downloadName, ?int $plainSize, ?string $keyVersion = null, ?string $keyId = null): void
    {
        try {
            if (!class_exists(AuditLogger::class, true)) return;

            $pdo = self::$auditPdo ?? null;

            // actor id: use provider if set; otherwise fallback to 'guest'
            $actorId = null;
            if (is_callable(self::$actorProvider)) {
                try {
                    $actorId = call_user_func(self::$actorProvider);
                } catch (\Throwable $_) {
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
                'key_id' => $keyId,
            ];
            $payload = json_encode($details, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if ($payload === false) {
                $payload = '{}';
            }

            // AuditLogger::log(PDO $pdo = null, string $actorId, string $action, string $payloadEnc, string $keyVersion = '', array $meta = [])
            AuditLogger::log($pdo instanceof \PDO ? $pdo : null, (string)$actorId, 'file_download', $payload, $keyVersion ?? '', []);
        } catch (\Throwable $e) {
            // swallow — audit is best-effort
            error_log('[FileVault] audit log failed');
        }
    }

    private static function logError(string $msg): void
    {
        if (class_exists(Logger::class, true) && method_exists(Logger::class, 'error')) {
            try {
                Logger::error('[FileVault] ' . $msg);
                return;
            } catch (\Throwable $e) {
                // fallback
            }
        }
        error_log('[FileVault] ' . $msg);
    }

    private static function normalizeKeyVersion(string $id): string
    {
        if ($id === '') {
            return 'v1';
        }

        if (preg_match('/v(\d+)/i', $id, $m)) {
            return 'v' . $m[1];
        }

        return 'v' . substr(hash('crc32', $id), 0, 4);
    }

    private static function isSymlinkPath(string $path): bool
    {
        $trimmed = rtrim($path, "/\\");
        if ($trimmed === '') {
            $trimmed = $path;
        }
        return is_link($trimmed);
    }

    private static function readMetaBestEffort(string $encPath): array
    {
        $metaPath = $encPath . '.meta';
        if (!is_readable($metaPath)) {
            return [];
        }
        if (self::isSymlinkPath($metaPath)) {
            self::logError('FileVault meta path is a symlink, ignoring: ' . $metaPath);
            return [];
        }
        if (!is_file($metaPath)) {
            return [];
        }

        $raw = self::safeReadFileBounded($metaPath, self::MAX_META_BYTES);
        if (!is_string($raw) || trim($raw) === '') {
            self::logError('FileVault meta read failed/too large, ignoring: ' . $metaPath);
            return [];
        }

        $tmp = json_decode($raw, true);
        return is_array($tmp) ? $tmp : [];
    }

    private static function safeReadFileBounded(string $path, int $maxBytes): string|false
    {
        if ($maxBytes < 0) {
            return false;
        }

        $fh = @fopen($path, 'rb');
        if ($fh === false) {
            return false;
        }

        try {
            $data = stream_get_contents($fh, $maxBytes + 1);
            if ($data === false) {
                return false;
            }
            if (strlen($data) > $maxBytes) {
                return false;
            }
            return $data;
        } finally {
            fclose($fh);
        }
    }

    private static function writeFileExclusive(string $path, string $contents): bool
    {
        $fh = @fopen($path, 'xb');
        if ($fh === false) {
            return false;
        }
        try {
            $len = strlen($contents);
            $offset = 0;
            while ($offset < $len) {
                $n = fwrite($fh, substr($contents, $offset));
                if ($n === false || $n === 0) {
                    return false;
                }
                $offset += $n;
            }
            fflush($fh);
            return true;
        } finally {
            fclose($fh);
        }
    }

    private static function createExclusiveTempFile(string $dir, string $suffix): string
    {
        $dir = rtrim($dir, DIRECTORY_SEPARATOR);
        $attempts = 0;
        while (true) {
            $attempts++;
            if ($attempts > 128) {
                throw new \RuntimeException('tempfile_create_failed');
            }
            $candidate = $dir . DIRECTORY_SEPARATOR . '.tmp-' . bin2hex(random_bytes(6)) . $suffix;
            $fh = @fopen($candidate, 'xb');
            if ($fh === false) {
                continue;
            }
            fclose($fh);
            return $candidate;
        }
    }

    private static function sanitizeHeaderFilename(string $name): string
    {
        $name = basename($name);
        $name = str_replace(["\0", "\r", "\n"], '', $name);
        $name = trim($name);
        if ($name === '') {
            return 'download.bin';
        }
        // Remove quotes/backslashes to avoid breaking Content-Disposition.
        $name = str_replace(['"', '\\'], '_', $name);
        // Replace other control chars.
        $name = preg_replace('/[\\x00-\\x1F\\x7F]/', '_', $name) ?? $name;
        if (strlen($name) > 180) {
            $name = substr($name, 0, 180);
        }
        return $name !== '' ? $name : 'download.bin';
    }

    private static function sanitizeMimeType(string $mimeType): string
    {
        $mimeType = str_replace(["\0", "\r", "\n"], '', $mimeType);
        $mimeType = trim($mimeType);
        if ($mimeType === '' || strlen($mimeType) > 128) {
            return 'application/octet-stream';
        }
        if (!preg_match('~^[a-zA-Z0-9][a-zA-Z0-9!#$&^_.+-]*/[a-zA-Z0-9][a-zA-Z0-9!#$&^_.+-]*$~', $mimeType)) {
            return 'application/octet-stream';
        }
        return strtolower($mimeType);
    }
}
