<?php
declare(strict_types=1);

/**
 * libs/Crypto.php
 *
 * Hardened libsodium-based Crypto helper.
 * - Use Crypto::init_from_base64($b64) or Crypto::init_from_file($path)
 * - Provides encrypt(), decrypt(), clearKey()
 */

final class Crypto
{
    /** @var array<int,string> Loaded raw keys (binary strings), order: oldest .. newest */
    private static array $keys = [];
    /** @var string|null Primary key (newest) for encryption */
    private static ?string $primaryKey = null;
    private static ?string $keysDir = null;

    private const VERSION = 1;
    private const AD = 'app:crypto:v1';
    public static function hmac(string $data, string $keyName, string $basename, ?string $keysDir = null, bool $allCandidates = false): array|string
    {
        // use stored keysDir as fallback when caller didn't pass one
        $keysDir = $keysDir ?? self::$keysDir;
        if ($allCandidates) {
            // vrací pole kandidátů pro ověřování
            return KeyManager::deriveHmacCandidates($keyName, $keysDir, $basename, $data);
        }
        // vrací jen hash string (binary)
        $res = KeyManager::deriveHmacWithLatest($keyName, $keysDir, $basename, $data);
        return $res['hash'];
    }
    public static function initFromKeyManager(?string $keysDir = null): void
    {
        // require libsodium
        KeyManager::requireSodium();

        self::$keysDir = $keysDir;

        // načteme všechny raw keys (newest last)
        $keys = KeyManager::getAllRawKeys('APP_CRYPTO_KEY', self::$keysDir, 'crypto_key');
        if (empty($keys)) {
            throw new RuntimeException('Crypto init failed: no crypto keys available (KeyManager).');
        }

        $expectedLen = KeyManager::keyByteLen();
        foreach ($keys as $k) {
            if (!is_string($k) || strlen($k) !== $expectedLen) {
                throw new RuntimeException('Crypto init failed: key length mismatch.');
            }
        }

        self::$keys = $keys;
        self::$primaryKey = end(self::$keys);
        reset(self::$keys); // obnovíme pointer, aby future foreach/current() fungoval správně
        if (!is_string(self::$primaryKey) || strlen(self::$primaryKey) !== $expectedLen) {
            self::clearKey();
            throw new RuntimeException('Crypto init failed: invalid primary key.');
        }
    }

    public static function clearKey(): void
    {
        // Best-effort memzero všech uložených klíčů (operujeme přímo na poli, aby se memzero pokusilo přepsat
        // skutečné interní buffery, ne jen lokální kopie). Poté pole vyprázdníme a primární klíč nulujeme.
        $expectedLen = KeyManager::keyByteLen();
        foreach (array_keys(self::$keys) as $i) {
            if (isset(self::$keys[$i]) && is_string(self::$keys[$i]) && strlen(self::$keys[$i]) === $expectedLen) {
                if (function_exists('sodium_memzero')) {
                    @sodium_memzero(self::$keys[$i]);
                } else {
                    // fallback: přepiš string nulami (best-effort)
                    self::$keys[$i] = str_repeat("\0", strlen(self::$keys[$i]));
                }
            }
            unset(self::$keys[$i]);
        }

        // Memzero primárního klíče pokud existuje (může být kopií reference)
        if (is_string(self::$primaryKey) && strlen(self::$primaryKey) === $expectedLen) {
            if (function_exists('sodium_memzero')) {
                @sodium_memzero(self::$primaryKey);
            } else {
                self::$primaryKey = str_repeat("\0", strlen(self::$primaryKey));
            }
        }

        self::$keys = [];
        self::$primaryKey = null;
    }

    public static function encrypt(string $plaintext, string $outFormat = 'binary'): string
    {
        if (self::$primaryKey === null) {
            throw new RuntimeException('Crypto::encrypt called but Crypto not initialized.');
        }
        $expectedLen = KeyManager::keyByteLen();
        if (!is_string(self::$primaryKey) || strlen(self::$primaryKey) !== $expectedLen) {
            throw new RuntimeException('Crypto::encrypt: invalid primary key length.');
        }

        if ($outFormat !== 'binary' && $outFormat !== 'compact_base64') {
            throw new InvalidArgumentException('Unsupported outFormat');
        }

        $nonceSize = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES; // 24
        $nonce = random_bytes($nonceSize);
        $combined = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, self::AD, $nonce, self::$primaryKey);
        if ($combined === false) {
            throw new RuntimeException('Crypto::encrypt: encryption failed');
        }

        if ($outFormat === 'compact_base64') {
            return base64_encode($nonce . $combined);
        }

        $iv_len = strlen($nonce);
        if ($iv_len > 255) {
            throw new RuntimeException('Crypto::encrypt produced iv too large');
        }

        // vždy 24 bajtů pro XChaCha20 nonce
        return chr(self::VERSION) . chr(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES) . $nonce . $combined;
    }

    public static function decrypt(string $payload): ?string
    {
        if (empty(self::$keys) || self::$primaryKey === null) {
            // Když Crypto není inicializováno, považujeme to za kritickou konfiguraci.
            throw new RuntimeException('Crypto::decrypt called but Crypto not initialized.');
        }

        if ($payload === '') {
            self::log('decrypt failed: empty payload');
            return null;
        }

        // Nejprve zkontrolujeme, zda nejde o versioned binary v raw tvaru
        if (strlen($payload) >= 1 && ord($payload[0]) === self::VERSION) {
            return self::decrypt_versioned($payload);
        }

        // Jinak zkusíme compact_base64 (nonce + cipher)
        $decoded = base64_decode($payload, true);
        if ($decoded !== false) {
            if (strlen($decoded) < SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES) {
                self::log('decrypt failed: compact_base64 too short');
                return null;
            }

            $nonceLen = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
            if (strlen($decoded) < $nonceLen + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES) {
                self::log('decrypt failed: compact_base64 too short');
                return null;
            }

            $nonce = substr($decoded, 0, $nonceLen);
            $cipher = substr($decoded, $nonceLen);

            // zkoušíme uložené klíče newest -> oldest (end(self::$keys) je newest)
            for ($i = count(self::$keys) - 1; $i >= 0; $i--) {
                $k = self::$keys[$i];
                $plain = @sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, self::AD, $nonce, $k);
                if ($plain !== false) {
                    return $plain;
                }
                // nevoláme memzero zde — clearKey() provede bezpečné vyčištění
            }
            self::log('decrypt failed: compact_base64 — all keys tried');
            return null;
        }

        // Nebase64 payload — zkusíme, jestli jde o versioned binary v raw tvaru
        if (strlen($payload) >= 1 && ord($payload[0]) === self::VERSION) {
            return self::decrypt_versioned($payload);
        }

        self::log('decrypt failed: unknown payload format');
        return null;
    }

    private static function decrypt_versioned(string $data): ?string
    {
        $len = strlen($data);
        if ($len < 2) {
            self::log('decrypt_versioned: too short');
            return null;
        }

        $ptr = 0;
        $version = ord($data[$ptr++]);
        if ($version !== self::VERSION) {
            self::log('decrypt_versioned: unsupported version ' . $version);
            return null;
        }

        $nonce_len = ord($data[$ptr++]);
        if ($nonce_len < 1 || $nonce_len > 255) {
            self::log('decrypt_versioned: unreasonable nonce_len ' . $nonce_len);
            return null;
        }

        if ($len < $ptr + $nonce_len) {
            self::log('decrypt_versioned: data too short for nonce');
            return null;
        }

        $nonce = substr($data, $ptr, $nonce_len);
        $ptr += $nonce_len;

        $cipher = substr($data, $ptr);
        if ($cipher === false || $cipher === '') {
            self::log('decrypt_versioned: no cipher data');
            return null;
        }

        // Zkusíme cached keys newest->oldest
        for ($i = count(self::$keys) - 1; $i >= 0; $i--) {
            $k = self::$keys[$i];
            $plain = @sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, self::AD, $nonce, $k);
            if ($plain !== false) {
                return $plain;
            }
        }

        self::log('decrypt_versioned: all keys exhausted');
        return null;
    }

    /**
     * Encrypt using a specific raw key bytes (32B).
     * Same format as encrypt(): either binary(versioned) or compact_base64.
     * Does NOT alter internal self::$keys; caller is responsible for key memzero.
     *
     * @param string $plaintext
     * @param string $keyRaw  raw binary key (32 bytes)
     * @param string $outFormat 'binary'|'compact_base64'
     * @return string
     */
    public static function encryptWithKeyBytes(string $plaintext, string $keyRaw, string $outFormat = 'binary'): string
    {
        KeyManager::requireSodium();
        $expectedLen = KeyManager::keyByteLen();
        if (!is_string($keyRaw) || strlen($keyRaw) !== $expectedLen) {
            throw new RuntimeException('encryptWithKeyBytes: invalid key length.');
        }

        if ($outFormat !== 'binary' && $outFormat !== 'compact_base64') {
            throw new InvalidArgumentException('Unsupported outFormat');
        }

        $nonceSize = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES; // 24
        $nonce = random_bytes($nonceSize);
        $combined = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, self::AD, $nonce, $keyRaw);
        if ($combined === false) {
            throw new RuntimeException('encryptWithKeyBytes: encryption failed');
        }

        if ($outFormat === 'compact_base64') {
            return base64_encode($nonce . $combined);
        }

        return chr(self::VERSION) . chr($nonceSize) . $nonce . $combined;
    }

    public static function decryptWithKeyCandidates(string $payload, array $candidateKeys): ?string
    {
        KeyManager::requireSodium();
        if ($payload === '') return null;

        $expectedLen = KeyManager::keyByteLen();

        // Security: limit number of candidate keys to avoid DoS via huge arrays
        $maxCandidates = 16;
        if (count($candidateKeys) > $maxCandidates) {
            $candidateKeys = array_slice($candidateKeys, 0, $maxCandidates);
        }

        // normalize: EXPECT candidateKeys to be ordered newest-first (index 0 = newest).
        // Try keys in order (newest -> oldest)
        $tryKeys = $candidateKeys;

        // compact_base64 path (nonce + combined)
        $decoded = base64_decode($payload, true);
        if ($decoded !== false) {
            if (strlen($decoded) < SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES) {
                // too short to be valid
                // log: invalid format/too short
                return null;
            }

            $nonceLen = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
            $nonce = substr($decoded, 0, $nonceLen);
            $cipher = substr($decoded, $nonceLen);

            foreach ($tryKeys as $k) {
                if (!is_string($k) || strlen($k) !== $expectedLen) continue;
                $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, self::AD, $nonce, $k);
                // zero-out key copy quickly
                KeyManager::memzero($k);
                if ($plain !== false) {
                    // wipe candidateKeys before returning
                    foreach ($candidateKeys as &$c) { try { KeyManager::memzero($c); } catch (Throwable $_) {} }
                    unset($c);
                    return $plain;
                }
            }

            // wipe candidateKeys after attempts
            foreach ($candidateKeys as &$c) { try { KeyManager::memzero($c); } catch (Throwable $_) {} }
            unset($c);

            return null;
        }

        // versioned binary path
        if (strlen($payload) >= 2 && ord($payload[0]) === self::VERSION) {
            $ptr = 0;
            $version = ord($payload[$ptr++]);
            $nonce_len = ord($payload[$ptr++]);
            if ($nonce_len < 1 || $nonce_len > 255) return null;
            if (strlen($payload) < $ptr + $nonce_len) return null;
            $nonce = substr($payload, $ptr, $nonce_len);
            $ptr += $nonce_len;
            $cipher = substr($payload, $ptr);

            foreach ($tryKeys as $k) {
                if (!is_string($k) || strlen($k) !== $expectedLen) continue;
                $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, self::AD, $nonce, $k);
                try { KeyManager::memzero($k); } catch (Throwable $_) {}
                if ($plain !== false) {
                    foreach ($candidateKeys as &$c) { try { KeyManager::memzero($c); } catch (Throwable $_) {} }
                    unset($c);
                    return $plain;
                }
            }

            foreach ($candidateKeys as &$c) { try { KeyManager::memzero($c); } catch (Throwable $_) {} }
            unset($c);
            return null;
        }

        // unknown format
        return null;
    }

    private static function log(string $msg): void
    {
        if (class_exists('Logger')) {
            Logger::systemMessage('error', 'Crypto error', null, [
                'stage' => debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2)[1]['function'] ?? 'unknown',
                'error' => $msg
            ]);
        }
    }
}