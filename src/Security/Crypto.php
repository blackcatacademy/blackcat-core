<?php
declare(strict_types=1);

namespace BlackCat\Core\Security;

use Psr\Log\LoggerInterface;
use RuntimeException;

/**
 * libs/Crypto.php
 *
 * Hardened libsodium-based Crypto helper.
 * - Use Crypto::initFromKeyManager($keysDir, $logger = null)
 * - Provides encrypt(), decrypt(), clearKey(), encryptWithKeyBytes(), decryptWithKeyCandidates()
 *
 * Notes:
 *  - This class does not persist keys; KeyManager is source of truth.
 *  - Caller is responsible for calling KeyManager::memzero(...) for raw key copies when appropriate.
 */
final class Crypto
{
    /** @var array<int,string> Loaded raw keys (binary strings), order: oldest .. newest */
    private static array $keys = [];
    /** @var string|null Primary key (newest) for encryption */
    private static ?string $primaryKey = null;
    private static ?string $keysDir = null;

    /** Optional PSR-3 logger */
    private static ?LoggerInterface $logger = null;

    private const VERSION = 1;
    private const AD = 'app:crypto:v1';

    public static function setLogger(?LoggerInterface $logger): void
    {
        self::$logger = $logger;
    }

    private static function logger(): ?LoggerInterface
    {
        if (self::$logger !== null) return self::$logger;

        // best-effort: ask KeyManager / Database for logger is not exposed publicly,
        // so we avoid coupling — caller should inject logger.
        return null;
    }

    private static function logDebug(string $msg, array $ctx = []): void
    {
        $l = self::logger();
        if ($l !== null) {
            try { $l->debug($msg, $ctx); } catch (\Throwable $_) {}
        }
    }

    private static function logError(string $msg, array $ctx = []): void
    {
        $l = self::logger();
        if ($l !== null) {
            try { $l->error($msg, $ctx); } catch (\Throwable $_) {}
        }
    }

    /**
     * Helper to produce HMAC(s) via KeyManager.
     * If $allCandidates=true returns candidates array from KeyManager::deriveHmacCandidates.
     * Otherwise returns binary hash (string).
     *
     * @return array|string
     */
    public static function hmac(string $data, string $keyName, string $basename, ?string $keysDir = null, bool $allCandidates = false): array|string
    {
        $keysDir = $keysDir ?? self::$keysDir;
        if ($allCandidates) {
            return KeyManager::deriveHmacCandidates($keyName, $keysDir, $basename, $data);
        }
        $res = KeyManager::deriveHmacWithLatest($keyName, $keysDir, $basename, $data);
        return $res['hash'];
    }

    /**
     * Initialize Crypto state from KeyManager keys.
     *
     * @param string|null $keysDir optional directory override passed to KeyManager
     * @param LoggerInterface|null $logger optional PSR logger
     */
    public static function initFromKeyManager(?string $keysDir = null, ?LoggerInterface $logger = null): void
    {
        KeyManager::requireSodium();

        if ($logger !== null) {
            self::setLogger($logger);
            KeyManager::setLogger($logger); // also set to KeyManager so it can log if needed
        }

        self::$keysDir = $keysDir;

        // prefer 'crypto_key' basename, env var APP_CRYPTO_KEY
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

        self::$keys = array_values($keys);
        self::$primaryKey = end(self::$keys) ?: null;
        reset(self::$keys);

        if (!is_string(self::$primaryKey) || strlen(self::$primaryKey) !== $expectedLen) {
            self::clearKey();
            throw new RuntimeException('Crypto init failed: invalid primary key.');
        }

        self::logDebug('Crypto initialized', ['keys' => count(self::$keys)]);
    }

    /**
     * Clear in-memory keys (best-effort memzero).
     */
    public static function clearKey(): void
    {
        $expectedLen = KeyManager::keyByteLen();

        foreach (array_keys(self::$keys) as $i) {
            if (isset(self::$keys[$i]) && is_string(self::$keys[$i]) && strlen(self::$keys[$i]) === $expectedLen) {
                if (function_exists('sodium_memzero')) {
                    @sodium_memzero(self::$keys[$i]);
                } else {
                    self::$keys[$i] = str_repeat("\0", strlen(self::$keys[$i]));
                }
            }
            unset(self::$keys[$i]);
        }

        if (is_string(self::$primaryKey) && strlen(self::$primaryKey) === $expectedLen) {
            if (function_exists('sodium_memzero')) {
                @sodium_memzero(self::$primaryKey);
            } else {
                self::$primaryKey = str_repeat("\0", strlen(self::$primaryKey));
            }
        }

        self::$keys = [];
        self::$primaryKey = null;
        self::logDebug('Crypto cleared keys');
    }

    /**
     * Encrypt plaintext using primary key.
     *
     * @param string $plaintext
     * @param string $outFormat 'binary'|'compact_base64'
     * @return string
     */
    public static function encrypt(string $plaintext, string $outFormat = 'binary'): string
    {
        KeyManager::requireSodium();
        if (self::$primaryKey === null) {
            throw new RuntimeException('Crypto::encrypt called but Crypto not initialized.');
        }

        $expectedLen = KeyManager::keyByteLen();
        if (!is_string(self::$primaryKey) || strlen(self::$primaryKey) !== $expectedLen) {
            throw new RuntimeException('Crypto::encrypt: invalid primary key length.');
        }

        if ($outFormat !== 'binary' && $outFormat !== 'compact_base64') {
            throw new \InvalidArgumentException('Unsupported outFormat');
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

        return chr(self::VERSION) . chr($nonceSize) . $nonce . $combined;
    }

    /**
     * Decrypt payload using internal cached keys (newest->oldest).
     * Accepts either versioned-binary or compact_base64.
     *
     * @param string $payload
     * @return string|null plaintext or null on failure
     */
    public static function decrypt(string $payload): ?string
    {
        KeyManager::requireSodium();

        if (empty(self::$keys) || self::$primaryKey === null) {
            throw new RuntimeException('Crypto::decrypt called but Crypto not initialized.');
        }

        if ($payload === '') {
            self::logError('decrypt failed: empty payload');
            return null;
        }

        // versioned-binary shortcut
        if (strlen($payload) >= 1 && ord($payload[0]) === self::VERSION) {
            return self::decrypt_versioned($payload);
        }

        // compact_base64 path
        $decoded = base64_decode($payload, true);
        if ($decoded !== false) {
            $nonceLen = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
            if (strlen($decoded) < $nonceLen + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES) {
                self::logError('decrypt failed: compact_base64 too short');
                return null;
            }

            $nonce = substr($decoded, 0, $nonceLen);
            $cipher = substr($decoded, $nonceLen);

            // try keys newest->oldest
            for ($i = count(self::$keys) - 1; $i >= 0; $i--) {
                $k = self::$keys[$i];
                $plain = @sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, self::AD, $nonce, $k);
                if ($plain !== false) {
                    return $plain;
                }
            }

            self::logError('decrypt failed: compact_base64 — all keys tried');
            return null;
        }

        // fallback check versioned-binary again (if raw binary passed)
        if (strlen($payload) >= 1 && ord($payload[0]) === self::VERSION) {
            return self::decrypt_versioned($payload);
        }

        self::logError('decrypt failed: unknown payload format');
        return null;
    }

    private static function decrypt_versioned(string $data): ?string
    {
        $len = strlen($data);
        if ($len < 2) {
            self::logError('decrypt_versioned: too short');
            return null;
        }

        $ptr = 0;
        $version = ord($data[$ptr++]);
        if ($version !== self::VERSION) {
            self::logError('decrypt_versioned: unsupported version ' . $version);
            return null;
        }

        $nonce_len = ord($data[$ptr++]);
        if ($nonce_len < 1 || $nonce_len > 255) {
            self::logError('decrypt_versioned: unreasonable nonce_len ' . $nonce_len);
            return null;
        }

        if ($len < $ptr + $nonce_len) {
            self::logError('decrypt_versioned: data too short for nonce');
            return null;
        }

        $nonce = substr($data, $ptr, $nonce_len);
        $ptr += $nonce_len;

        $cipher = substr($data, $ptr);
        if ($cipher === false || $cipher === '') {
            self::logError('decrypt_versioned: no cipher data');
            return null;
        }

        for ($i = count(self::$keys) - 1; $i >= 0; $i--) {
            $k = self::$keys[$i];
            $plain = @sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, self::AD, $nonce, $k);
            if ($plain !== false) {
                return $plain;
            }
        }

        self::logError('decrypt_versioned: all keys exhausted');
        return null;
    }

    /**
     * Encrypt using a specific raw key bytes (32B).
     * Does NOT alter internal self::$keys; caller is responsible for memzero of $keyRaw.
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
            throw new \InvalidArgumentException('Unsupported outFormat');
        }

        $nonceSize = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
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

    /**
     * Decrypt with array of candidate raw keys (each binary string).
     * Candidate keys order: newest-first (index 0 = newest) — but function normalizes/order-insensitive.
     *
     * @param string $payload
     * @param array $candidateKeys array of raw binary keys (strings). Note: this function will attempt to memzero candidate values.
     * @return string|null
     */
    public static function decryptWithKeyCandidates(string $payload, array $candidateKeys): ?string
    {
        KeyManager::requireSodium();
        if ($payload === '') return null;

        $expectedLen = KeyManager::keyByteLen();

        // limit to reasonable number of candidates
        $maxCandidates = 16;
        if (count($candidateKeys) > $maxCandidates) {
            $candidateKeys = array_slice($candidateKeys, 0, $maxCandidates);
        }

        // assume candidateKeys indexed newest-first; try in given order
        $tryKeys = $candidateKeys;

        // compact_base64 path
        $decoded = base64_decode($payload, true);
        if ($decoded !== false) {
            if (strlen($decoded) < SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES) {
                self::logError('decryptWithKeyCandidates: compact_base64 too short');
                return null;
            }

            $nonceLen = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
            $nonce = substr($decoded, 0, $nonceLen);
            $cipher = substr($decoded, $nonceLen);

            foreach ($tryKeys as $k) {
                if (!is_string($k) || strlen($k) !== $expectedLen) continue;
                $plain = @sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, self::AD, $nonce, $k);
                // best-effort zero local copy
                try { KeyManager::memzero($k); } catch (\Throwable $_) {}
                if ($plain !== false) {
                    // wipe all provided candidate keys (best-effort)
                    foreach ($candidateKeys as &$c) { try { KeyManager::memzero($c); } catch (\Throwable $_) {} }
                    unset($c);
                    return $plain;
                }
            }

            // wipe candidateKeys after attempts
            foreach ($candidateKeys as &$c) { try { KeyManager::memzero($c); } catch (\Throwable $_) {} }
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
                $plain = @sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, self::AD, $nonce, $k);
                try { KeyManager::memzero($k); } catch (\Throwable $_) {}
                if ($plain !== false) {
                    foreach ($candidateKeys as &$c) { try { KeyManager::memzero($c); } catch (\Throwable $_) {} }
                    unset($c);
                    return $plain;
                }
            }

            foreach ($candidateKeys as &$c) { try { KeyManager::memzero($c); } catch (\Throwable $_) {} }
            unset($c);
            return null;
        }

        // unknown format
        self::logError('decryptWithKeyCandidates: unknown format');
        return null;
    }
}