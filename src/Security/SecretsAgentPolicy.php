<?php

declare(strict_types=1);

namespace BlackCat\Core\Security;

/**
 * Canonical allowlist for secrets-agent mode.
 *
 * Goal:
 * - reduce exfil surface if an attacker can call the agent protocol,
 * - make the "single source of truth" explicit (do not spread allowlists across repos).
 *
 * The agent should only expose key basenames that are used by blackcat-core itself.
 */
final class SecretsAgentPolicy
{
    /**
     * @return array<string,int> basename => expected raw bytes length
     */
    public static function keyBasenameAllowlist(): array
    {
        $bytes32 = KeyManager::keyByteLen();

        return [
            // Core crypto primitives
            'crypto_key' => $bytes32,
            'filevault_key' => $bytes32,

            // Encrypted local cache (optional)
            'cache_crypto' => $bytes32,

            // Kernel-level secrets (HMAC/AEAD)
            'password_pepper' => 32,
            'app_salt' => 32,
            'session_key' => 32,
            'ip_hash_key' => 32,
            'csrf_key' => 32,
            'jwt_key' => 32,

            // Email flows (kernel-owned)
            'email_key' => $bytes32,
            'email_hash_key' => $bytes32,
            'email_verification_key' => $bytes32,
            'unsubscribe_key' => $bytes32,

            // Optional profile encryption
            'profile_crypto' => $bytes32,
        ];
    }

    public static function expectedLenForBasename(string $basename): ?int
    {
        $basename = trim($basename);
        if ($basename === '' || str_contains($basename, "\0")) {
            return null;
        }

        $map = self::keyBasenameAllowlist();
        $v = $map[$basename] ?? null;
        return is_int($v) && $v > 0 ? $v : null;
    }
}

