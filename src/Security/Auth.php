<?php
declare(strict_types=1);

namespace BlackCat\Core\Security;

/**
 * Compatibility facade for the legacy `BlackCat\Core\Security\Auth` API surface.
 *
 * If `blackcatacademy/blackcat-auth` is installed, this file aliases:
 * `BlackCat\Auth\CoreCompat\CoreAuth`.
 *
 * Otherwise it throws a clear runtime error.
 */
if (class_exists('BlackCat\\Auth\\CoreCompat\\CoreAuth')) {
    class_alias('BlackCat\\Auth\\CoreCompat\\CoreAuth', __NAMESPACE__ . '\\Auth');
    return;
}

final class Auth
{
    private function __construct() {}

    private static function missing(): \RuntimeException
    {
        return new \RuntimeException('blackcat-auth is required (composer require blackcatacademy/blackcat-auth).');
    }

    public static function getPepperVersionForStorage(): string
    {
        throw self::missing();
    }

    public static function hashPassword(string $password): string
    {
        unset($password);
        throw self::missing();
    }

    public static function buildHesloAlgoMetadata(string $hash): string
    {
        unset($hash);
        throw self::missing();
    }

    public static function verifyPasswordWithVersion(string $password, string $storedHash, ?string $hesloKeyVersion = null): array
    {
        unset($password, $storedHash, $hesloKeyVersion);
        throw self::missing();
    }

    public static function login(\PDO $db, string $email, string $password, int $maxFailed = 5): array
    {
        unset($db, $email, $password, $maxFailed);
        throw self::missing();
    }

    public static function isAdmin(array $userData): bool
    {
        unset($userData);
        throw self::missing();
    }

    public static function issueTokens(string $username, string $password): mixed
    {
        unset($username, $password);
        throw self::missing();
    }

    public static function verifyAccessToken(string $token): array
    {
        unset($token);
        throw self::missing();
    }

    public static function refreshTokens(string $refreshToken): mixed
    {
        unset($refreshToken);
        throw self::missing();
    }
}
