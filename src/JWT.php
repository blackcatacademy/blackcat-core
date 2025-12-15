<?php
declare(strict_types=1);

/**
 * Compatibility facade for the legacy global `JWT` helper.
 *
 * If `blackcatacademy/blackcat-jwt` is installed, this file aliases:
 * `BlackCat\Jwt\CoreCompat\CoreJWT`.
 */
if (class_exists('BlackCat\\Jwt\\CoreCompat\\CoreJWT')) {
    class_alias('BlackCat\\Jwt\\CoreCompat\\CoreJWT', 'JWT');
    return;
}

final class JWT
{
    private function __construct() {}

    private static function missing(): \RuntimeException
    {
        return new \RuntimeException('JWT implementation not installed. Install blackcatacademy/blackcat-jwt.');
    }

    public static function issueAccessToken(int $userId, array $extraClaims = [], ?int $ttl = null, ?string $keysDir = null): string
    {
        unset($userId, $extraClaims, $ttl, $keysDir);
        throw self::missing();
    }

    public static function verify(string $jwt, ?string $keysDir = null, bool $checkJtiInDb = false, mixed $db = null): ?array
    {
        unset($jwt, $keysDir, $checkJtiInDb, $db);
        throw self::missing();
    }

    public static function generateRefreshToken(int $userId, ?int $ttl = null, ?string $keysDir = null): array
    {
        unset($userId, $ttl, $keysDir);
        throw self::missing();
    }

    public static function validateRefreshTokenRaw(string $rawToken, string $storedHashBin, ?string $keysDir = null): bool
    {
        unset($rawToken, $storedHashBin, $keysDir);
        throw self::missing();
    }
}
