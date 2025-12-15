<?php
declare(strict_types=1);

/**
 * Compatibility facade for the legacy global `RBAC` helper.
 *
 * If `blackcatacademy/blackcat-rbac` is installed, this file aliases:
 * `BlackCat\Rbac\CoreCompat\CoreRBAC`.
 */
if (class_exists('BlackCat\\Rbac\\CoreCompat\\CoreRBAC')) {
    class_alias('BlackCat\\Rbac\\CoreCompat\\CoreRBAC', 'RBAC');
    return;
}

final class RBAC
{
    private function __construct() {}

    private static function missing(): \RuntimeException
    {
        return new \RuntimeException('RBAC implementation not installed. Install blackcatacademy/blackcat-rbac.');
    }

    public static function assignRole(\PDO $db, int $userId, mixed $roleIdOrName): bool
    {
        unset($db, $userId, $roleIdOrName);
        throw self::missing();
    }

    public static function revokeRole(\PDO $db, int $userId, mixed $roleIdOrName): bool
    {
        unset($db, $userId, $roleIdOrName);
        throw self::missing();
    }

    public static function userHasRole(\PDO $db, int $userId, string $roleName): bool
    {
        unset($db, $userId, $roleName);
        throw self::missing();
    }

    public static function getRolesForUser(\PDO $db, int $userId): array
    {
        unset($db, $userId);
        throw self::missing();
    }

    public static function createRole(\PDO $db, string $name, ?string $description = null): ?int
    {
        unset($db, $name, $description);
        throw self::missing();
    }
}
