// File: libs/RBAC.php
<?php
declare(strict_types=1);

/**
 * RBAC helper
 * - assignRole(PDO $db, int $userId, mixed $roleIdOrName)
 * - revokeRole(PDO $db, int $userId, mixed $roleIdOrName)
 * - userHasRole(PDO $db, int $userId, string $roleName): bool
 * - createRole(PDO $db, string $name, ?string $description = null): int (role id)
 *
 * Conventions: PSR-12, class PascalCase, methods camelCase. Uses PDO prepared statements.
 */
class RBAC
{
    public static function assignRole(PDO $db, int $userId, $roleIdOrName): bool
    {
        $db->beginTransaction();
        try {
            $roleId = self::resolveRoleId($db, $roleIdOrName);
            if ($roleId === null) {
                // create role automatically if name provided
                if (is_string($roleIdOrName)) {
                    $roleId = self::createRole($db, $roleIdOrName);
                } else {
                    throw new InvalidArgumentException('Role not found');
                }
            }

            $stmt = $db->prepare('INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (:uid, :rid)');
            $stmt->execute([':uid' => $userId, ':rid' => $roleId]);
            $db->commit();
            return true;
        } catch (Throwable $e) {
            if ($db->inTransaction()) $db->rollBack();
            error_log('RBAC::assignRole error: ' . $e->getMessage());
            return false;
        }
    }

    public static function revokeRole(PDO $db, int $userId, $roleIdOrName): bool
    {
        try {
            $roleId = self::resolveRoleId($db, $roleIdOrName);
            if ($roleId === null) return false;
            $stmt = $db->prepare('DELETE FROM user_roles WHERE user_id = :uid AND role_id = :rid');
            $stmt->execute([':uid' => $userId, ':rid' => $roleId]);
            return true;
        } catch (Throwable $e) {
            error_log('RBAC::revokeRole error: ' . $e->getMessage());
            return false;
        }
    }

    public static function userHasRole(PDO $db, int $userId, string $roleName): bool
    {
        try {
            $stmt = $db->prepare('SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = :uid AND r.name = :rname LIMIT 1');
            $stmt->execute([':uid' => $userId, ':rname' => $roleName]);
            return (bool)$stmt->fetchColumn();
        } catch (Throwable $e) {
            error_log('RBAC::userHasRole error: ' . $e->getMessage());
            return false;
        }
    }

    public static function getRolesForUser(PDO $db, int $userId): array
    {
        try {
            $stmt = $db->prepare('SELECT r.* FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = :uid');
            $stmt->execute([':uid' => $userId]);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (Throwable $e) {
            error_log('RBAC::getRolesForUser error: ' . $e->getMessage());
            return [];
        }
    }

    public static function createRole(PDO $db, string $name, ?string $description = null): ?int
    {
        try {
            $stmt = $db->prepare('INSERT INTO roles (name, description, created_at) VALUES (:name, :desc, NOW())');
            $stmt->execute([':name' => $name, ':desc' => $description]);
            return (int)$db->lastInsertId();
        } catch (PDOException $e) {
            // If role exists, return its id
            try {
                $stmt = $db->prepare('SELECT id FROM roles WHERE name = :name LIMIT 1');
                $stmt->execute([':name' => $name]);
                $id = $stmt->fetchColumn();
                return $id !== false ? (int)$id : null;
            } catch (Throwable $ex) {
                error_log('RBAC::createRole error: ' . $e->getMessage());
                return null;
            }
        }
    }

    private static function resolveRoleId(PDO $db, $roleIdOrName): ?int
    {
        if (is_int($roleIdOrName) || ctype_digit((string)$roleIdOrName)) {
            return (int)$roleIdOrName;
        }
        if (is_string($roleIdOrName)) {
            $stmt = $db->prepare('SELECT id FROM roles WHERE name = :name LIMIT 1');
            $stmt->execute([':name' => $roleIdOrName]);
            $id = $stmt->fetchColumn();
            return $id !== false ? (int)$id : null;
        }
        return null;
    }
}