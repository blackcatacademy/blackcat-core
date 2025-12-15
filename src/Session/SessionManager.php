<?php
declare(strict_types=1);

namespace BlackCat\Core\Session;

use BlackCat\Core\Database;
use Psr\SimpleCache\CacheInterface;

// The session implementation lives in the dedicated blackcat-sessions module.
if (class_exists('BlackCat\\Sessions\\Php\\SessionManager')) {
    class_alias('BlackCat\\Sessions\\Php\\SessionManager', __NAMESPACE__ . '\\SessionManager');
    return;
}

final class SessionManager
{
    private function __construct() {}

    public static function initCache(CacheInterface $cache, int $ttlSeconds = 120): void
    {
        unset($cache, $ttlSeconds);
        throw new \RuntimeException('blackcat-sessions is required (composer require blackcatacademy/blackcat-sessions).');
    }

    public static function createSession(
        Database $db,
        int $userId,
        int $days = 30,
        bool $allowMultiple = true,
        string $samesite = 'Lax'
    ): string {
        unset($db, $userId, $days, $allowMultiple, $samesite);
        throw new \RuntimeException('blackcat-sessions is required (composer require blackcatacademy/blackcat-sessions).');
    }

    public static function validateSession(Database $db): ?int
    {
        unset($db);
        throw new \RuntimeException('blackcat-sessions is required (composer require blackcatacademy/blackcat-sessions).');
    }

    public static function destroySession(Database $db): void
    {
        unset($db);
        throw new \RuntimeException('blackcat-sessions is required (composer require blackcatacademy/blackcat-sessions).');
    }
}
