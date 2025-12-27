<?php

declare(strict_types=1);

namespace BlackCat\Config\Runtime;

/**
 * Minimal blackcat-config stub for blackcat-core unit tests.
 *
 * blackcat-core treats blackcat-config as an optional dependency and only needs:
 * - Config::isInitialized()
 * - Config::repo()
 *
 * The extra methods are present to keep existing tests simple.
 */
final class Config
{
    private static ?object $repo = null;

    public static function isInitialized(): bool
    {
        return self::$repo !== null;
    }

    public static function initFromFirstAvailableJsonFileIfNeeded(): void
    {
        // no-op for tests
    }

    public static function repo(): object
    {
        if (self::$repo === null) {
            throw new \RuntimeException('Config is not initialized.');
        }
        return self::$repo;
    }

    public static function _setRepo(object $repo): void
    {
        self::$repo = $repo;
    }

    public static function _clearRepo(): void
    {
        self::$repo = null;
    }
}

/**
 * Minimal stub to let blackcat-core detect "blackcat-config is installed" in isolated tests.
 *
 * In real deployments, this is a fully-featured repository class.
 */
final class ConfigRepository
{
}
