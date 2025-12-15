<?php

declare(strict_types=1);

namespace BlackCat\Core\Security;

/**
 * Compatibility facade for the legacy `BlackCat\Core\Security\LoginLimiter` name.
 *
 * Delegates to `BlackCat\Auth\Security\LoginLimiter` when `blackcatacademy/blackcat-auth` is installed.
 * Otherwise it becomes a no-op and returns safe defaults.
 */
final class LoginLimiter
{
    private function __construct() {}

    private static function impl(): ?string
    {
        return \class_exists('BlackCat\\Auth\\Security\\LoginLimiter')
            ? 'BlackCat\\Auth\\Security\\LoginLimiter'
            : null;
    }

    public static function registerAttempt(?string $ip = null, bool $success = false, ?int $userId = null, ?string $usernameHash = null): void
    {
        $impl = self::impl();
        if ($impl === null) {
            return;
        }
        try {
            $impl::registerAttempt($ip, $success, $userId, $usernameHash);
        } catch (\Throwable) {
        }
    }

    public static function isBlocked(?string $ip = null, int $maxAttempts = 5, int $windowSec = 300): bool
    {
        $impl = self::impl();
        if ($impl === null) {
            return false;
        }
        try {
            return (bool)$impl::isBlocked($ip, $maxAttempts, $windowSec);
        } catch (\Throwable) {
            return false;
        }
    }

    public static function getAttemptsCount(?string $ip = null, int $windowSec = 300): int
    {
        $impl = self::impl();
        if ($impl === null) {
            return 0;
        }
        try {
            return (int)$impl::getAttemptsCount($ip, $windowSec);
        } catch (\Throwable) {
            return 0;
        }
    }

    public static function getRemainingAttempts(?string $ip = null, int $maxAttempts = 5, int $windowSec = 300): int
    {
        $impl = self::impl();
        if ($impl === null) {
            return 0;
        }
        try {
            return (int)$impl::getRemainingAttempts($ip, $maxAttempts, $windowSec);
        } catch (\Throwable) {
            return 0;
        }
    }

    public static function getSecondsUntilUnblock(?string $ip = null, int $maxAttempts = 5, int $windowSec = 300): int
    {
        $impl = self::impl();
        if ($impl === null) {
            return 0;
        }
        try {
            return (int)$impl::getSecondsUntilUnblock($ip, $maxAttempts, $windowSec);
        } catch (\Throwable) {
            return 0;
        }
    }

    public static function registerRegisterAttempt(bool $success = false, ?int $userId = null, ?string $userAgent = null, ?array $meta = null, ?string $error = null): void
    {
        $impl = self::impl();
        if ($impl === null) {
            return;
        }
        try {
            $impl::registerRegisterAttempt($success, $userId, $userAgent, $meta, $error);
        } catch (\Throwable) {
        }
    }

    public static function isRegisterBlocked(?string $ip = null, int $maxAttempts = 5, int $windowSec = 300): bool
    {
        $impl = self::impl();
        if ($impl === null) {
            return false;
        }
        try {
            return (bool)$impl::isRegisterBlocked($ip, $maxAttempts, $windowSec);
        } catch (\Throwable) {
            return false;
        }
    }

    public static function getRegisterAttemptsCount(?string $ip = null, int $windowSec = 300): int
    {
        $impl = self::impl();
        if ($impl === null) {
            return 0;
        }
        try {
            return (int)$impl::getRegisterAttemptsCount($ip, $windowSec);
        } catch (\Throwable) {
            return 0;
        }
    }

    public static function getRegisterRemainingAttempts(?string $ip = null, int $maxAttempts = 5, int $windowSec = 300): int
    {
        $impl = self::impl();
        if ($impl === null) {
            return 0;
        }
        try {
            return (int)$impl::getRegisterRemainingAttempts($ip, $maxAttempts, $windowSec);
        } catch (\Throwable) {
            return 0;
        }
    }

    public static function getRegisterSecondsUntilUnblock(?string $ip = null, int $maxAttempts = 5, int $windowSec = 300): int
    {
        $impl = self::impl();
        if ($impl === null) {
            return 0;
        }
        try {
            return (int)$impl::getRegisterSecondsUntilUnblock($ip, $maxAttempts, $windowSec);
        } catch (\Throwable) {
            return 0;
        }
    }

    public static function cleanup(int $olderThanSec = 86400): void
    {
        $impl = self::impl();
        if ($impl === null) {
            return;
        }
        try {
            $impl::cleanup($olderThanSec);
        } catch (\Throwable) {
        }
    }
}
