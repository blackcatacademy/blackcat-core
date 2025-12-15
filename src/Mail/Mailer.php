<?php
declare(strict_types=1);

namespace BlackCat\Core\Mail;

/**
 * Compatibility facade for the legacy `BlackCat\Core\Mail\Mailer` name.
 *
 * If `blackcatacademy/blackcat-mailing` is installed, this file aliases:
 * `BlackCat\Mailing\CoreCompat\CoreMailer`.
 *
 * Otherwise it throws a clear runtime error.
 */
if (class_exists('BlackCat\\Mailing\\CoreCompat\\CoreMailer')) {
    class_alias('BlackCat\\Mailing\\CoreCompat\\CoreMailer', __NAMESPACE__ . '\\Mailer');
    return;
}

final class Mailer
{
    private function __construct() {}

    private static function missing(): \RuntimeException
    {
        return new \RuntimeException(
            'Mailer moved to blackcat-mailing. Use BlackCat\\Mailing\\Queue\\NotificationEnqueuer + BlackCat\\Mailing\\Worker\\NotificationWorker.'
        );
    }

    public static function init(array $config, \PDO $pdo): void
    {
        unset($config, $pdo);
        throw self::missing();
    }

    public static function enqueue(array $payloadArr, int $maxRetries = 0): int
    {
        unset($payloadArr, $maxRetries);
        throw self::missing();
    }

    public static function processPendingNotifications(int $limit = 100): array
    {
        unset($limit);
        throw self::missing();
    }
}
