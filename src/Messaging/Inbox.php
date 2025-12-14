<?php
declare(strict_types=1);

namespace BlackCat\Core\Messaging;

use BlackCat\Core\Database;
use Psr\Log\LoggerInterface;

/**
 * Compatibility facade for the legacy `BlackCat\Core\Messaging\Inbox` name.
 *
 * If `blackcatacademy/blackcat-messaging` is installed, this file aliases the real implementation:
 * `BlackCat\Messaging\CoreCompat\CoreInbox`.
 *
 * Otherwise it throws a clear runtime error.
 */
if (class_exists(\BlackCat\Messaging\CoreCompat\CoreInbox::class)) {
    class_alias(\BlackCat\Messaging\CoreCompat\CoreInbox::class, __NAMESPACE__ . '\\Inbox');
    return;
}

final class Inbox
{
    public function __construct(Database $db, ?LoggerInterface $logger = null, string $table = 'inbox')
    {
        unset($db, $logger, $table);
        throw new \RuntimeException('blackcat-messaging is required (composer require blackcatacademy/blackcat-messaging).');
    }

    /**
     * Processes a message exactly once.
     *
     * @param callable $handler Invoked inside the same transaction; throw on failure.
     */
    public function process(string $messageId, string $topic, callable $handler): bool
    {
        unset($messageId, $topic, $handler);
        throw new \RuntimeException('blackcat-messaging is required (composer require blackcatacademy/blackcat-messaging).');
    }

    public function ack(string $messageId): void
    {
        unset($messageId);
        throw new \RuntimeException('blackcat-messaging is required (composer require blackcatacademy/blackcat-messaging).');
    }

    public function cleanup(string $status = 'processed', int $olderThanDays = 30): int
    {
        unset($status, $olderThanDays);
        throw new \RuntimeException('blackcat-messaging is required (composer require blackcatacademy/blackcat-messaging).');
    }
}
