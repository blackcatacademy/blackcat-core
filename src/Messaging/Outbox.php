<?php
declare(strict_types=1);

namespace BlackCat\Core\Messaging;

use BlackCat\Core\Database;
use Psr\Log\LoggerInterface;

/**
 * Compatibility facade for the legacy `BlackCat\Core\Messaging\Outbox` name.
 *
 * If `blackcatacademy/blackcat-messaging` is installed, this file aliases the real implementation:
 * `BlackCat\Messaging\CoreCompat\CoreOutbox`.
 *
 * Otherwise it throws a clear runtime error.
 */
if (class_exists('BlackCat\\Messaging\\CoreCompat\\CoreOutbox')) {
    class_alias('BlackCat\\Messaging\\CoreCompat\\CoreOutbox', __NAMESPACE__ . '\\Outbox');
    return;
}

final class Outbox
{
    public function __construct(Database $db, ?LoggerInterface $logger = null, string $table = 'outbox')
    {
        unset($db, $logger, $table);
        throw new \RuntimeException('blackcat-messaging is required (composer require blackcatacademy/blackcat-messaging).');
    }

    public function enqueue(
        string $topic,
        array $payload,
        ?string $partitionKey = null,
        ?string $dedupKey = null,
        array $headers = [],
        ?\DateTimeInterface $availableAt = null,
        array $notifications = []
    ): void {
        unset($topic, $payload, $partitionKey, $dedupKey, $headers, $availableAt, $notifications);
        throw new \RuntimeException('blackcat-messaging is required (composer require blackcatacademy/blackcat-messaging).');
    }

    /**
     * Flush pending events via a sender/transport.
     *
     * @param callable|object $sender
     */
    public function flush(callable|object $sender, int $limit = 100): int
    {
        unset($sender, $limit);
        throw new \RuntimeException('blackcat-messaging is required (composer require blackcatacademy/blackcat-messaging).');
    }
}
