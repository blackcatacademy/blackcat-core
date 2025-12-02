<?php
declare(strict_types=1);

namespace BlackCat\Core\Messaging\Sender;

/**
 * Contract implemented by transports used with the Outbox worker.
 */
interface OutboxSender
{
    /**
     * @param array<string,mixed> $row Raw outbox row (id, topic, payload, headers, attempts, ...)
     */
    public function send(array $row): bool;
}
