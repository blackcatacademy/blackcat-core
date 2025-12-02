<?php
declare(strict_types=1);

namespace BlackCat\Core\Messaging;

use BlackCat\Core\Database;
use Psr\Log\LoggerInterface;

/**
 * Inbox provides idempotent message consumption (one handler execution per message_id).
 */
final class Inbox
{
    public function __construct(
        private readonly Database $db,
        private readonly ?LoggerInterface $logger = null,
        private readonly string $table = 'inbox'
    ) {}

    /**
     * Processes a message exactly once.
     *
     * @param callable $handler Invoked inside the same transaction; throw on failure.
     */
    public function process(string $messageId, string $topic, callable $handler): bool
    {
        $table = $this->db->quoteIdent($this->table);
        $meta  = ['component' => 'inbox', 'message_id' => $messageId, 'topic' => $topic];

        return (bool)$this->db->txWithMeta(
            function () use ($table, $messageId, $topic, $handler, $meta): bool {
                $now = $this->nowExpression();

                if (!$this->insertEnvelope($table, $messageId, $topic, $meta)) {
                    return false;
                }

                try {
                    $handler();
                    $this->db->execute(
                        "UPDATE {$table}
                            SET processed_at = {$now},
                                last_error    = NULL
                          WHERE message_id = :id",
                        [':id' => $messageId]
                    );
                    return true;
                } catch (\Throwable $e) {
                    $err = \substr($e->getMessage() ?? '', 0, 2000);
                    $this->db->execute(
                        "UPDATE {$table}
                            SET last_error = :err
                          WHERE message_id = :id",
                        [':err' => $err, ':id' => $messageId]
                    );
                    $this->logger?->error('inbox-handler-failed', ['error' => $err] + $meta);
                    throw $e;
                }
            },
            $meta,
            ['readOnly' => false]
        );
    }

    public function ack(string $messageId): void
    {
        $table = $this->db->quoteIdent($this->table);
        $this->db->execute(
            "UPDATE {$table} SET acknowledged_at = :ts WHERE message_id = :id",
            [
                ':ts' => (new \DateTimeImmutable())->format('Y-m-d H:i:s'),
                ':id' => $messageId,
            ]
        );
    }

    private function insertEnvelope(string $table, string $messageId, string $topic, array $meta): bool
    {
        try {
            $this->db->execute(
                "INSERT INTO {$table} (message_id, topic) VALUES (:id, :topic)",
                [':id' => $messageId, ':topic' => $topic]
            );
        } catch (\Throwable $e) {
            if ($this->isDuplicateError($e)) {
                $this->logger?->info('inbox-duplicate', $meta);
                return false;
            }
            throw $e;
        }

        return true;
    }

    public function cleanup(string $status = 'processed', int $olderThanDays = 30): int
    {
        $field = $status === 'acknowledged' ? 'acknowledged_at' : 'processed_at';
        $table = $this->db->quoteIdent($this->table);
        $sql = "DELETE FROM {$table} WHERE {$field} < DATE_SUB(NOW(), INTERVAL :days DAY)";
        return $this->db->execute($sql, [':days' => $olderThanDays]);
    }

    private function isDuplicateError(\Throwable $e): bool
    {
        $message = \strtolower($e->getMessage() ?? '');
        return \str_contains($message, 'duplicate') || \str_contains($message, 'unique');
    }

    private function nowExpression(): string
    {
        if ($this->db->isPg() || $this->db->isMysql()) {
            return 'NOW()';
        }
        return 'CURRENT_TIMESTAMP';
    }
}
