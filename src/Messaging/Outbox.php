<?php
declare(strict_types=1);

namespace BlackCat\Core\Messaging;

use BlackCat\Core\Database;
use BlackCat\Core\Messaging\Sender\OutboxSender;
use Psr\Log\LoggerInterface;

/**
 * Transactional outbox – stores events inside the primary database and later delivers them via a worker.
 */
final class Outbox
{
    public function __construct(
        private readonly Database $db,
        private readonly ?LoggerInterface $logger = null,
        private readonly string $table = 'outbox'
    ) {}

    /**
     * @param array<string,mixed>      $payload
     * @param array<string,string|int> $headers
     */
    public function enqueue(
        string $topic,
        array $payload,
        ?string $partitionKey = null,
        ?string $dedupKey = null,
        array $headers = [],
        ?\DateTimeInterface $availableAt = null,
        array $notifications = []
    ): void {
        $payloadJson = \json_encode($payload, \JSON_UNESCAPED_UNICODE | \JSON_UNESCAPED_SLASHES);
        $headersJson = \json_encode($headers, \JSON_UNESCAPED_UNICODE | \JSON_UNESCAPED_SLASHES);

        if ($payloadJson === false || $headersJson === false) {
            throw new \RuntimeException('Failed to encode outbox payload/headers.');
        }

        $sql = \sprintf(
            'INSERT INTO %s (topic, part_key, payload, headers, dedup_key, available_at, notifications)
             VALUES (:topic, :key, :payload, :headers, :dedup, :available_at, :notifications)',
            $this->db->quoteIdent($this->table)
        );

        $params = [
            ':topic'        => $topic,
            ':key'          => $partitionKey,
            ':payload'      => $payloadJson,
            ':headers'      => $headersJson,
            ':dedup'        => $dedupKey,
            ':available_at' => $availableAt?->format('Y-m-d H:i:s'),
            ':notifications'=> json_encode($notifications, \JSON_UNESCAPED_UNICODE | \JSON_UNESCAPED_SLASHES) ?: '[]',
        ];

        try {
            $this->db->execute($sql, $params);
        } catch (\Throwable $e) {
            if ($dedupKey !== null && $this->isDuplicateError($e)) {
                $this->logger?->info('outbox-duplicate', ['topic' => $topic, 'dedup' => $dedupKey]);
                return;
            }
            throw $e;
        }
    }

    /**
     * Flush pending events via a sender/transport.
     *
     * @param callable|OutboxSender $sender
     */
    public function flush(callable|OutboxSender $sender, int $limit = 100): int
    {
        $limit = \max(1, $limit);
        $rows  = $this->claimBatch($limit);
        $sent  = 0;
        $callback = $sender instanceof OutboxSender ? [$sender, 'send'] : $sender;

        foreach ($rows as $row) {
            try {
                $result = $callback($row);
                if ($result === false) {
                    throw new \RuntimeException('Sender reported failure.');
                }
                $this->markSent((int)$row['id']);
                $sent++;
            } catch (\Throwable $e) {
                $this->markFailed($row, $e);
            }
        }

        return $sent;
    }

    /**
     * @return list<array<string,mixed>>
     */
    private function claimBatch(int $limit): array
    {
        $table = $this->db->quoteIdent($this->table);
        $now   = $this->nowExpression();
        $skipLocked = 'FOR UPDATE SKIP LOCKED';

        if (!$this->db->isPg() && !$this->db->isMysql()) {
            $skipLocked = 'FOR UPDATE';
        }

        $sql = "
            SELECT id, topic, part_key, payload, headers, attempts
              FROM {$table}
             WHERE sent_at IS NULL
               AND (next_attempt_at IS NULL OR next_attempt_at <= {$now})
               AND (available_at IS NULL OR available_at <= {$now})
             ORDER BY id
             LIMIT {$limit}
             {$skipLocked}";

        return $this->db->fetchAll($sql);
    }

    private function markSent(int $id): void
    {
        $table = $this->db->quoteIdent($this->table);
        $row = $this->db->fetchOne("SELECT notifications FROM {$table} WHERE id = :id", [':id' => $id]);
        $this->db->execute(
            "UPDATE {$table}
                SET sent_at = :ts,
                    last_error = NULL
              WHERE id = :id",
            [
                ':ts' => (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s'),
                ':id' => $id,
            ]
        );

        $this->dispatchNotifications($row['notifications'] ?? '[]');
    }

    private function dispatchNotifications(string $json): void
    {
        $items = json_decode($json, true);
        if (!\is_array($items)) {
            return;
        }
        foreach ($items as $note) {
            $type = $note['type'] ?? null;
            if ($type === 'webhook' && isset($note['url'])) {
                $this->notifyWebhook((string)$note['url'], $note['payload'] ?? []);
            }
        }
    }

    private function notifyWebhook(string $url, array $payload): void
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
            CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 5,
        ]);
        $response = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($response === false || $status >= 400) {
            $this->logger?->warning('outbox-webhook-failed', ['url' => $url, 'status' => $status]);
        }
        curl_close($ch);
    }

    /**
     * @param array<string,mixed> $row
     */
    private function markFailed(array $row, \Throwable $e): void
    {
        $table    = $this->db->quoteIdent($this->table);
        $attempts = (int)($row['attempts'] ?? 0);
        $wait     = \min(3600, (int)\pow(2, \min(10, $attempts)) + \random_int(0, 15));
        $nextAt   = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))
            ->modify('+' . $wait . ' seconds')
            ->format('Y-m-d H:i:s');

        $this->db->execute(
            "UPDATE {$table}
                SET attempts = attempts + 1,
                    next_attempt_at = :next_at,
                    last_error = :err
              WHERE id = :id",
            [
                ':next_at' => $nextAt,
                ':err'     => \substr($e->getMessage() ?? '', 0, 2000),
                ':id'      => (int)$row['id'],
            ]
        );

        $this->logger?->warning('outbox-send-failed', [
            'id'         => (int)$row['id'],
            'next_in_s'  => $wait,
            'error'      => $e->getMessage(),
        ]);
    }

    private function nowExpression(): string
    {
        if ($this->db->isPg() || $this->db->isMysql()) {
            return 'NOW()';
        }
        return 'CURRENT_TIMESTAMP';
    }

    private function isDuplicateError(\Throwable $e): bool
    {
        $message = \strtolower($e->getMessage() ?? '');
        return \str_contains($message, 'duplicate') || \str_contains($message, 'unique');
    }
}
