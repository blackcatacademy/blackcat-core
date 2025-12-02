<?php
declare(strict_types=1);

namespace BlackCat\Core\Messaging\Sender;

use Psr\Log\LoggerInterface;

final class WebhookSender implements OutboxSender
{
    public function __construct(private readonly ?LoggerInterface $logger = null) {}

    public function send(array $row): bool
    {
        $payload = json_decode((string)($row['payload'] ?? '{}'), true);
        $headers = json_decode((string)($row['headers'] ?? '{}'), true);
        $url = $headers['webhook_url'] ?? null;
        if (!$url) {
            $this->logger?->warning('webhook-sender-missing-url', ['id' => $row['id'] ?? null]);
            return true;
        }
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
        curl_close($ch);
        if ($response === false || $status >= 400) {
            $this->logger?->warning('webhook-sender-failed', ['url' => $url, 'status' => $status]);
            return false;
        }
        return true;
    }
}
