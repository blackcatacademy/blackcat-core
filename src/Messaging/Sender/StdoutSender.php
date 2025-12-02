<?php
declare(strict_types=1);

namespace BlackCat\Core\Messaging\Sender;

final class StdoutSender implements OutboxSender
{
    public function __construct(private readonly bool $decodePayload = true) {}

    public function send(array $row): bool
    {
        $payload = $this->decodeMaybeJson($row['payload'] ?? null, $this->decodePayload);
        $headers = $this->decodeMaybeJson($row['headers'] ?? null, true);

        $record = [
            'id'      => $row['id'] ?? null,
            'topic'   => $row['topic'] ?? null,
            'key'     => $row['part_key'] ?? null,
            'payload' => $payload,
            'headers' => $headers,
            'attempt' => $row['attempts'] ?? 0,
            'ts'      => (new \DateTimeImmutable())->format(\DateTimeInterface::ATOM),
        ];

        $json = \json_encode($record, \JSON_UNESCAPED_UNICODE | \JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            return false;
        }

        $stream = \defined('STDOUT') ? \STDOUT : \fopen('php://stdout', 'wb');
        if ($stream === false) {
            return false;
        }

        \fwrite($stream, $json . \PHP_EOL);

        if (!\defined('STDOUT')) {
            \fclose($stream);
        }

        return true;
    }

    private function decodeMaybeJson(mixed $value, bool $enabled): mixed
    {
        if (!$enabled || !\is_string($value) || $value === '') {
            return $value;
        }
        $decoded = \json_decode($value, true);
        return \json_last_error() === \JSON_ERROR_NONE ? $decoded : $value;
    }
}
