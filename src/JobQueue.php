<?php
declare(strict_types=1);

/**
 * Compatibility facade for the legacy global `JobQueue` helper.
 *
 * If `blackcatacademy/blackcat-jobs` is installed, this file aliases:
 * `BlackCat\Jobs\CoreCompat\JobQueue`.
 */
if (class_exists(\BlackCat\Jobs\CoreCompat\JobQueue::class)) {
    class_alias(\BlackCat\Jobs\CoreCompat\JobQueue::class, 'JobQueue');
    return;
}

final class JobQueue
{
    private static function missing(): \RuntimeException
    {
        return new \RuntimeException('JobQueue implementation not installed. Install blackcatacademy/blackcat-jobs.');
    }

    public function __construct(\PDO $db)
    {
        unset($db);
        throw self::missing();
    }

    public function push(array $payload, int $delaySeconds = 0, int $maxAttempts = 5): mixed
    {
        unset($payload, $delaySeconds, $maxAttempts);
        throw self::missing();
    }

    public function fetchNext(): mixed
    {
        throw self::missing();
    }

    public function markSuccess(int|string $id): void
    {
        unset($id);
        throw self::missing();
    }

    public function markFailed(int|string $id, string $errorMsg): void
    {
        unset($id, $errorMsg);
        throw self::missing();
    }
}
