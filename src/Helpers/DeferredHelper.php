<?php
declare(strict_types=1);

namespace BlackCat\Core\Helpers;

use BlackCat\Core\Database;
use Psr\Log\LoggerInterface;

/**
 * DeferredHelper
 *
 * - Queue for deferred callbacks / simple SQL payloads before Database is initialized
 * - Call flush() after Database::init(...) (bootstrap)
 */
final class DeferredHelper
{
    private const MAX_QUEUE = 1000;

    /** @var array<int, callable|array> */
    private static array $queue = [];

    private static bool $isProcessing = false;
    private static ?LoggerInterface $logger = null;

    private function __construct() {}

    /**
     * Enqueue a callable or an SQL payload.
     *
     * SQL payload = ['sql' => string, 'params' => array]
     *
     * @param callable|array $item
     */
    public static function enqueue(callable|array $item): void
    {
        if (count(self::$queue) >= self::MAX_QUEUE) {
            array_shift(self::$queue);
        }

        if (is_callable($item)) {
            self::$queue[] = $item;
            return;
        }

        if (is_array($item)) {
            if (!isset($item['sql']) || !is_string($item['sql'])) {
                return;
            }
            if (!isset($item['params']) || !is_array($item['params'])) {
                $item['params'] = [];
            }
            self::$queue[] = $item;
            return;
        }
    }

    /**
     * Explicitly set a PSR logger (usable even before Database initialization).
     */
    public static function setLogger(?LoggerInterface $logger): void
    {
        self::$logger = $logger;
    }

    /**
     * Preferred logger resolution:
     * - explicit logger (setLogger)
     * - Database logger (if initialized and available)
     * - otherwise null
     */
    private static function getLogger(): ?LoggerInterface
    {
        if (self::$logger !== null) {
            return self::$logger;
        }

        if (!Database::isInitialized()) {
            return null;
        }

        try {
            return Database::getInstance()->getLogger();
        } catch (\Throwable $_) {
            return null;
        }
    }

    /**
     * Reports a throwable via PSR logger (if available).
     * Silent when logger is absent — logging must never crash the app.
     */
    private static function reportThrowable(\Throwable $e, ?string $context = null): void
    {
        $logger = self::getLogger();
        if ($logger !== null) {
            try {
                $msg = 'DeferredHelper exception' . ($context !== null ? " ({$context})" : '');
                $logger->error($msg, ['exception' => $e]);
            } catch (\Throwable $_) {
                // swallow - logging must not throw
            }
        }
        // Pure PSR approach: do not fallback to error_log here.
        // If you want a fallback, you could add an optional boolean flag and call error_log().
    }

    /**
     * Execute all queued items.
     *
     * - if item is callable -> invoke it
     * - if item is an SQL payload -> execute via Database::getInstance()->execute()
     *
     * Errors are logged via PSR logger (if available), otherwise silently ignored.
     */
    public static function flush(): void
    {
        if (self::$isProcessing || empty(self::$queue)) {
            return;
        }

        self::$isProcessing = true;

        while (!empty(self::$queue)) {
            $item = array_shift(self::$queue);

            try {
                if (is_callable($item)) {
                    try {
                        ($item)();
                    } catch (\Throwable $e) {
                        self::reportThrowable($e, 'callable');
                    }
                    continue;
                }

                if (is_array($item) && isset($item['sql'])) {
                    // If DB is not initialized yet, push payload back and stop flushing.
                    if (!Database::isInitialized()) {
                        array_unshift(self::$queue, $item);
                        break;
                    }

                    try {
                        Database::getInstance()->execute($item['sql'], $item['params'] ?? []);
                    } catch (\Throwable $e) {
                        self::reportThrowable($e, 'sql_payload');
                    }
                    continue;
                }

                // unknown item -> ignore
            } catch (\Throwable $e) {
                self::reportThrowable($e, 'flush_outer');
            }
        }

        self::$isProcessing = false;
    }

    /* ----------------- Test / introspection utilities ----------------- */

    public static function getQueueSize(): int
    {
        return count(self::$queue);
    }

    public static function clearQueue(): void
    {
        self::$queue = [];
    }
}
