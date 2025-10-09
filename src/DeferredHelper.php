<?php
declare(strict_types=1);

final class DeferredHelper
{
    private const MAX_QUEUE = 1000;
    private static array $queue = [];
    private static bool $isProcessing = false;

    private function __construct() {}

    /**
     * Přidá callable do fronty pro deferred execution.
     */
    public static function enqueue(callable $callback): void
    {
        if (count(self::$queue) >= self::MAX_QUEUE) {
            array_shift(self::$queue); // odstraní nejstarší
        }
        self::$queue[] = $callback;
    }

    /**
     * Spustí všechny deferred callbacky.
     * Chyby jsou zachyceny a odeslány do Loggeru (pokud existuje),
     * jinak do error_log. Fronta je vyprázdněna po dokončení.
     */
    public static function flush(): void
    {
        if (self::$isProcessing || empty(self::$queue)) {
            return;
        }

        self::$isProcessing = true;

        while (!empty(self::$queue)) {
            $cb = array_shift(self::$queue);
            try {
                $cb();
            } catch (\Throwable $e) {
                if (class_exists('Logger')) {
                    try {
                        Logger::systemError($e);
                    } catch (\Throwable $_) {
                        error_log('[DeferredHelper fallback] ' . $e->getMessage());
                    }
                } else {
                    error_log('[DeferredHelper] ' . $e->getMessage());
                }
            }
        }

        self::$isProcessing = false;
    }
}