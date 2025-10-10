<?php
declare(strict_types=1);

namespace BlackCat\Core\Helpers;

use BlackCat\Core\Database;
use Psr\Log\LoggerInterface;

/**
 * DeferredHelper
 *
 * - fronta pro deferred callbacky / jednoduché SQL payloady před tím, než je DB inicializována
 * - flush() volat po Database::init(...) (bootstrap)
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
     * Přidá do fronty callable nebo SQL payload.
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
     * Explicitně nastavit PSR logger - použitelný i před inicializací Database.
     */
    public static function setLogger(?LoggerInterface $logger): void
    {
        self::$logger = $logger;
    }

    /**
     * Preferovaný logger: nejdříve explicitně nastavený (setLogger),
     * pak logger z Database (pokud je DB initializována a vrací logger),
     * jinak null.
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
     * Reportuje throwable přes PSR logger (pokud je dostupný).
     * Ticho v případě absence loggeru - logger nesmí nikdy shodit aplikaci.
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
     * Provede všechny položky fronty.
     *
     * - pokud je položka callable -> zavolat
     * - pokud je položka sql payload -> pokusit se vykonat přes Database::getInstance()->execute()
     *
     * Chyby jsou zalogovány přes PSR logger (pokud je dostupný), jinak jsou potichu ignorovány.
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
                    // pokud ještě není DB inicializována, vrátíme payload zpět a ukončíme flush
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

    /* ----------------- Utility pro testování / introspekci ----------------- */

    public static function getQueueSize(): int
    {
        return count(self::$queue);
    }

    public static function clearQueue(): void
    {
        self::$queue = [];
    }
}