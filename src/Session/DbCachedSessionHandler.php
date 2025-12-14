<?php
declare(strict_types=1);

namespace BlackCat\Core\Session;

// The session handler implementation lives in the dedicated blackcat-sessions module.
if (class_exists(\BlackCat\Sessions\Php\DbCachedSessionHandler::class)) {
    class_alias(\BlackCat\Sessions\Php\DbCachedSessionHandler::class, __NAMESPACE__ . '\\DbCachedSessionHandler');
    return;
}

final class DbCachedSessionHandler implements \SessionHandlerInterface
{
    public function __construct(...$args)
    {
        unset($args);
        throw new \RuntimeException('blackcat-sessions is required (composer require blackcatacademy/blackcat-sessions).');
    }

    public function open(string $savePath, string $sessionName): bool { return true; }
    public function close(): bool { return true; }
    public function read(string $id): string { return ''; }
    public function write(string $id, string $data): bool { return false; }
    public function destroy(string $id): bool { return true; }
    public function gc(int $max_lifetime): int|false { return 0; }
}

