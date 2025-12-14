<?php
declare(strict_types=1);

namespace BlackCat\Core\Messaging\Sender;

// Sender implementations live in the dedicated blackcat-messaging module.
if (class_exists(\BlackCat\Messaging\CoreCompat\CoreStdoutSender::class)) {
    class_alias(\BlackCat\Messaging\CoreCompat\CoreStdoutSender::class, __NAMESPACE__ . '\\StdoutSender');
    return;
}

final class StdoutSender implements OutboxSender
{
    public function __construct(...$args)
    {
        unset($args);
        throw new \RuntimeException('blackcat-messaging is required (composer require blackcatacademy/blackcat-messaging).');
    }

    public function send(array $row): bool
    {
        unset($row);
        throw new \RuntimeException('blackcat-messaging is required (composer require blackcatacademy/blackcat-messaging).');
    }
}
