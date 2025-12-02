<?php
declare(strict_types=1);

namespace BlackCat\Core\Database\Observer;

use BlackCat\DatabaseSync\Hook\HookDispatcher;
use BlackCat\DatabaseSync\Event\SyncEvent;
use Psr\Log\LoggerInterface;

final class SyncEventObserver
{
    public function __construct(
        private readonly HookDispatcher $dispatcher,
        private readonly LoggerInterface $logger,
    ) {}

    public function attach(): void
    {
        $this->dispatcher->on('sync.start', function (SyncEvent $event): void {
            $this->logger->info('sync-start', ['link' => $event->link, 'payload' => $event->payload]);
        });
        $this->dispatcher->on('sync.end', function (SyncEvent $event): void {
            $this->logger->info('sync-end', ['link' => $event->link, 'payload' => $event->payload]);
        });
        $this->dispatcher->on('sync.fail', function (SyncEvent $event): void {
            $this->logger->error('sync-fail', ['link' => $event->link, 'payload' => $event->payload]);
        });
    }
}
