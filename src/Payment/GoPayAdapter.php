<?php

declare(strict_types=1);

namespace BlackCat\Core\Payment;

use BlackCat\Core\Database;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Compatibility facade for the legacy `BlackCat\Core\Payment\GoPayAdapter` name.
 *
 * If `blackcatacademy/blackcat-gopay` is installed, this file aliases:
 * `BlackCat\GoPay\GoPayAdapter`.
 */
if (class_exists(\BlackCat\GoPay\GoPayAdapter::class)) {
    class_alias(\BlackCat\GoPay\GoPayAdapter::class, __NAMESPACE__ . '\\GoPayAdapter');
    return;
}

final class GoPayAdapter
{
    public function __construct(
        Database $db,
        PaymentGatewayInterface $gopayClient,
        LoggerInterface $logger,
        ?object $mailer = null,
        string $notificationUrl = '',
        string $returnUrl = '',
        ?CacheInterface $cache = null
    ) {
        unset($db, $gopayClient, $logger, $mailer, $notificationUrl, $returnUrl, $cache);
        throw new \RuntimeException('GoPayAdapter moved to blackcat-gopay (install blackcatacademy/blackcat-gopay).');
    }

    public function createPaymentFromOrder(int $orderId, string $idempotencyKey): array
    {
        unset($orderId, $idempotencyKey);
        throw new \RuntimeException('GoPayAdapter moved to blackcat-gopay (install blackcatacademy/blackcat-gopay).');
    }

    public function handleNotify(string $gwId, ?bool $allowCreate = null): array
    {
        unset($gwId, $allowCreate);
        throw new \RuntimeException('GoPayAdapter moved to blackcat-gopay (install blackcatacademy/blackcat-gopay).');
    }

    public function fetchStatus(string $gopayPaymentId): array
    {
        unset($gopayPaymentId);
        throw new \RuntimeException('GoPayAdapter moved to blackcat-gopay (install blackcatacademy/blackcat-gopay).');
    }

    public function refundPayment(string $gopayPaymentId, float $amount): array
    {
        unset($gopayPaymentId, $amount);
        throw new \RuntimeException('GoPayAdapter moved to blackcat-gopay (install blackcatacademy/blackcat-gopay).');
    }

    public function lookupIdempotency(string $idempotencyKey): ?array
    {
        unset($idempotencyKey);
        throw new \RuntimeException('GoPayAdapter moved to blackcat-gopay (install blackcatacademy/blackcat-gopay).');
    }

    public function persistIdempotency(string $idempotencyKey, array $payload, int $paymentId): void
    {
        unset($idempotencyKey, $payload, $paymentId);
        throw new \RuntimeException('GoPayAdapter moved to blackcat-gopay (install blackcatacademy/blackcat-gopay).');
    }
}
