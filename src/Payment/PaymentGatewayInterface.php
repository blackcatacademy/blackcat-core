<?php

declare(strict_types=1);

namespace BlackCat\Core\Payment;

/**
 * Compatibility facade for the legacy `BlackCat\Core\Payment\PaymentGatewayInterface` name.
 *
 * If `blackcatacademy/blackcat-gopay` is installed, this file aliases:
 * `BlackCat\GoPay\PaymentGatewayInterface`.
 */
if (interface_exists(\BlackCat\GoPay\PaymentGatewayInterface::class)) {
    class_alias(\BlackCat\GoPay\PaymentGatewayInterface::class, __NAMESPACE__ . '\\PaymentGatewayInterface');
    return;
}

interface PaymentGatewayInterface
{
    /**
     * Create payment using gateway payload. Return whatever underlying SDK returns (object/array).
     * @param array $payload
     * @return mixed
     */
    public function createPayment(array $payload);

    /**
     * Retrieve status for gateway payment id.
     * @param string $gatewayPaymentId
     * @return mixed
     */
    public function getStatus(string $gatewayPaymentId);

    /**
     * Refund payment. $args is delegated to underlying SDK (amount in smallest unit etc.).
     * @param string $gatewayPaymentId
     * @param array $args
     * @return mixed
     */
    public function refundPayment(string $gatewayPaymentId, array $args);
}
