<?php
// File: libs/PaymentGatewayInterface.php
// -----------------------------
declare(strict_types=1);

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