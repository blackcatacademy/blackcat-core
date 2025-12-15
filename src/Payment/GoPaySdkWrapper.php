<?php

declare(strict_types=1);

namespace BlackCat\Core\Payment;

use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Compatibility facade for the legacy `BlackCat\Core\Payment\GoPaySdkWrapper` name.
 *
 * If `blackcatacademy/blackcat-gopay` is installed, this file aliases:
 * `BlackCat\GoPay\GoPaySdkWrapper` and related exception types.
 */
if (class_exists('BlackCat\\GoPay\\GoPaySdkWrapper')) {
    $sdk = 'BlackCat\\GoPay\\GoPaySdkWrapper';
    $tok = 'BlackCat\\GoPay\\GoPayTokenException';
    $http = 'BlackCat\\GoPay\\GoPayHttpException';
    $pay = 'BlackCat\\GoPay\\GoPayPaymentException';

    if (class_exists($tok)) {
        class_alias($tok, __NAMESPACE__ . '\\GoPayTokenException');
    }
    if (class_exists($http)) {
        class_alias($http, __NAMESPACE__ . '\\GoPayHttpException');
    }
    if (class_exists($pay)) {
        class_alias($pay, __NAMESPACE__ . '\\GoPayPaymentException');
    }
    class_alias($sdk, __NAMESPACE__ . '\\GoPaySdkWrapper');
    return;
}

final class GoPayTokenException extends \RuntimeException {}
final class GoPayHttpException extends \RuntimeException {}
final class GoPayPaymentException extends \RuntimeException {}

final class GoPaySdkWrapper implements PaymentGatewayInterface
{
    public function __construct(array $cfg, LoggerInterface $logger, CacheInterface $cache)
    {
        unset($cfg, $logger, $cache);
        throw new \RuntimeException('GoPaySdkWrapper moved to blackcat-gopay (install blackcatacademy/blackcat-gopay).');
    }

    public function createPayment(array $payload)
    {
        unset($payload);
        throw new \RuntimeException('GoPaySdkWrapper moved to blackcat-gopay (install blackcatacademy/blackcat-gopay).');
    }

    public function getStatus(string $gatewayPaymentId)
    {
        unset($gatewayPaymentId);
        throw new \RuntimeException('GoPaySdkWrapper moved to blackcat-gopay (install blackcatacademy/blackcat-gopay).');
    }

    public function refundPayment(string $gatewayPaymentId, array $args)
    {
        unset($gatewayPaymentId, $args);
        throw new \RuntimeException('GoPaySdkWrapper moved to blackcat-gopay (install blackcatacademy/blackcat-gopay).');
    }
}
