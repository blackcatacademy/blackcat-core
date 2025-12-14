<?php

declare(strict_types=1);

namespace BlackCat\Core\Payment;

/**
 * Compatibility facade for the legacy `BlackCat\Core\Payment\GoPayStatus` name.
 *
 * If `blackcatacademy/blackcat-gopay` is installed, this file aliases:
 * `BlackCat\GoPay\GoPayStatus`.
 */
if (class_exists(\BlackCat\GoPay\GoPayStatus::class)) {
    class_alias(\BlackCat\GoPay\GoPayStatus::class, __NAMESPACE__ . '\\GoPayStatus');
    return;
}

enum GoPayStatus: string
{
    case CREATED = 'CREATED';
    case PAYMENT_METHOD_CHOSEN = 'PAYMENT_METHOD_CHOSEN';
    case PAID = 'PAID';
    case AUTHORIZED = 'AUTHORIZED';
    case CANCELED = 'CANCELED';
    case TIMEOUTED = 'TIMEOUTED';
    case REFUNDED = 'REFUNDED';
    case PARTIALLY_REFUNDED = 'PARTIALLY_REFUNDED';

    public function isNonPermanent(): bool
    {
        return in_array($this, [self::CREATED, self::PAYMENT_METHOD_CHOSEN], true);
    }
}
