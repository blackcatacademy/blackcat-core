<?php
declare(strict_types=1);

namespace BlackCat\Core\Adapter;

/**
 * Noop ingress adapter for cases where the caller already performed deterministic transforms
 * (e.g. HMAC criteria) and must prevent double-processing by repository ingress hooks.
 *
 * This class is only meant as a bridge when `blackcat-database(-crypto)` is present.
 */
if (!interface_exists(\BlackCat\Database\Contracts\DatabaseIngressAdapterInterface::class)) {
    return;
}

final class NoopIngressAdapter implements \BlackCat\Database\Contracts\DatabaseIngressAdapterInterface
{
    /**
     * @param array<string,mixed> $payload
     * @return array<string,mixed>
     */
    public function encrypt(string $table, array $payload): array
    {
        unset($table);
        return $payload;
    }
}
