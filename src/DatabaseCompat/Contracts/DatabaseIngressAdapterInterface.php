<?php
declare(strict_types=1);

namespace BlackCat\Database\Contracts;

/**
 * Minimal contract for manifest-driven ingress adapters.
 *
 * Implementations (for example, the DatabaseIngressAdapter from
 * blackcat-database-crypto) are responsible for applying deterministic
 * encryption / tokenization to payloads according to a manifest map.
 *
 * The database package only needs the ability to transform associative rows
 * before they are handed to repositories – lifecycle hooks (coverage, gateways,
 * etc.) stay within the adapter layer.
 */
interface DatabaseIngressAdapterInterface
{
    /**
     * Transform the provided payload using the manifest definition for $table.
     *
     * @param array<string,mixed> $payload
     * @return array<string,mixed>
     */
    public function encrypt(string $table, array $payload): array;
}

