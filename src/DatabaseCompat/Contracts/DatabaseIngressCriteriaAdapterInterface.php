<?php
declare(strict_types=1);

namespace BlackCat\Database\Contracts;

/**
 * Optional extension for ingress adapters that can deterministically transform
 * query criteria (e.g., HMAC columns used for lookups and unique keys).
 *
 * This keeps `blackcat-database` decoupled from concrete implementations while
 * allowing higher-level services to safely query encrypted datasets.
 */
interface DatabaseIngressCriteriaAdapterInterface extends DatabaseIngressAdapterInterface
{
    /**
     * Transform query criteria using the manifest map for $table.
     *
     * The adapter must only apply deterministic transformations (e.g. HMAC).
     * Columns that use non-deterministic encryption should be rejected.
     *
     * @param array<string,mixed> $criteria
     * @return array<string,mixed>
     */
    public function criteria(string $table, array $criteria): array;
}

