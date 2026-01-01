<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class TrustPolicyV1
{
    public function __construct(
        public readonly string $mode,
        public readonly int $maxStaleSec,
    ) {
        $mode = strtolower(trim($mode));
        if ($mode === '' || !in_array($mode, ['root_uri', 'full'], true)) {
            throw new \InvalidArgumentException('Invalid trust policy mode (expected root_uri|full).');
        }
        if ($maxStaleSec < 1 || $maxStaleSec > 86400) {
            throw new \InvalidArgumentException('Invalid trust policy maxStaleSec (expected 1..86400).');
        }
    }

    /**
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        return [
            'schema_version' => 1,
            'type' => 'blackcat.trust.policy',
            'mode' => strtolower(trim($this->mode)),
            'max_stale_sec' => $this->maxStaleSec,
        ];
    }

    public function hashBytes32(): string
    {
        return CanonicalJson::sha256Bytes32($this->toArray());
    }
}

