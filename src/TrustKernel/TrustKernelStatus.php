<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class TrustKernelStatus implements \JsonSerializable
{
    /**
     * @param list<string> $errors
     */
    public function __construct(
        public readonly bool $trustedNow,
        public readonly bool $readAllowed,
        public readonly bool $writeAllowed,
        public readonly bool $rpcOkNow,
        public readonly bool $paused,
        public readonly ?InstanceControllerSnapshot $snapshot,
        public readonly ?string $computedRoot,
        public readonly int $checkedAt,
        public readonly ?int $lastOkAt,
        public readonly array $errors = [],
    ) {
    }

    /**
     * @return array{
     *   trusted_now:bool,
     *   read_allowed:bool,
     *   write_allowed:bool,
     *   rpc_ok_now:bool,
     *   paused:bool,
     *   snapshot:array{
     *     version:int,
     *     paused:bool,
     *     active_root:string,
     *     active_uri_hash:string,
     *     active_policy_hash:string,
     *     pending_root:string,
     *     pending_uri_hash:string,
     *     pending_policy_hash:string,
     *     pending_created_at:int,
     *     pending_ttl_sec:int,
     *     genesis_at:int,
     *     last_upgrade_at:int
     *   }|null,
     *   computed_root:?string,
     *   checked_at:int,
     *   last_ok_at:?int,
     *   errors:list<string>
     * }
     */
    public function toArray(): array
    {
        return [
            'trusted_now' => $this->trustedNow,
            'read_allowed' => $this->readAllowed,
            'write_allowed' => $this->writeAllowed,
            'rpc_ok_now' => $this->rpcOkNow,
            'paused' => $this->paused,
            'snapshot' => $this->snapshot?->toArray(),
            'computed_root' => $this->computedRoot,
            'checked_at' => $this->checkedAt,
            'last_ok_at' => $this->lastOkAt,
            'errors' => $this->errors,
        ];
    }

    public function jsonSerialize(): mixed
    {
        return $this->toArray();
    }
}
