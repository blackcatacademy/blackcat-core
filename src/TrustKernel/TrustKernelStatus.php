<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class TrustKernelStatus implements \JsonSerializable
{
    /**
     * @param list<string> $errors
     * @param list<string> $errorCodes
     */
    public function __construct(
        /** @var 'strict'|'warn' */
        public readonly string $enforcement,
        /** @var 'root_uri'|'full' */
        public readonly string $mode,
        public readonly int $maxStaleSec,
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
        public readonly array $errorCodes = [],
    ) {
    }

    /**
     * @return array{
     *   enforcement:'strict'|'warn',
     *   mode:'root_uri'|'full',
     *   max_stale_sec:int,
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
     *   errors:list<string>,
     *   error_codes:list<string>
     * }
     */
    public function toArray(): array
    {
        return [
            'enforcement' => $this->enforcement,
            'mode' => $this->mode,
            'max_stale_sec' => $this->maxStaleSec,
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
            'error_codes' => $this->errorCodes,
        ];
    }

    /**
     * Safe monitoring payload (avoid leaking internal paths / RPC error details).
     *
     * @return array{
     *   enforcement:'strict'|'warn',
     *   mode:'root_uri'|'full',
     *   max_stale_sec:int,
     *   trusted_now:bool,
     *   read_allowed:bool,
     *   write_allowed:bool,
     *   rpc_ok_now:bool,
     *   paused:bool,
     *   checked_at:int,
     *   last_ok_at:?int,
     *   error_codes:list<string>
     * }
     */
    public function toMonitorArray(): array
    {
        return [
            'enforcement' => $this->enforcement,
            'mode' => $this->mode,
            'max_stale_sec' => $this->maxStaleSec,
            'trusted_now' => $this->trustedNow,
            'read_allowed' => $this->readAllowed,
            'write_allowed' => $this->writeAllowed,
            'rpc_ok_now' => $this->rpcOkNow,
            'paused' => $this->paused,
            'checked_at' => $this->checkedAt,
            'last_ok_at' => $this->lastOkAt,
            'error_codes' => $this->errorCodes,
        ];
    }

    public function jsonSerialize(): mixed
    {
        return $this->toArray();
    }
}
