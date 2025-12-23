<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

use Psr\Log\LoggerInterface;
use BlackCat\Core\Database;
use BlackCat\Core\Security\KeyManager;

final class TrustKernel
{
    private Web3RpcQuorumClient $rpc;
    private InstanceControllerReader $controller;
    private LocalIntegrityVerifier $integrity;

    private ?IntegrityManifestV1 $manifest = null;
    private ?int $manifestMtime = null;

    private ?TrustKernelStatus $lastStatus = null;
    private ?int $lastStatusAt = null;

    private ?TrustKernelStatus $lastOkStatus = null;
    private ?int $lastOkAt = null;

    public function __construct(
        private readonly TrustKernelConfig $config,
        private readonly ?LoggerInterface $logger = null,
        ?Web3TransportInterface $transport = null,
    ) {
        $this->rpc = new Web3RpcQuorumClient(
            $config->rpcEndpoints,
            $config->chainId,
            $config->rpcQuorum,
            $transport,
            $config->rpcTimeoutSec,
        );
        $this->controller = new InstanceControllerReader($this->rpc);
        $this->integrity = new LocalIntegrityVerifier($config->integrityRootDir);
    }

    public function installGuards(): void
    {
        KeyManager::setAccessGuard(function (string $operation): void {
            if ($operation === 'write') {
                $this->assertWriteAllowed('secrets.write');
                return;
            }
            $this->assertReadAllowed('secrets.read');
        });

        Database::setWriteGuard(function (string $sql): void {
            $this->assertWriteAllowed('db.write');
        });
    }

    public function check(): TrustKernelStatus
    {
        $now = time();
        if ($this->lastStatus !== null && $this->lastStatusAt !== null && ($now - $this->lastStatusAt) < 1) {
            return $this->lastStatus;
        }

        $errors = [];
        $rpcOkNow = false;
        $snapshot = null;
        $computedRoot = null;
        $paused = false;
        $trustedNow = false;

        try {
            $snapshot = $this->controller->snapshot($this->config->instanceController);
            $rpcOkNow = true;
        } catch (\Throwable $e) {
            $errors[] = $e->getMessage();
            $rpcOkNow = false;
        }

        if ($rpcOkNow && $snapshot !== null) {
            $paused = $snapshot->paused;
            if ($paused) {
                $errors[] = 'Instance controller is paused.';
            }

            $expectedPolicyHash = Bytes32::normalizeHex($this->config->expectedPolicyHash);
            $activePolicyHash = Bytes32::normalizeHex($snapshot->activePolicyHash);
            if (!hash_equals($expectedPolicyHash, $activePolicyHash)) {
                $errors[] = 'Policy hash mismatch.';
            }

            try {
                $manifest = $this->loadManifestIfNeeded();
                $computedRoot = $this->integrity->computeAndVerifyRoot($manifest);

                $activeRoot = Bytes32::normalizeHex($snapshot->activeRoot);
                $computedRootNorm = Bytes32::normalizeHex($computedRoot);
                if (!hash_equals($activeRoot, $computedRootNorm)) {
                    $errors[] = 'Integrity root mismatch.';
                }

                $uriHash = $manifest->uriHashBytes32();
                if ($uriHash !== null) {
                    $expectedUriHash = Bytes32::normalizeHex($uriHash);
                    $activeUriHash = Bytes32::normalizeHex($snapshot->activeUriHash);
                    if (!hash_equals($expectedUriHash, $activeUriHash)) {
                        $errors[] = 'URI hash mismatch.';
                    }
                }
            } catch (\Throwable $e) {
                $errors[] = $e->getMessage();
            }

            $trustedNow = $errors === [];
            if ($trustedNow) {
                $this->lastOkAt = $now;
            }
        }

        $readAllowed = false;
        $writeAllowed = false;

        if ($trustedNow) {
            $readAllowed = true;
            $writeAllowed = true;
        } else {
            // Only allow stale reads when the failure is RPC-related and we have a recent OK state.
            if (!$rpcOkNow && $this->lastOkAt !== null && ($now - $this->lastOkAt) <= $this->config->maxStaleSec) {
                if ($this->lastOkStatus?->paused === false) {
                    $readAllowed = true;
                }
            }
        }

        $status = new TrustKernelStatus(
            $trustedNow,
            $readAllowed,
            $writeAllowed,
            $rpcOkNow,
            $paused,
            $snapshot,
            $computedRoot,
            $now,
            $this->lastOkAt,
            $errors,
        );

        $this->lastStatus = $status;
        $this->lastStatusAt = $now;
        if ($trustedNow) {
            $this->lastOkStatus = $status;
        }

        return $status;
    }

    public function assertReadAllowed(string $context = 'read'): void
    {
        $status = $this->check();
        if ($status->readAllowed) {
            return;
        }

        $this->enforceOrWarn($context, $status);
    }

    public function assertWriteAllowed(string $context = 'write'): void
    {
        $status = $this->check();
        if ($status->writeAllowed) {
            return;
        }

        $this->enforceOrWarn($context, $status);
    }

    private function enforceOrWarn(string $context, TrustKernelStatus $status): void
    {
        $msg = '[trust-kernel] denied: ' . $context;
        if ($status->errors !== []) {
            $msg .= ' (' . implode(' | ', $status->errors) . ')';
        }

        if ($this->config->enforcement === 'warn') {
            $this->logger?->warning($msg);
            return;
        }

        $this->logger?->error($msg);
        throw new TrustKernelException($msg);
    }

    private function loadManifestIfNeeded(): IntegrityManifestV1
    {
        $path = $this->config->integrityManifestPath;
        clearstatcache(true, $path);

        $mtime = @filemtime($path);
        if (!is_int($mtime) || $mtime <= 0) {
            throw new \RuntimeException('Unable to stat integrity manifest: ' . $path);
        }

        if ($this->manifest !== null && $this->manifestMtime === $mtime) {
            return $this->manifest;
        }

        $manifest = IntegrityManifestV1::fromJsonFile($path);
        $this->manifest = $manifest;
        $this->manifestMtime = $mtime;
        return $manifest;
    }
}
