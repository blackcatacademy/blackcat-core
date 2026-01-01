<?php

declare(strict_types=1);

namespace BlackCat\Core\TrustKernel;

final class ReleaseRegistryReader
{
    private const IS_TRUSTED_ROOT_SELECTOR = '0x3cb692b8'; // isTrustedRoot(bytes32)

    public function __construct(
        private readonly Web3RpcQuorumClient $rpc,
    ) {
    }

    public function isTrustedRoot(string $releaseRegistryAddress, string $rootBytes32): bool
    {
        $rootBytes32 = Bytes32::normalizeHex($rootBytes32);
        $data = self::IS_TRUSTED_ROOT_SELECTOR . substr($rootBytes32, 2);
        $hex = $this->rpc->ethCallQuorum($releaseRegistryAddress, $data, 'latest');
        return self::decodeBool($hex);
    }

    private static function decodeBool(string $hex): bool
    {
        $hex = trim($hex);
        if ($hex === '' || !str_starts_with($hex, '0x')) {
            throw new \RuntimeException('Invalid bool result.');
        }

        $payload = substr(strtolower($hex), 2);
        if ($payload === '') {
            throw new \RuntimeException('Invalid bool result length.');
        }

        if (!ctype_xdigit($payload)) {
            throw new \RuntimeException('Invalid bool result encoding.');
        }

        if (strlen($payload) < 64) {
            $payload = str_pad($payload, 64, '0', STR_PAD_LEFT);
        } elseif (strlen($payload) > 64) {
            $payload = substr($payload, -64);
        }

        return hexdec(substr($payload, 62, 2)) !== 0;
    }
}

