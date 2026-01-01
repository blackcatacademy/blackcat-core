<?php

declare(strict_types=1);

namespace BlackCat\Core\Database;

use BlackCat\Core\Database;
use BlackCat\Core\DatabaseException;
use Psr\Log\LoggerInterface;

/**
 * Recommended DB bootstrap for TrustKernel deployments.
 *
 * In strict TrustKernel mode, runtime config should not expose db.dsn/user/pass to the web runtime.
 * Instead, a privileged local secrets-agent should release DB credentials only when:
 * - reads are allowed (`read_allowed=true`) for the read role,
 * - writes are allowed (`write_allowed=true`) for the write role.
 */
final class DbBootstrap
{
    public static function initFromSecretsAgentIfNeeded(?LoggerInterface $logger = null, string $appName = 'blackcat'): void
    {
        if (Database::isInitialized()) {
            return;
        }

        $read = DbCredentialsAgentClient::fetch('read');

        $write = null;
        try {
            $write = DbCredentialsAgentClient::fetch('write');
        } catch (\Throwable) {
            $write = null;
        }

        $primary = $write ?? $read;

        $cfg = [
            'dsn' => $primary['dsn'],
            'user' => $primary['user'],
            'pass' => $primary['pass'],
            'options' => [],
            'init_commands' => [
                "SET time_zone = '+00:00'",
            ],
            'appName' => $appName,
        ];

        if ($write !== null) {
            $cfg['replica'] = [
                'dsn' => $read['dsn'],
                'user' => $read['user'],
                'pass' => $read['pass'],
                'options' => [],
                'init_commands' => [
                    "SET time_zone = '+00:00'",
                ],
            ];
        }

        Database::init($cfg, $logger);

        if ($write === null) {
            try {
                Database::getInstance()->enableReadOnlyGuard(true);
            } catch (\Throwable $e) {
                throw new DatabaseException('Unable to enable DB read-only guard.', 0, $e);
            }
        }
    }
}

