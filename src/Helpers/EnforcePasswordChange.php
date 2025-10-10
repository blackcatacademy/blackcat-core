<?php

declare(strict_types=1);

namespace BlackCat\Core\Helpers;

use BlackCat\Core\Database;
use BlackCat\Core\Log\Logger;
use BlackCat\Core\Session\SessionManager;

final class EnforcePasswordChange
{
    private function __construct() {}

    public static function check(): void
    {
        $callback = function() {
            try {
                $db = Database::getInstance();
                $userId = SessionManager::validateSession($db->getPdo());
                if ($userId === null) return;

                $row = $db->fetch(
                    'SELECT must_change_password FROM pouzivatelia WHERE id = :id LIMIT 1',
                    [':id' => $userId]
                );
                $mustChange = $row['must_change_password'] ?? null;
            } catch (\Throwable $e) {
                Logger::systemError($e, $userId ?? null);
                return;
            }

            if ($mustChange) {
                $target = '/eshop/change_password.php';
                if (!headers_sent()) {
                    header('Location: ' . $target);
                    exit;
                } else {
                    echo '<script>window.location="' . htmlspecialchars($target, ENT_QUOTES | ENT_SUBSTITUTE) . '";</script>';
                    echo '<noscript><meta http-equiv="refresh" content="0;url=' . htmlspecialchars($target, ENT_QUOTES | ENT_SUBSTITUTE) . '"></noscript>';
                    exit;
                }
            }
        };

        if (Database::isInitialized()) {
            $callback();
        } else {
            DeferredHelper::enqueue($callback);
        }
    }
}