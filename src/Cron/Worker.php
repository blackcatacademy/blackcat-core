<?php
declare(strict_types=1);

namespace BlackCat\Core\Cron;

use BlackCat\Core\Log\Logger;
use BlackCat\Core\Security\KeyManager;
use BlackCat\Core\Mail\Mailer;

/**
 * cron/Worker.php
 *
 * Production-ready Worker:
 *  - notification processing (deleguje na Mailer)
 *  - housekeeping (cleanup, sessions)
 *  - key rotation job scheduling / execution / forced rotation
 *  - job registry + simple locking
 *
 * Prereqs:
 *  - PDO instance with tables: worker_locks, key_rotation_jobs, key_events, crypto_keys, notifications
 *  - KeyManager::rotateKey(...) available
 *  - Logger available
 */

final class Worker
{
    private static ?\PDO $pdo = null;
    private static bool $inited = false;
    private static array $jobs = [];

    /** @var mixed|null */
    private static $gopayWrapper = null;

    /** @var mixed|null */
    private static $gopayAdapter = null;

    /** lock prefix to avoid colliding with other processes */
    private const LOCK_PREFIX = 'worker_lock_';

    public static function init(\PDO $pdo, $gopayWrapper = null, $gopayAdapter = null): void
    {
        self::$pdo        = $pdo;
        self::$gopayWrapper = $gopayWrapper;
        self::$gopayAdapter = $gopayAdapter;
        self::$inited     = true;

        if (class_exists(Logger::class, true)) {
            try { Logger::systemMessage('notice', 'Worker initialized'); } catch (\Throwable $_) {}
        }
    }

    private static function ensureInited(): void
    {
        if (!self::$inited || !self::$pdo) {
            throw new \RuntimeException('Worker not initialized.');
        }
    }

    /** volitelné, pokud je chceš využít interně */
    public static function getGoPayWrapper()
    {
        self::ensureInited();
        return self::$gopayWrapper;
    }

    public static function getGoPayAdapter()
    {
        self::ensureInited();
        return self::$gopayAdapter;
    }

    // -------------------- Notifications --------------------
    /**
     * Process notifications queue via Mailer.
     * $immediate = true runs Mailer::processPendingNotifications immediately.
     */
    public static function notification(int $limit = 100, bool $immediate = true): array
    {
        self::ensureInited();

        if (!class_exists(Mailer::class, true)) {
            throw new \RuntimeException('Mailer lib missing.');
        }

        // Acquire short lock so multiple cron runners don't run notifications concurrently
        $lockName = self::LOCK_PREFIX . 'notifications';
        if (!self::lock($lockName, 300)) {
            if (class_exists(Logger::class, true)) try { Logger::systemMessage('notice', 'Notification worker already running — skipping'); } catch (\Throwable $_) {}
            return ['notice' => 'locked'];
        }

        try {
            $report = ['processed' => 0, 'sent' => 0, 'failed' => 0, 'skipped' => 0, 'errors' => []];
            if ($immediate) {
                try {
                    $report = Mailer::processPendingNotifications($limit);
                } catch (\Throwable $e) {
                    if (class_exists(Logger::class, true)) try { Logger::systemError($e); } catch (\Throwable $_) {}
                    $report['errors'][] = $e->getMessage();
                }
            } else {
                $report['notice'] = 'immediate disabled';
            }

            if (class_exists(Logger::class, true)) try { Logger::systemMessage('notice', 'Notification worker finished', null, $report); } catch (\Throwable $_) {}
            return $report;
        } finally {
            self::unlock($lockName);
        }
    }

    // -------------------- Cleanup --------------------
    public static function cleanupNotifications(int $days = 30): int
    {
        self::ensureInited();
        $stmt = self::$pdo->prepare('DELETE FROM notifications WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY) AND status = "sent"');
        $stmt->execute([$days]);
        $count = $stmt->rowCount();
        if (class_exists(Logger::class, true)) try { Logger::systemMessage('notice', 'Cleanup old notifications', null, ['deleted' => $count]); } catch (\Throwable $_) {}
        return $count;
    }

    public static function cleanupSessions(int $graceHours = 24, int $auditDays = 90): array
    {
        self::ensureInited();
        $report = [];

        $stmt = self::$pdo->prepare(
            'DELETE FROM sessions 
            WHERE (revoked = 1 OR expires_at < NOW()) 
            AND last_seen_at < DATE_SUB(NOW(), INTERVAL ? HOUR)'
        );
        $stmt->execute([$graceHours]);
        $report['sessions_deleted'] = $stmt->rowCount();

        $stmt = self::$pdo->prepare(
            'DELETE FROM session_audit WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)'
        );
        $stmt->execute([$auditDays]);
        $report['session_audit_deleted'] = $stmt->rowCount();

        if (class_exists(Logger::class, true)) try { Logger::systemMessage('notice', 'Cleanup sessions finished', null, $report); } catch (\Throwable $_) {}
        return $report;
    }

    // -------------------- Jobs registry --------------------
    public static function registerJob(string $name, callable $callback): void
    {
        self::$jobs[$name] = $callback;
        if (class_exists(Logger::class, true)) try { Logger::systemMessage('notice', "Registered job {$name}"); } catch (\Throwable $_) {}
    }

    public static function runJob(string $name, array $args = []): void
    {
        if (!isset(self::$jobs[$name])) {
            if (class_exists(Logger::class, true)) try { Logger::systemMessage('warning', "Job {$name} not found"); } catch (\Throwable $_) {}
            return;
        }
        try {
            call_user_func_array(self::$jobs[$name], $args);
        } catch (\Throwable $e) {
            if (class_exists(Logger::class, true)) try { Logger::systemError($e); } catch (\Throwable $_) {}
        }
    }

    // -------------------- DB-backed worker locks --------------------
    public static function lock(string $name, int $ttl = 300): bool
    {
        self::ensureInited();
        // Try atomic insert; if exists, check expiration and try to replace
        try {
            $stmt = self::$pdo->prepare('INSERT IGNORE INTO worker_locks (name, locked_until) VALUES (?, DATE_ADD(NOW(), INTERVAL ? SECOND))');
            $stmt->execute([$name, $ttl]);
            if ($stmt->rowCount() > 0) return true;

            // if not inserted, maybe existing expired -> try update where expired
            $upd = self::$pdo->prepare('UPDATE worker_locks SET locked_until = DATE_ADD(NOW(), INTERVAL ? SECOND) WHERE name = ? AND (locked_until IS NULL OR locked_until <= NOW())');
            $upd->execute([$ttl, $name]);
            return $upd->rowCount() > 0;
        } catch (\Throwable $e) {
            if (class_exists(Logger::class, true)) try { Logger::systemError($e); } catch (\Throwable $_) {}
            return false;
        }
    }

    public static function unlock(string $name): void
    {
        self::ensureInited();
        try {
            $stmt = self::$pdo->prepare('DELETE FROM worker_locks WHERE name = ?');
            $stmt->execute([$name]);
        } catch (\Throwable $e) {
            if (class_exists(Logger::class, true)) try { Logger::systemError($e); } catch (\Throwable $_) {}
        }
    }

    // -------------------- Key rotation API (DB + KeyManager) --------------------

    /**
     * Schedule a rotation job. Returns inserted job id.
     *
     * $when = null -> schedule immediately (pending)
     * $executedBy = optional actor user id
     */
    public static function scheduleKeyRotation(string $basename, ?int $executedBy = null, ?int $targetVersion = null, ?\DateTimeInterface $when = null): int
    {
        self::ensureInited();
        $scheduledAt = $when ? $when->format('Y-m-d H:i:s') : null;
        $stmt = self::$pdo->prepare('INSERT INTO key_rotation_jobs (basename, target_version, scheduled_at, attempts, status, executed_by, created_at) VALUES (?, ?, ?, 0, "pending", ?, NOW())');
        $stmt->execute([$basename, $targetVersion, $scheduledAt, $executedBy]);
        $id = (int) self::$pdo->lastInsertId();
        if (class_exists(Logger::class, true)) try { Logger::systemMessage('notice', 'Scheduled key rotation', $executedBy, ['job_id' => $id, 'basename' => $basename, 'scheduled_at' => $scheduledAt]); } catch (\Throwable $_) {}
        return $id;
    }

    /**
     * Force immediate key rotation (synchronous).
     * Writes to key_events and crypto_keys (optional) and returns rotation result.
     * This is intended for admin-invoked rotations.
     */
    public static function forceRotateKey(string $basename, ?int $executedBy = null, int $keepVersions = 5, bool $archiveOld = false): array
    {
        self::ensureInited();

        if (!class_exists(KeyManager::class, true)) throw new \RuntimeException('KeyManager missing');
        $res = null;

        // short lock per basename to avoid concurrent rotations
        $lockName = self::LOCK_PREFIX . 'rotate_' . $basename;
        if (!self::lock($lockName, 600)) {
            throw new \RuntimeException('Rotation for this key is already running');
        }

        try {
            // run rotation (KeyManager::rotateKey writes file and returns meta)
            $res = KeyManager::rotateKey($basename, KEYS_DIR, self::$pdo, $keepVersions, $archiveOld);

            // record job entry and mark done
            $jobId = self::scheduleKeyRotation($basename, $executedBy, null, null);
            try {
                $upd = self::$pdo->prepare('UPDATE key_rotation_jobs SET status = ?, started_at = NOW(), finished_at = NOW(), attempts = attempts + 1, result = ? WHERE id = ?');
                $upd->execute(['done', json_encode($res, JSON_UNESCAPED_UNICODE), $jobId]);
            } catch (\Throwable $_) { /* non-fatal */ }

            // record event (key_events). Try to link to crypto_keys if you insert one
            $meta = json_encode(['filename' => basename($res['path'] ?? ''), 'fingerprint' => $res['fingerprint'] ?? null]);
            $ins = self::$pdo->prepare('INSERT INTO key_events (key_id, basename, event_type, actor_id, job_id, note, meta, source, created_at) VALUES (NULL, ?, "rotated", ?, ?, "rotation forced", ?, "admin", NOW())');
            $ins->execute([$basename, $executedBy, $jobId, $meta]);

            if (class_exists(Logger::class, true)) try { Logger::systemMessage('notice', 'Key rotated (forced)', $executedBy, ['basename' => $basename, 'res' => $res]); } catch (\Throwable $_) {}

            return $res;
        } catch (\Throwable $e) {
            if (class_exists(Logger::class, true)) try { Logger::systemError($e); } catch (\Throwable $_) {}
            throw $e;
        } finally {
            self::unlock($lockName);
        }
    }

    /**
     * Run pending scheduled rotation jobs (called by cron). Returns array of job results.
     */
    public static function runPendingKeyRotationJobs(int $limit = 5): array
    {
        self::ensureInited();

        $out = [];
        // Process pending jobs ordered by scheduled_at asc (NULL last)
        $stmt = self::$pdo->prepare("SELECT * FROM key_rotation_jobs WHERE status IN ('pending','failed') ORDER BY scheduled_at IS NULL, scheduled_at ASC, created_at ASC LIMIT ?");
        $stmt->bindValue(1, $limit, \PDO::PARAM_INT);
        $stmt->execute();
        $jobs = $stmt->fetchAll(\PDO::FETCH_ASSOC) ?: [];

        foreach ($jobs as $job) {
            $jobId = (int)$job['id'];
            $basename = $job['basename'];
            $attempts = (int)$job['attempts'];

            // Try to atomically claim job (status -> running)
            try {
                $upd = self::$pdo->prepare("UPDATE key_rotation_jobs SET status = 'running', started_at = NOW(), attempts = attempts + 1 WHERE id = ? AND status IN ('pending','failed')");
                $upd->execute([$jobId]);
                if ($upd->rowCount() === 0) {
                    $out[$jobId] = 'skipped';
                    continue;
                }

                $lockName = self::LOCK_PREFIX . 'rotate_' . $basename;
                if (!self::lock($lockName, 900)) {
                    // cannot lock, mark as pending again and skip
                    $revert = self::$pdo->prepare("UPDATE key_rotation_jobs SET status = 'pending' WHERE id = ?");
                    $revert->execute([$jobId]);
                    $out[$jobId] = 'locked';
                    continue;
                }

                try {
                    $keep = (int)($job['target_version'] ?? 5);
                    $archive = false;
                    $res = KeyManager::rotateKey($basename, KEYS_DIR, self::$pdo, $keep, $archive);

                    // record success event
                    $meta = json_encode(['filename' => basename($res['path'] ?? ''), 'fingerprint' => $res['fingerprint'] ?? null]);
                    $ins = self::$pdo->prepare('INSERT INTO key_events (key_id, basename, event_type, actor_id, job_id, note, meta, source, created_at) VALUES (NULL, ?, "rotated", NULL, ?, "rotation worker", ?, "cron", NOW())');
                    $ins->execute([$basename, $jobId, $meta]);

                    // mark job done
                    $done = self::$pdo->prepare("UPDATE key_rotation_jobs SET status = 'done', finished_at = NOW(), result = ? WHERE id = ?");
                    $done->execute([json_encode($res, JSON_UNESCAPED_UNICODE), $jobId]);

                    $out[$jobId] = ['status' => 'done', 'res' => $res];
                    if (class_exists(Logger::class, true)) try { Logger::systemMessage('notice', 'Key rotation job done', null, ['job' => $jobId, 'basename' => $basename]); } catch (\Throwable $_) {}

                } finally {
                    self::unlock($lockName);
                }
            } catch (\Throwable $e) {
                // mark failed and increment attempts already done above
                try {
                    $err = ['error' => $e->getMessage()];
                    $fail = self::$pdo->prepare("UPDATE key_rotation_jobs SET status = 'failed', finished_at = NOW(), result = ? WHERE id = ?");
                    $fail->execute([json_encode($err, JSON_UNESCAPED_UNICODE), $jobId]);
                } catch (\Throwable $_) {}
                if (class_exists(Logger::class, true)) try { Logger::systemError($e); } catch (\Throwable $_) {}
                $out[$jobId] = ['status' => 'failed', 'error' => $e->getMessage()];
            }
        }

        return $out;
    }

    // -------------------- Example: registration mail helper --------------------
    public static function registrationMail(int $userId, array $payload): void
    {
        if (!class_exists(Mailer::class, true)) throw new \RuntimeException('Mailer lib missing.');

        try {
            $payload['user_id'] = $userId;
            $id = Mailer::enqueue($payload);
            if (class_exists(Logger::class, true)) try { Logger::systemMessage('notice', 'Notification enqueued', $userId, ['notification_id' => $id]); } catch (\Throwable $_) {}

            // best-effort immediate attempt, non-fatal
            $report = Mailer::processPendingNotifications(1);
            if (class_exists(Logger::class, true)) try { Logger::systemMessage('notice', 'Immediate send attempt', $userId, $report); } catch (\Throwable $_) {}
        } catch (\Throwable $e) {
            if (class_exists(Logger::class, true)) try { Logger::systemError($e); } catch (\Throwable $_) {}
        }
    }
    
    public static function processGoPayNotify(int $limit = 5, int $claimTtlSec = 120): array
    {
        self::ensureInited();

        $me = getmypid() . '@' . gethostname();
        $processingUntil = (new \DateTimeImmutable('+' . $claimTtlSec . ' seconds'))->format('Y-m-d H:i:s');

        $report = ['claimed' => 0, 'done' => 0, 'skipped' => 0, 'failed' => 0, 'errors' => []];

        // -----------------------------
        // 1) Claim rows atomically
        // -----------------------------
        try {
            self::$pdo->beginTransaction();

            $sql = '
                SELECT id, transaction_id, received_at, processing_by, processing_until, attempts, status
                FROM gopay_notify_log
                WHERE status = :status
                AND (processing_until IS NULL OR processing_until < NOW())
                ORDER BY received_at ASC
                LIMIT :limit FOR UPDATE
            ';
            $sel = self::$pdo->prepare($sql);
            $sel->bindValue(':status', 'pending', \PDO::PARAM_STR);
            $sel->bindValue(':limit', $limit, \PDO::PARAM_INT);
            $sel->execute();
            $rows = $sel->fetchAll(\PDO::FETCH_ASSOC);

            if (!$rows) {
                self::$pdo->commit();
                return $report;
            }

            $updClaim = self::$pdo->prepare('
                UPDATE gopay_notify_log
                SET status = ?, processing_by = ?, processing_until = ?, attempts = attempts + 1
                WHERE id = ?
            ');

            foreach ($rows as $r) {
                $updClaim->execute(['processing', $me, $processingUntil, $r['id']]);
                if ($updClaim->rowCount() > 0) {
                    $report['claimed']++;
                    $r['status'] = 'processing';
                    $r['attempts']++; // synchronizace pro další logiku

                }
            }

            self::$pdo->commit();
        } catch (\Throwable $e) {
            try { self::$pdo->rollBack(); } catch (\Throwable $_) {}
            $report['errors'][] = 'claim_failed: ' . $e->getMessage();
            if (class_exists(Logger::class, true)) try { Logger::systemError($e); } catch (\Throwable $_) {}
            return $report;
        }

        foreach ($rows as $r) {
            $orderId = $r['transaction_id'];
            if (empty($orderId)) {
                continue; // skip if transaction_id missing
            }

        try {
            $res = self::getGoPayAdapter()->handleNotify((string)$orderId, false);
            $action = $res['action'] ?? 'done';
            
            $updStatus = self::$pdo->prepare('
                UPDATE gopay_notify_log
                SET status = ?, processing_by = NULL, processing_until = NULL
                WHERE id = ?
            ');

            $lastError = $res['last_error'] ?? null;
            if (!empty($lastError) && class_exists(Logger::class, true)) {
                Logger::systemError(new \RuntimeException($lastError), null, null, ['transaction_id' => $orderId]);
            }

            switch ($action) {
                case 'done':
                    $updStatus->execute(['done', $r['id']]);
                    $report['done']++;
                    break;

                case 'delete':
                    // reset row, worker může zpracovat znovu
                    $updStatus->execute(['pending', $r['id']]);
                    $report['skipped']++;
                    break;

                case 'fail':
                    $updStatus->execute(['failed', $r['id']]);
                    $report['failed']++;
                    break;
            }

        } catch (\Throwable $e) {
            if (class_exists(Logger::class, true)) {
                try {
                    Logger::systemError($e, null, null, ['transaction_id' => $orderId]);
                } catch (\Throwable $_) {}
            }
            $report['failed']++;
        }
        }

        return $report;
    }
}