<?php
// libs/JobQueue.php
// Simple DB-backed job queue. Table: job_queue (id, payload JSON, attempts, max_attempts, run_after DATETIME, status, last_error, created_at)
class JobQueue {
    private $db;
    public function __construct(PDO $db) { $this->db = $db; }

    // push job
    public function push(array $payload, int $delaySeconds = 0, int $maxAttempts = 5) {
        $runAfter = date('Y-m-d H:i:s', time() + $delaySeconds);
        $this->db->prepare('INSERT INTO job_queue (payload, attempts, max_attempts, run_after, status, created_at) VALUES (?, 0, ?, ?, "pending", NOW())')
            ->execute([json_encode($payload), $maxAttempts, $runAfter]);
        return $this->db->lastInsertId();
    }

    // fetch next job (atomically)
    public function fetchNext() {
        $this->db->beginTransaction();
        $stmt = $this->db->prepare('SELECT * FROM job_queue WHERE status="pending" AND run_after <= NOW() ORDER BY created_at ASC LIMIT 1 FOR UPDATE');
        $stmt->execute();
        $job = $stmt->fetch();
        if ($job) {
            $this->db->prepare('UPDATE job_queue SET status="processing", last_processed_at=NOW() WHERE id=?')->execute([$job['id']]);
        }
        $this->db->commit();
        return $job ?: null;
    }

    public function markSuccess($id) {
        $this->db->prepare('UPDATE job_queue SET status="done", finished_at=NOW() WHERE id=?')->execute([$id]);
    }

    public function markFailed($id, $errorMsg) {
        $this->db->prepare('UPDATE job_queue SET attempts = attempts + 1, last_error = ?, status = CASE WHEN attempts+1 >= max_attempts THEN "failed" ELSE "pending" END, run_after = DATE_ADD(NOW(), INTERVAL 60 SECOND) WHERE id=?')
            ->execute([$errorMsg, $id]);
    }
}