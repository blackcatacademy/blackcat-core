# Worker Jobs

- `notification` – process pending outbound notifications via `Mailer`.
- `cleanupNotifications` – remove old sent notifications.
- `cleanupSessions` – clean session tables.
- `flushOutbox` – flush transactional outbox (requires Outbox instance via `Worker::init`).
