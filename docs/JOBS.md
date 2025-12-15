# Workers / jobs

`blackcat-core` is a kernel and does **not** ship operational workers.

Use the dedicated modules instead:

- Mailing queue worker: `blackcatacademy/blackcat-mailing` → `bin/mailing-worker`
- Event/webhook outbox workers: `blackcatacademy/blackcat-messaging` → `bin/event-outbox-worker`, `bin/webhook-outbox-worker`
- Auth HTTP server/CLI: `blackcatacademy/blackcat-auth` → `bin/auth-http`, `bin/auth`
- Job queue workers: `blackcatacademy/blackcat-jobs` (DB-backed `system_jobs`)

For orchestration/cron scheduling, prefer `blackcat-orchestrator`.
