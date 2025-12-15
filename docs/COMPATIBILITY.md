# Compatibility facades (legacy names)

The BlackCat ecosystem evolved into separate modules. For smoother migrations, `blackcat-core` keeps a few **compatibility facades**.

They follow a strict rule:
- **No duplicated source of truth** inside core
- If the target module is installed → core `class_alias`-es the real implementation
- If not installed → core fails fast with a clear “install X” error (or returns safe defaults)

## Mapping

- `BlackCat\Core\Messaging\Outbox` / `Inbox` → `blackcatacademy/blackcat-messaging`
- `BlackCat\Core\Mail\Mailer` → `blackcatacademy/blackcat-mailing`
- `BlackCat\Core\Security\Auth` / `LoginLimiter` → `blackcatacademy/blackcat-auth`
- `BlackCat\Core\Session\SessionManager` / `DbCachedSessionHandler` → `blackcatacademy/blackcat-sessions`
- global `JWT` → `blackcatacademy/blackcat-jwt`
- global `RBAC` → `blackcatacademy/blackcat-rbac`
- global `JobQueue` → `blackcatacademy/blackcat-jobs`
- `BlackCat\Core\Payment\*` → `blackcatacademy/blackcat-gopay`

## Recommendation

New code should:
- depend on the dedicated module directly (not the facade)
- rely on `blackcat-database` generated repositories (no raw SQL in domain modules)
