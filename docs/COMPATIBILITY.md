# Compatibility / migration notes

`blackcat-core` is a **fail-closed kernel**. To keep the attack surface minimal and avoid “shadow APIs”, it intentionally does **not** ship compatibility facades (`class_alias` shims) for other modules.

If you are migrating older code that referenced legacy names, update your imports to the dedicated module package.

## Common migration mapping

- `BlackCat\Core\Messaging\*` → `blackcatacademy/blackcat-messaging`
- `BlackCat\Core\Mail\Mailer` → `blackcatacademy/blackcat-mailing`
- `BlackCat\Core\Security\Auth` / `LoginLimiter` → `blackcatacademy/blackcat-auth`
- `BlackCat\Core\Session\*` → `blackcatacademy/blackcat-sessions`
- global `JWT` → `blackcatacademy/blackcat-jwt`
- global `RBAC` → `blackcatacademy/blackcat-rbac`
- global `JobQueue` → `blackcatacademy/blackcat-jobs`
- `BlackCat\Core\Payment\*` → `blackcatacademy/blackcat-gopay`

## Why

- Less code in the kernel = smaller audited surface.
- No “safe defaults” that accidentally disable security when a module is missing.
- Clear ownership: business logic and workers live in their dedicated repos.
