# GitHub setup (recommended)

This file is a copy-paste checklist for the GitHub repository settings.

## Repository description (About)

Suggested:
> Minimal kernel for the BlackCat ecosystem: hardened PDO wrapper, crypto primitives, and core utilities.

## Topics (tags)

Suggested:
- `php`
- `security`
- `crypto`
- `libsodium`
- `database`
- `pdo`
- `kernel`
- `monorepo`
- `observability`

## Recommended repository settings

- Default branch: `main` (or `dev` until the first stable release)
- Protect the default branch:
  - require PRs
  - require status checks (CI)
  - require linear history (optional)
- Enable:
  - Issues
  - Discussions (optional)
  - Dependabot (enabled by `.github/dependabot.yml`)

