# Contributing

This repository is **proprietary**. External contributions are accepted only with explicit written permission from Black Cat Academy s. r. o.

## Development

Requirements:
- PHP `^8.1` (CI runs on PHP `8.3`)
- Composer
- Extensions: `ext-pdo`, `ext-json`, `ext-sodium` (`ext-mbstring` recommended)

Quality gates:

```bash
composer validate --strict
composer stan
composer test
```

## Reporting issues

- Non-security bugs and feature requests: GitHub Issues.
- Security issues: see `SECURITY.md`.

