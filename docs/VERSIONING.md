# Versioning and stability

## Goal

`blackcat-core` aims to be the **stable kernel** of the ecosystem.

## Semantic Versioning

The intent is to follow SemVer:
- **MAJOR**: breaking API changes in the kernel surface
- **MINOR**: backward-compatible features
- **PATCH**: backward-compatible fixes

## Kernel API surface

The stable surface is the namespaced API under:
- `BlackCat\Core\Database`
- `BlackCat\Core\Security\*`
- `BlackCat\Core\Cache\*`
- `BlackCat\Core\Log\*`
- `BlackCat\Core\Migrations\*`
- `BlackCat\Core\Templates\*`
- `BlackCat\Core\Validation\*`

## Compatibility facades

`blackcat-core` does not ship compatibility facades for other modules. For migration notes and module boundaries, see `docs/COMPATIBILITY.md`.
