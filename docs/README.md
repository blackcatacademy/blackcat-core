# BlackCat Core — Documentation

`blackcat-core` is the kernel of the BlackCat ecosystem. This folder documents the stable primitives that live in core, and how core composes with the modular stack.

## Start here

- [Getting Started](GETTING_STARTED.md) — bootstrapping patterns (kernel-only vs modular).
- [Bootstrap Examples](BOOTSTRAP_EXAMPLES.md) — copy-paste bootstrap snippets.
- [Database](DATABASE.md) — `BlackCat\Core\Database` (safe PDO wrapper).
- [Security](SECURITY.md) — key management, crypto primitives, CSRF, file vault.
- [Live RPC smoke test](LIVE_RPC_SMOKE.md) — manual JSON-RPC check against a real chain.
- [Trust Kernel Status](TRUST_KERNEL_STATUS.md) — minimal health output (JSON) for monitoring/automation.
- [Trust Watchdog](TRUST_WATCHDOG.md) — planned “security grid” worker (local + remote sentinel model).
- [Troubleshooting](TROUBLESHOOTING.md) — common runtime/setup issues.
- [Compatibility](COMPATIBILITY.md) — legacy facades and recommended migrations.
- [Roadmap](ROADMAP.md) — planned stabilization and next steps.
- [Versioning](VERSIONING.md) — SemVer and what is considered stable kernel API.
