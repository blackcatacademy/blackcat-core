# BlackCat Core — Documentation

`blackcat-core` is the kernel of the BlackCat ecosystem. This folder documents the stable primitives that live in core, and how core composes with the modular stack.

## Start here

- [Getting Started](GETTING_STARTED.md) — bootstrapping patterns (kernel-only vs modular).
- [Bootstrap Examples](BOOTSTRAP_EXAMPLES.md) — copy-paste bootstrap snippets.
- [Database](DATABASE.md) — `BlackCat\Core\Database` (safe PDO wrapper).
- [Security](SECURITY.md) — key management, crypto primitives, CSRF, file vault.
- [Minimal Security Stack](MINIMAL_SECURITY_STACK.md) — core + config + kernel contracts only.
- [Front Controller Hardening](FRONT_CONTROLLER.md) — strict single-entrypoint web setup (cheap hosting baseline).
- [Integrity Manifest](INTEGRITY_MANIFEST.md) — how to build/commit roots for tamper detection.
- [Deployment Hardening](DEPLOYMENT_HARDENING.md) — practical baseline for single-VM reality.
- [Live RPC smoke test](LIVE_RPC_SMOKE.md) — manual JSON-RPC check against a real chain.
- [Trust Kernel Status](TRUST_KERNEL_STATUS.md) — minimal health output (JSON) for monitoring/automation.
- [Trust Watchdog](TRUST_WATCHDOG.md) — planned “security grid” worker (local + remote sentinel model).
- [Troubleshooting](TROUBLESHOOTING.md) — common runtime/setup issues.
- [Compatibility](COMPATIBILITY.md) — migration notes (no shims in core).
- [Roadmap](ROADMAP.md) — planned stabilization and next steps.
- [Versioning](VERSIONING.md) — SemVer and what is considered stable kernel API.
