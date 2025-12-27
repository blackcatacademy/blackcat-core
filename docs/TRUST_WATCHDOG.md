# Trust Watchdog (planned)

This document describes a planned “security grid” layer that complements the Trust Kernel:
- the Trust Kernel enforces trust **inside** the runtime (guards in `KeyManager` + `Database`),
- the Watchdog detects abnormal situations and can trigger **emergency actions** (pause / incident reporting).

## Why this exists

Even with strict fail-closed runtime guards, a compromised host can still cause damage:
- kill processes,
- block outbound RPC,
- attempt to replace runtime config / binaries (DoS),
- try to exfiltrate encrypted data (DB backups, caches) and hunt for keys.

The Watchdog’s job is not to “make compromise impossible”, but to:
- detect loss of trust signals,
- make the failure mode deterministic,
- shorten the attacker’s time window,
- trigger emergency state transitions on-chain (when possible).

## Threat model (summary)

Covered best-effort:
- RPC outage / tampering (quorum loss),
- runtime integrity mismatch (file tamper),
- missing on-chain check-ins,
- unexpected contract state changes (pause/upgrade).

Not fully solvable by software alone:
- attacker with full root access can delete the install (DoS),
- attacker with physical access,
- attacker who controls both the host and all admin signing devices.

## Core mechanism

The contracts already support a “kill switch” posture:
- `InstanceController.pause()` (emergency stop),
- incident reporting / audit commitments (if enabled),
- upgrade gating (multi-step ceremony).

The Watchdog adds operational glue:
- periodic checks (chain + local),
- a decision policy (when to pause, when to alert),
- an “outside-the-host” trust anchor for emergency actions.

## Recommended architecture

### 1) In-process enforcement (already in core)

`blackcat-core` installs strict guards:
- secrets reads/writes are blocked when trust fails (`KeyManager`),
- DB writes are blocked immediately when trust fails (`Database`),
- raw PDO access is denied to avoid bypass (`Database::getPdo()` guarded).

### 2) Local Watchdog (optional)

Runs on the same host (systemd container/cron worker).

Pros:
- can react quickly,
- can provide local telemetry/logs.

Cons:
- if the host is compromised, the attacker can kill it.

Local Watchdog should not be considered authoritative by itself.

### 3) Remote Guardian / Sentinel (recommended)

Runs outside the host and watches for:
- periodic `checkIn` txs/events,
- signed off-chain heartbeats anchored to chain (optional),
- expected on-chain invariants (policy hash, root, registry pointers).

If trust breaks or check-ins stop:
- it triggers `pause()` / `reportIncident()` using an emergency multi-sig threshold,
- it pages the operator with a clear incident timeline.

This is the only practical way to remain resilient against “host is fully compromised” scenarios.

## “Security grid” behavior

When suspicion is detected, the “grid” should do **safe, reversible** actions first:
- pause on-chain,
- force runtime into fail-closed (already done by guards),
- stop accepting new sessions / tokens (future: `blackcat-auth` integration),
- emit alerts to monitoring/observability sinks.

Destructive actions (wipe keys, rotate keys, delete DB) must be **opt-in** and require multi-sig approval,
because they can permanently destroy availability.

## Implementation plan (repo layout)

To avoid mixing ops logic into `blackcat-core`, the Watchdog should live in a separate optional module:
- proposed repo: `blackcatacademy/blackcat-trust-watchdog` (name TBD)
- depends on: `blackcat-core` + `blackcat-config`
- optional CLI integration via `blackcat-cli` (`blackcat trust watch`, `blackcat trust doctor`)

## Interfaces needed from core (stable)

The Watchdog should only rely on stable kernel interfaces:
- `BlackCat\Core\TrustKernel\TrustKernel::check()` (status + errors),
- `BlackCat\Core\TrustKernel\InstanceControllerReader` (low-level reads),
- deterministic status output for monitoring (JSON).

