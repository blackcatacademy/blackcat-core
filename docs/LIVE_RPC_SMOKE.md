# Live RPC smoke test (manual)

This document describes how to run a **real-chain** smoke test against an already-deployed `InstanceController`.

This is intentionally **not** a PHPUnit test:
- it depends on an external RPC endpoint,
- it is meant to be run manually before/after deployments.

## Edgen Chain (Chain ID `4207`)

Example:

```bash
docker run --rm -u 1000:1000 -v "$PWD":/app -w /app/blackcat-core composer:2.7 \
  php scripts/trust-kernel-rpc-smoke.php \
    --rpc https://rpc.layeredge.io \
    --chain-id 4207 \
    --quorum 1 \
    --controller 0xYOUR_INSTANCE_CONTROLLER
```

Output is JSON and includes:
- `snapshot.activeRoot` / `activeUriHash` / `activePolicyHash`,
- `paused`,
- `release_registry`,
- basic `eth_getCode` sanity.

## Notes

- A “trusted” runtime check requires your local integrity manifest (`trust.integrity.*`) to match on-chain state.
- This script only confirms that JSON-RPC + contract reads work.

