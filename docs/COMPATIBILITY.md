# Compatibility boundary

## Deployment topology

The bridge runs once per environment. The PastureStack Vault volume driver runs once on each eligible Linux host and connects to:

- host metadata for its immutable host UUID;
- this bridge for issue and revoke requests; and
- the host-local Docker Volume Plugin API for workload mounts.

The bridge uses scoped environment-service credentials to resolve active host public keys. It does not need the Docker socket, host network namespace, host PID namespace, host filesystem, or privileged-container mode.

## Current protocol

The runtime API is intentionally small:

- `POST /v1/leases`
- `POST /v1/leases/revoke`
- `GET /healthz`
- `GET /readyz`

The host driver option names are:

- `io.pasturestack.vault.policies` (required);
- `io.pasturestack.vault.file` (default `token`);
- `io.pasturestack.vault.uid` (default `0`);
- `io.pasturestack.vault.gid` (default `0`); and
- `io.pasturestack.vault.mode` (default `0400`).

Neutral short aliases (`policies`, `file`, `uid`, `gid`, and `mode`) are accepted for compose compatibility. Conflicting aliases are rejected.

The driver name, socket, volume root, health port, and bridge URL are supplied by the Catalog template. Image references use semantic version tags only.

## Environment service compatibility

The bridge's public variables are `PASTURESTACK_CONTROL_PLANE_URL`, `PASTURESTACK_ACCESS_KEY`, and `PASTURESTACK_SECRET_KEY`. Catalog deployment may supply the environment service's preserved compatibility credential names. Those aliases exist only at the protocol boundary and are not current project identifiers.

## Deliberate differences

The current implementation does not preserve historical routes, signature headers, device strings, writable token files, accessor files inside workload volumes, unrestricted mount behavior, vendor packages, plaintext diagnostics, global variables, or permissive type assertions.

The bridge no longer asks the environment API for a volume template. Per-container isolation is provided by the current Docker volume driver: each local volume has a separate memory filesystem, and the lease key includes both authenticated host identity and volume name.

The bridge returns a standard encrypted-record envelope already used by the PastureStack secret volume driver. This avoids a second privileged mount implementation and keeps all host filesystem controls in one audited component.

## Offline planner compatibility

The metadata-only `v1alpha1` planner remains available through `capabilities`, `validate`, and `plan`. Its schema is not a wire format for runtime tokens. Runtime requests and encrypted responses are accepted only by the `serve` command.
