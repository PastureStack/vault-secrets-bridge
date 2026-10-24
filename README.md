PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

**Upstream:** [`rancher/secrets-bridge-v2`](https://github.com/rancher/secrets-bridge-v2). This GitHub fork retains the upstream Git history, authorship, dates, and license notices unchanged; PastureStack maintenance is consolidated into one commit after the preserved upstream boundary.

# Vault Secrets Bridge

Linux candidate **`v0.1.3`** integrates shared Ubuntu 26.04 security backports for already-installed packages while preserving the selected coreutils provider. It is unpublished; the last published Linux release is [v0.1.2](https://github.com/PastureStack/vault-secrets-bridge/releases/tag/v0.1.2).

Build and image examples below target the candidate. Publication requires completed bundle provenance and the normal final-image release gates. The image retains bundle manifests, source inputs and install/verify receipts under `/usr/share/pasturestack/security/ubuntu-backports/`.

`vault-secrets-bridge` is the PastureStack host-authenticated broker for short-lived HashiCorp Vault leases. It accepts only fresh requests signed by an active host identity, enforces an explicit policy allowlist, asks Vault for a response-wrapped child token, encrypts that wrapping token to the requesting host, and tracks only the revocable accessor under a hashed host-and-volume key.

After publication, the candidate image is `ghcr.io/pasturestack/vault-secrets-bridge:v0.1.3`.
This repository uses unused pure numeric versions and does not publish a
mutable `latest` tag.

The companion `secrets-flexvolume-plugin` runs as a separate host-local Docker volume driver with `--provider vault`. It verifies and decrypts the returned envelope, writes the wrapping token to a read-only file in an isolated `tmpfs`, and asks this bridge to revoke the lease after the final workload unmounts the volume.

## Runtime entry point

```text
vault-secrets-bridge serve
```

The release container starts this entry point automatically. Catalog deployment is the supported installation path; operators do not pass issuing tokens, API credentials, private keys, or accessors on the command line.

## Required configuration

| Environment variable | Purpose |
| --- | --- |
| `VAULT_ADDR` | Vault API base URL |
| `PASTURESTACK_VAULT_ISSUER_TOKEN_FILE` | Absolute path to the platform-mounted Secret containing the renewable issuing token |
| `VAULT_ROLE` | Token role used to create child tokens |
| `PASTURESTACK_VAULT_ALLOWED_POLICIES` | Comma-separated policy allowlist |
| `PASTURESTACK_CONTROL_PLANE_URL` | Compatible environment API URL |
| `PASTURESTACK_ACCESS_KEY` | Scoped environment-service access key |
| `PASTURESTACK_SECRET_KEY` | Scoped environment-service secret key |

The bridge also accepts the environment service's compatibility credential names when deployed through the preserved platform protocol. Those compatibility names are not PastureStack public identifiers.

Catalog deployments mount the issuing token as a read-only platform Secret and
set `PASTURESTACK_VAULT_ISSUER_TOKEN_FILE`. Direct `VAULT_TOKEN` or
`PASTURESTACK_VAULT_ISSUER_TOKEN` input remains available for isolated
validation, but operators should not place issuing tokens in Compose
environment values or command-line arguments. The bridge rejects simultaneous
file and direct-token inputs.

Defaults:

- listener: `0.0.0.0:8080`;
- state file: `/var/lib/pasturestack/vault-secrets-bridge/leases.json`;
- child-token TTL: 5 minutes;
- response-wrapping TTL: 1 minute;
- issuer-token renewal interval: 5 minutes;
- signed-request replay window: 5 minutes; and
- upstream request deadline: 10 seconds.

Run `vault-secrets-bridge serve -help` for bounded overrides.

## HTTP contract

- `POST /v1/leases` issues one encrypted, response-wrapped Vault token.
- `POST /v1/leases/revoke` revokes the accessor associated with the signed host-and-volume identity.
- `GET /healthz` reports process health.
- `GET /readyz` verifies issuer renewal state and Vault availability without returning identifiers or token material.

Issue and revoke requests use RSA-PSS with SHA-256 over the exact JSON body. The bridge obtains the active host's RSA public key from the scoped environment API, rejects stale timestamps and repeated nonces, and does not trust a public key supplied by the caller.

## Security properties

- Requested policies must be sorted, unique, syntactically bounded, and present in the operator allowlist.
- A replacement request revokes the previous accessor before creating another lease.
- Vault returns a response-wrapping token; the bridge never sends the issuing token or an unwrapped child token to a workload.
- The wrapping token uses RSA-OAEP/SHA-256, AES-256-GCM, and HMAC-SHA256 in the envelope consumed by the host driver.
- Persistent state uses mode `0600` and stores only a SHA-256 host-and-volume key plus the Vault accessor.
- Plain HTTP is restricted to private, loopback, or link-local addresses. HTTPS requires TLS 1.2 or newer.
- Redirects and environment proxy routing are rejected.
- Request and response bodies, headers, timeouts, policy counts, replay entries, paths, ownership values, and file modes are bounded.
- Logs and errors never include tokens, credentials, accessors, host identifiers, volume names, policies, ciphertext, or upstream response bodies.

See [the security model](docs/SECURITY-MODEL.md), [the compatibility boundary](docs/COMPATIBILITY.md), [origin and release gates](ORIGIN.md), and [the historical legal manifest](LICENSES/HISTORICAL-MANIFEST.json).

## Audit planner

The repository retains the side-effect-free lifecycle planner:

```text
vault-secrets-bridge [--locale en-US|zh-TW] capabilities
vault-secrets-bridge [--locale en-US|zh-TW] validate
vault-secrets-bridge [--locale en-US|zh-TW] plan
```

These commands never start the network service or handle runtime token material. Runtime behavior is available only through `serve`.

## Validation

Go 1.26 or newer is required:

```text
./scripts/validate.sh
./scripts/validate.ps1
```

The validation scripts check formatting, repeated unit tests, race safety, vet, module integrity, the public-tree policy, deterministic builds, binary content, and audit-planner behavior. The release container repeats the complete Go test suite before producing the static Linux binary.

The repository-integrity workflow runs for pull requests, `main` pushes, and
manual dispatch. It validates repository policy but does not publish or deploy
runtime artifacts.

## License

The preserved root license is Apache License 2.0. Historical third-party legal artifacts are byte-preserved and classified separately under `LICENSES/`; their presence does not change the root license or claim authorship of historical work. The current implementation uses only the Go standard library and does not import historical vendored packages.

## October 2026 security maintenance

Maintained Go builds select the patched Go 1.27.3 compiler without raising the existing Go language requirement. Ubuntu build/runtime stages apply the checksum-pinned `ca-certificates 20260816ubuntu0.26.04.1` security package after their frozen APT baseline; the final trust store and installed version are verified. Release artifacts must pass the repository's existing checks before publication.

## Full-severity release policy

Release verification retains the complete runtime vulnerability report. Every
finding with an official fix blocks release, regardless of severity. Unknown
findings block unless a separately reviewed, exact not-affected statement is
proved by the actual product dependency graph. LOW/MEDIUM findings without an
official fix require the repository's exact CVE/package/version/PURL review ledger;
new or changed findings fail closed. Each candidate must pass this policy against its exact image and package versions.
