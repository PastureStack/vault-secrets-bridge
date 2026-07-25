# Security model

## Trust boundary

The bridge is an environment-level service with three trusted dependencies:

- a scoped compatible environment API used only to resolve an active host identity key;
- a renewable HashiCorp Vault issuing token restricted to one token role; and
- a local mode-`0600` state file containing hashed lease keys and revocable accessors.

The caller is an untrusted host-side volume driver until its RSA-PSS signature has been verified against the active host key returned by the environment API. The bridge never accepts a caller-supplied public key.

## Authentication and replay protection

Issue and revoke requests contain a version, host UUID, volume name, UTC timestamp, and 192-bit random nonce. The host signs the exact JSON body with RSA-PSS/SHA-256. The bridge:

1. strictly decodes the bounded single JSON document;
2. validates every field and the operator policy allowlist;
3. resolves exactly one matching host in the `active` state;
4. verifies the signature with a 2048- to 8192-bit RSA key; and
5. atomically records a hash of the host and nonce for the five-minute replay window.

Stale timestamps, future timestamps outside the same window, repeated nonces, invalid signatures, ambiguous host results, unknown fields, multiple documents, unsupported content types, query strings, redirects, and oversized requests fail closed.

## Vault boundary

The operator supplies a renewable issuing token and token role. A workload may request only sorted, unique policy names present in `PASTURESTACK_VAULT_ALLOWED_POLICIES`. The bridge asks Vault to create a renewable child token with a bounded five-minute default TTL and a one-minute response-wrapping TTL.

Vault returns a wrapping token and wrapped accessor. The bridge encrypts the wrapping token to the host and stores only the accessor. It never unwraps the child token. Before replacing a lease for the same host and volume, it revokes the previous accessor. Final unmount uses a separately signed request to revoke and remove the current accessor.

The issuing token is never written to disk by this process. HTTP headers, response bodies, request bodies, tokens, accessors, policies, identifiers, keys, and ciphertext are never logged.

## Envelope

Each successful issue response contains one encrypted record compatible with the PastureStack host volume driver:

- RSA-OAEP with SHA-256 protects a random 256-bit data key;
- AES-256-GCM with a 96-bit nonce protects the base64-encoded wrapping token;
- HMAC-SHA256 authenticates the encoded encrypted payload; and
- the file path, numeric UID/GID, and mode are constrained to safe read-only values.

Only `0400`, `0440`, and `0444` are accepted. Paths must be relative, clean, slash-separated, and free of dot segments or special characters.

## Persistent state

The state file uses mode `0600` in a mode-`0700` directory under `/var/lib/pasturestack`. Keys are SHA-256 digests of host UUID plus volume name. Values are bounded Vault accessors. Host identifiers, volume names, policies, tokens, credentials, and keys are not persisted.

Updates use a same-directory temporary file, `fsync`, and atomic rename. If state activation fails after Vault issues a lease, the bridge attempts immediate revocation and returns an error.

## Transport and limits

- HTTPS requires TLS 1.2 or newer.
- Plain HTTP is limited to private, loopback, and link-local IP addresses.
- Environment proxy variables are ignored.
- Redirects are rejected.
- Default request timeout is 10 seconds.
- Signed request bodies default to 64 KiB maximum.
- Upstream responses default to 2 MiB maximum.
- At most 16 policies may be requested, and at most 64 may be allowlisted.
- The replay cache is bounded and expires entries after five minutes.

## Availability and residual risk

`/readyz` checks both the last issuer-renewal result and Vault health. Renewal failures stop readiness until a later renewal succeeds. Existing response-wrapped tokens retain their Vault TTL if the bridge becomes unavailable.

Root on the host can read the host private key and workload mount. A compromised environment API, active-host identity key, Vault issuing token, or token role defeats the corresponding trust boundary. A process crash after Vault revocation but before state activation may leave a stale accessor record; revocation treats Vault's already-invalid accessor response as idempotent on the next request. Operators must restrict network reachability, protect environment credentials and the state volume, issue the narrowest renewable token possible, and monitor readiness failures.

## Audit planner separation

The `capabilities`, `validate`, and `plan` commands remain side-effect-free and never initialize this runtime. The networked broker starts only when the first argument is `serve`.
