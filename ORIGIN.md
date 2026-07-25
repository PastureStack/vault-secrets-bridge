# Origin and release gates

This file preserves necessary provenance and legal facts. Historical names below are attribution only and do not identify the current project.

## Source snapshot

The migration source is `rancher/secrets-bridge-v2` commit `080db7d3ebfd98a5e725f4aec1970b524f8f1290`, tree `bb59f03c610ba51990f44331daa1718460161372`. Lightweight tag `v0.3.5` points directly to that commit. The source has 57 reachable commits and 15 tags at the start of this migration.

Copyright (c) 2014-2017 Rancher Labs, Inc.

The historical project was distributed under Apache License 2.0. The root `LICENSE` in this tree is the exact 10,174-byte source Git blob `f433b1a53f5b830a205fd2df78e2b34974656c7b`, SHA-256 `0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594`.

## Historical dependency evidence

Twenty license or patent artifacts found in the source vendor tree are byte-preserved under `LICENSES/historical` and mapped by `LICENSES/HISTORICAL-MANIFEST.json`. They include Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, MPL-2.0, and an additional patent grant. They document historical code only; the current implementation imports no external module.

The source vendor manifest also named packages under `golang.org/x/net`, `golang.org/x/text`, `github.com/moby/moby`, `github.com/rancher/go-rancher-metadata`, and `github.com/rancher/secrets-api` without a standalone license file at the audited paths. Three AUTHORS or CONTRIBUTORS files remain in history but are not redistributed by the current implementation. These facts are release gates, not conclusions about license status.

## History and runtime gates

No public history may be published until every reachable commit and blob has passed privacy, credential, key, legal, brand, binary, and distribution review. Valid historical authorship and attribution must remain; unsafe or legally uncertain objects take priority over unchanged commit identity.

The current implementation uses only the Go standard library. Its broker, Vault HTTP client, compatible environment API client, signature verifier, replay cache, envelope encoder, and atomic accessor state store were independently rewritten after the preserved upstream boundary. It does not import the historical server, clients, RSA helpers, volume code, vendor packages, containers, or release automation.

Release requires repeated unit and race tests, public-tree and legal-manifest gates, deterministic Linux builds, container vulnerability and secret scans, an isolated Vault integration test, a real host-identity signature test, workload materialization and revoke evidence, restart and rollback evidence, and confirmation that every Catalog and compose image reference uses a semantic version tag without a digest.
