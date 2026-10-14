# uBixVault — Positioning & Prior Art

> **Status:** Active · Last updated 2026-10-14 (v1.6.0)
> What uBixVault is, and how it relates to HashiCorp Vault and OpenBao.

## Prior art (acknowledged up front)

Secrets management is a mature space with strong existing implementations, and it's worth
being clear about them:

- **HashiCorp Vault** — the reference implementation and uBixVault's API-compatibility
  target. Relicensed from MPL 2.0 to the source-available **BUSL** in 2023; now IBM-owned.
- **OpenBao** — the MPL 2.0, Linux Foundation fork of Vault's last open version: the other
  open option, and the one with Vault's full breadth, plugin ecosystem and an established
  community. The honest difference is scope and size: OpenBao is Vault's whole system kept
  open; uBixVault is a much smaller one, built to be read and run end to end.

## What uBixVault is

**A lightweight, open, Vault-API-compatible secrets manager** — a real alternative to
HashiCorp Vault for the deployments that need what it covers: KV, Transit, dynamic database
credentials, PKI, the main auth methods, policies and leases, over Vault's HTTP API and
client libraries, with HA and (experimentally) integrated Raft storage.

- **Lightweight.** One small Go binary and a handful of dependencies. No plugin processes,
  no sidecars, no external service required to start: it is easy to read, audit by hand
  and run. This is a statement about size and operation, not about feature parity.
- **Open.** BSD 3-Clause licensed, owned by its author, with no source-available terms and no
  vendor that can change them.
- **Vault-API-compatible.** Written to Vault's request and response shapes so the `vault`
  CLI, External Secrets Operator and Vault's Go client work unmodified. Compatibility is
  checked end to end, and divergences are documented, not hidden.
- **Origin.** It began as secrets management for
  [uBixCore](https://github.com/cwolsen7905/uBixCore), but it is framework-agnostic and
  works with any stack over its HTTP API.

## Scope philosophy

Depth over breadth: a small, finished, tested, well-documented core rather than a partial
clone chasing feature parity. The committed scope and the optional extensions are separated
explicitly in `docs/ROADMAP.md`, with the reasoning in `docs/DECISIONS.md` (D-004).

## What this project is *not*

- Not Vault's full feature set: no Enterprise capability, and not every Community one —
  see the roadmap's committed-vs-extension split and the table below.
- Not independently audited. It has had **no external security review**; that is the open
  milestone, tracked separately from the version (`docs/VERSIONING.md`,
  `docs/SECURITY_REVIEW_BRIEF.md`). Weigh that against what the secrets are worth.
- Not a claim that Raft storage is finished: integrated storage is **experimental** in
  1.6.0 until it has soaked in the maintainer's own dev and prod.

## Where it sits: Vault Community vs. Enterprise

uBixVault deliberately targets a **subset of Vault _Community_** (the free tier), not
Enterprise — and it does not yet have full Community parity either. That's the point of
"depth over breadth." Enterprise-tier features are, with a couple of exceptions, out of
scope; the long-term catch-up backlog is tracked in `docs/ROADMAP.md` ("Beyond 1.0").

The Community/Enterprise line has shifted over Vault's history — cloud-KMS auto-unseal,
login MFA, and rate-limit quotas all moved from Enterprise to Community. Notably, uBix
Vault's **external-command seal already covers cloud-KMS/HSM auto-unseal** — the capability
that was Enterprise-gated (HSM) for years — reached without any provider SDK.

| Vault Enterprise capability | uBixVault |
| --- | --- |
| HSM / cloud-KMS auto-unseal (+ seal-wrap) | 🟡 KMS/HSM unseal via the external-command seal; no seal-wrap |
| Automated snapshots to cloud storage | 🟡 scheduled backup CronJob (to a PVC, not object storage yet) |
| Namespaces (in-vault multi-tenancy) | ❌ |
| Performance + DR replication; performance standbys | ❌ |
| Sentinel policies (ABAC / EGP / RGP) | ❌ — ACL (JSON + HCL) only |
| Control Groups (M-of-N approval) | ❌ |
| Managed Keys; Key Management engine (→ cloud KMS) | ❌ |
| KMIP secrets engine | ❌ |
| Transform engine (tokenization / FPE / masking) | ❌ |
| FIPS 140-2/-3 builds; entropy augmentation | ❌ |
| Lease-count / resource quotas | ✅ rate-limit and lease-count quotas, path-scoped, Vault-compatible (1.1, D-020) |

Of ~15 Enterprise-differentiated capabilities, uBixVault has ~1 and a partial analog of ~2,
and is missing ~12 — **by design.** The gaps that matter more for the project are the
remaining *Community* ones (more auth methods and DB plugins), also tracked in the roadmap;
the real open milestone is an external security review.

**High availability** is a Community feature in Vault, and uBixVault has it two ways. Since
1.2, active/standby replicas over MySQL/MariaDB: every replica unseals, one holds a fenced
lock in the database and serves, standbys forward to it over their own mutual-TLS cluster
port, and `sys/leader`, `sys/step-down` and the `sys/health` standby codes behave as
Vault's do (D-021). Since 1.6.0, **integrated storage (Raft)** — **experimental**: three
replicas each keep their own copy, so the database leaves the critical path, with a
MySQL-to-Raft migration and rollback that is rehearsed in CI. It is a different
implementation from Vault's integrated storage (a few response shapes and autopilot
detail differ; `docs/design/raft-storage.md`). What neither has is Enterprise *performance
standbys* that answer reads.
