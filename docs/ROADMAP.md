# uBix Vault — Roadmap

> **Status:** Active · Last updated 2026-08-06 · Current release `v0.2.0-beta.8`

uBix Vault is a **self-hosted secrets manager for a single organization**, built on a
minimal-dependency, fully-auditable ethos: the security-critical code — the encryption
barrier, Shamir seal/unseal, all cryptography — is standard-library Go written and tested
in-house, so the entire trust path can be read in an afternoon. It speaks a
Vault-compatible HTTP API so existing clients work unchanged.

The **feature core is essentially complete** (see below). The remaining work to a real
`1.0` is not more features — it is the three things that gate running a secrets manager in
production: **durable storage**, **hardened correctness**, and **external review**. This
roadmap is sequenced around that reality.

## Honest positioning (read before deploying)

uBix Vault matches HashiCorp Vault's *core feature surface* but **not** its *assurance*.
Until the items in "Path to production 1.0" below are done — in particular an external
security review — it is suitable for sandbox, dev, and internal/low-blast-radius use, not
as a drop-in replacement for an audited secrets manager holding critical secrets.

**Recommended adoption path** for anyone (including the maintainer) moving real workloads
onto it:
1. Run it **alongside** an existing audited secrets manager, not as a big-bang cutover.
2. Start with **low-blast-radius** secrets (a dev environment, one non-critical service).
3. Keep the incumbent for anything whose loss or compromise is serious until durable
   storage **and** an external review are in place.
4. Make the risk **visible** to whoever owns security — a solo, unreviewed system in the
   secrets path is a shared-risk decision.

---

## Where it is now (through `v0.2.0-beta.8`)

Core — complete, tested, documented:

- [x] Storage backend interface + **file** and **in-memory** backends.
- [x] **Barrier** — AES-256-GCM at rest, path-bound AAD, barrier-key hierarchy.
- [x] **Seal / unseal** — in-house Shamir k-of-n; init, unseal, seal-status.
- [x] **Root regeneration** (`generate-root`) + **recovery keys** for auto-unseal mode.
- [x] **Tokens** (TTL/expiry, renew-self, revoke-self) + **ACL policies** (JSON *and* HCL, default-deny).
- [x] **KV v2** (versioned secrets).
- [x] **Transit** — full crypto-as-a-service: encrypt/decrypt, rotate, **rewrap**, **data keys**, **HMAC**, **sign/verify** (ECDSA + Ed25519).
- [x] **Dynamic database credentials** — `DatabasePlugin` interface + MariaDB plugin, lease-scoped, auto-revoked.
- [x] **PKI** — internal CA, role-constrained short-lived certificate issuance.
- [x] **Auth methods** — token, AppRole, Kubernetes, userpass, JWT/OIDC.
- [x] **Seals** — Shamir, static KEK, and transit seal (unwrap via another vault).
- [x] **Response wrapping** — single-use, TTL'd secure-introduction tokens.
- [x] **Audit** — fail-closed file device, HMAC'd sensitive fields.
- [x] **Leases** — renew/lookup + cascading revocation.
- [x] **Web console** (`/ui/`) — KV, policies, tokens, PKI.
- [x] **Operations** — Prometheus metrics, rate limiting, health/readiness, encrypted snapshot/restore.
- [x] **Delivery** — `ubixvault server` + `operator` CLI, single-node Helm chart, multi-arch GHCR images, CI (build/test/lint/govulncheck/MariaDB integration).

---

## Path to production 1.0

Ordered by what actually makes it safe to run, not by what is most fun to build. The
guiding rule: **durability without correctness is a trap** — HA on top of un-hardened
crypto is just a reliable way to lose or leak secrets — so the hardening work runs
*alongside* the storage work, not after it.

### Tier 0 — production safety (do first; small)
- [ ] **Automated, tested, off-node backups.** Wire `snapshot save` to a scheduled job →
      object storage, and prove a restore. Converts "single disk dies = total loss" into
      "lose minutes." (Chart CronJob + a snapshot-to-object-store target.)
- [ ] **Rekey** — operator flow to re-split the master key into fresh Shamir shares (and
      change threshold/count), for when a share-holder leaves. Mirrors `generate-root`.

### Tier 1 — durable storage (the real production unlock)
- [ ] **SQL storage backend** over the existing MySQL/MariaDB driver (no new dependency).
      Turns "single node + local disk" into "**replaceable node over managed, replicated
      storage**": the node can die and reschedule pointing at the same durable database,
      and the database's own HA handles durability. For most single-org production this is
      *sufficient HA*; it also de-risks any future Raft work.

### Continuous — trust & correctness (rides alongside Tier 0–1)
- [ ] **Fuzz** the parsers — HCL policy, JWT/JWS, transit ciphertext, snapshot format.
- [ ] **Property tests** for Shamir (split/combine round-trips, threshold behavior) and the barrier.
- [ ] **Race / chaos tests** — concurrent access; kill mid-write and verify recovery.
- [ ] **Supply-chain hygiene** — signed, reproducible release images (cosign), SBOM.

### Tier 2 — pre-production trust gates (before real secrets land)
- [ ] **Pluggable cloud-KMS/HSM seal** behind the existing seal interface (kept zero-dep by
      staying over-the-wire / pluggable, like the transit seal), so the KEK is never on the host.
- [ ] **`SECURITY.md`** + coordinated-disclosure policy; threat-model refresh (`docs/DESIGN.md`).
- [ ] **External security review** — the real gate. Full paid audit (Trail of Bits / NCC /
      Cure53) when feasible; at minimum a scoped external look + the hardening above first.

### Optional — only if a single durable node isn't enough
- [ ] **Integrated Storage (Raft)** — multi-writer HA with no external dependency. Deliberately
      **last**: the SQL backend already gives durability and a replaceable node, so Raft is a
      step this project may never need. If pursued, starts with a design doc + an ADR on
      in-house Raft vs. `hashicorp/raft` (the latter breaks the one-dependency ethos).

---

## Beyond 1.0 — not committed scope

Recorded to show the shape of the full problem space; undertaken only if they earn their
place, never at the expense of the path above.

- **More auth**: TLS client cert, LDAP.
- **More dynamic secrets**: PostgreSQL/Mongo/MSSQL DB plugins; cloud IAM (AWS/GCP/Azure).
- **Identity**: entities + groups, so multiple auth logins map to one subject.
- **Console breadth**: Transit and the newer auth methods in `/ui/`.
- **Transit extras**: convergent encryption, key derivation, BYOK import.
- **Multi-tenancy**: namespaces (in-vault administrative isolation).
- **Replication**: multi-DC HA/DR; control groups (M-of-N approval); login-enforced MFA.
- **Hard compliance**: HSM/PKCS#11 seal-wrap, FIPS 140-3 validated build, KMIP, tokenization/FPE.
- **OIDC discovery**: resolve the JWKS URL from `.well-known/openid-configuration`.

---

## Sequencing principles

- **Interfaces first** (storage, seal, auth, engine, audit) so every addition is additive, never a rewrite — this is what lets the SQL backend and KMS seal slot in without touching the core.
- **Durability before HA, correctness before durability.** Backups and hardening are cheap insurance that make everything after them safer.
- **Zero-new-dependency by default.** Each capability is built from the standard library unless there is no reasonable alternative; the dependency graph staying readable is a security feature.
- **Ship in small, reviewed, CI-green slices**; cut a beta when a coherent set lands.
