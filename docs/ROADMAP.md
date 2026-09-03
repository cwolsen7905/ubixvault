# uBix Vault — Roadmap

> **Status:** Active · Last updated 2026-08-27 · Current release `v0.2.0-beta.11`

uBix Vault is a **self-hosted secrets manager for a single organization**, built on a
minimal-dependency, fully-auditable ethos: the security-critical code — the encryption
barrier, Shamir seal/unseal, all cryptography — is standard-library Go written and tested
in-house, so the entire trust path can be read in an afternoon. It speaks a
Vault-compatible HTTP API so existing clients work unchanged.

The **feature core is essentially complete**, and as of `v0.2.0-beta.11` the
engineering gates for `1.0` have landed: **durable storage** (a MySQL/MariaDB backend),
**hardened correctness** (parser fuzzing, crypto property tests, a crash-recovery fix,
signed images + SBOM), and the **cloud-KMS/HSM seal** (an external-command seal, ADR
D-015). What remains for `1.0` is the one gate that is **not ours to build**: an
**external security review**. This roadmap is sequenced around that.

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

## Where it is now (through `v0.2.0-beta.10`)

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
- [x] **Rekey** — live rotation of the Shamir unseal shares (`sys/rekey`, `operator rekey`), no downtime.
- [x] **MySQL/MariaDB storage backend** — durable, replaceable-node storage (`-storage mysql`); the DB holds only ciphertext (ADR D-014).
- [x] **Scheduled backups** — opt-in chart CronJob snapshotting to an off-node PVC.
- [x] **Signed releases** — keyless cosign signatures + SPDX SBOM attestation on every published image.
- [x] **Dedicated liveness endpoint** (`/v1/sys/livez`), used by the chart's probes.

---

## Path to production 1.0

Ordered by what actually makes it safe to run, not by what is most fun to build. The
guiding rule: **durability without correctness is a trap** — HA on top of un-hardened
crypto is just a reliable way to lose or leak secrets — so the hardening work runs
*alongside* the storage work, not after it.

### Tier 0 — production safety (do first; small) — **done**
- [x] **Automated, off-node backups.** Chart CronJob runs `snapshot save` to a separate
      (network-backed) PVC. *Follow-up:* timestamped history + direct object-storage upload
      (needs an uploader image alongside the shell-less vault image).
- [x] **Rekey** — live rotation of the Shamir unseal shares (`sys/rekey`, `operator rekey`),
      no downtime, no data re-encryption.

### Tier 1 — durable storage (the real production unlock) — **done**
- [x] **SQL storage backend** over the existing MySQL/MariaDB driver (no new dependency).
      Turns "single node + local disk" into "**replaceable node over managed, replicated
      storage**": the node can die and reschedule pointing at the same durable database,
      and the database's own HA handles durability. For most single-org production this is
      *sufficient HA*; it also de-risks any future Raft work.
      Design: [`docs/design/sql-storage-backend.md`](design/sql-storage-backend.md) · ADR D-014.

### Continuous — trust & correctness (rides alongside Tier 0–1)
- [x] **Fuzz** the parsers — HCL policy, JWT/JWS, transit ciphertext, snapshot restore.
- [x] **Property tests** for Shamir (split/combine round-trips) and the barrier (round-trip + encryption-at-rest).
- [~] **Race / chaos tests** — crash-mid-write recovery done (found + fixed a real temp-file bug);
      broader concurrent-load testing still open.
- [x] **Supply-chain hygiene** — keyless cosign signatures + SPDX SBOM attestation on every image.
      *Follow-up:* reproducible builds.

### Tier 2 — pre-production trust gates (before real secrets land)
- [x] **Pluggable cloud-KMS/HSM seal** — an external-command seal (`-seal-external-command`)
      wraps/unwraps the master key via an operator-supplied command, so any cloud KMS or HSM
      works with no provider SDK in the vault ([`docs/design/kms-hsm-seal.md`](design/kms-hsm-seal.md) ·
      ADR D-015). *Follow-up:* Helm `sealExternal` chart wiring.
- [x] **`SECURITY.md`** + coordinated-disclosure policy, supported-versions, and scope;
      threat-model refresh in `docs/DESIGN.md` §5 (current as of beta.11).
- [ ] **External security review** — the real gate. Full paid audit (Trail of Bits / NCC /
      Cure53) when feasible; at minimum a scoped external look + the hardening above first.

### Optional — only if a single durable node isn't enough
- [ ] **Integrated Storage (Raft)** — multi-writer HA with no external dependency. Deliberately
      **last**: the SQL backend already gives durability and a replaceable node, so Raft is a
      step this project may never need. If pursued, starts with a design doc + an ADR on
      in-house Raft vs. `hashicorp/raft` (the latter breaks the one-dependency ethos).

---

## Beyond 1.0 — the catch-up backlog (not committed scope)

The long path toward broader Vault parity, recorded so the gap is explicit and can be
chipped away at slowly. **This is not committed 1.0 scope** — 1.0 is gated only on the
external review (above). These are undertaken as they earn their place, never at the expense
of the finished core, and each larger item gets its own design note + ADR first (as the SQL
backend and the KMS seal did), with any new dependency recorded there. Rough priority:
Community-parity gaps before Enterprise-tier features.

### Toward Vault Community parity (free-tier gaps)
- [ ] **Integrated Storage (Raft)** — multi-writer HA (also in "Path to 1.0 · Optional"; the SQL backend already gives a durable, replaceable node, so this may never be needed).
- [x] **TLS client-certificate auth** — mTLS cert roles (CA- or pinned-cert trust, name constraints).
- [ ] **More auth methods** — LDAP.
- [ ] **More dynamic secrets** — PostgreSQL / MySQL / Mongo / MSSQL DB plugins; cloud IAM (AWS/GCP/Azure).
- [ ] **Identity** — entities + groups, so multiple auth logins map to one subject. Design: [`docs/design/identity-entities-groups.md`](design/identity-entities-groups.md) (ADR D-016, proposed); ships in phases.
- [ ] **Console breadth** — Transit and the newer auth methods in `/ui/`.
- [ ] **Transit extras** — convergent encryption, key derivation, BYOK import.
- [x] **Cubbyhole** — per-token private storage, destroyed on token revoke.
- [x] **OIDC discovery** — resolve the JWKS URL from `.well-known/openid-configuration`.

### Toward Vault Enterprise parity (Enterprise-differentiated features)
Mostly large and compliance-oriented; listed so the gap is explicit (see
`docs/POSITIONING.md` for the side-by-side). Of ~15, two already have partial analogs:
- [~] **HSM / cloud-KMS auto-unseal** — done via the external-command seal (D-015); **seal-wrap** of individual entries is not.
- [~] **Automated snapshots to object storage** — the scheduled backup CronJob exists (to a PVC); direct object-storage upload + retention remains.
- [ ] **Namespaces** — in-vault administrative multi-tenancy.
- [ ] **Replication** — Performance replication, Disaster-Recovery replication, performance standby nodes.
- [ ] **Policy-as-code (Sentinel-style)** — ABAC / endpoint- & role-governing policies beyond ACL.
- [ ] **Control Groups** — M-of-N approval to access a secret; login-enforced step-up MFA.
- [ ] **Managed Keys** — offload crypto operations to an external HSM/KMS.
- [ ] **Key Management secrets engine** — distribute/manage keys in cloud KMS (AWS/Azure/GCP).
- [ ] **KMIP secrets engine** — act as a KMIP server.
- [ ] **Transform secrets engine** — tokenization, format-preserving encryption, data masking.
- [ ] **Resource quotas** — lease-count quotas and richer rate-limit quotas.
- [ ] **Compliance builds** — FIPS 140-3 validated crypto, entropy augmentation.

---

## Sequencing principles

- **Interfaces first** (storage, seal, auth, engine, audit) so every addition is additive, never a rewrite — this is what lets the SQL backend and KMS seal slot in without touching the core.
- **Durability before HA, correctness before durability.** Backups and hardening are cheap insurance that make everything after them safer.
- **Zero-new-dependency by default.** Each capability is built from the standard library unless there is no reasonable alternative; the dependency graph staying readable is a security feature.
- **Ship in small, reviewed, CI-green slices**; cut a beta when a coherent set lands.
