# uBix Vault — Decision Log (ADRs)

> **Status:** Active · Last updated 2026-07-18
> Architecture decision records: the trade-offs behind each significant choice, and why.

## D-001 — Implementation language: Go

**Status:** Accepted · 2026-07-18

**Decision:** Go.

**Options weighed:** Go, Rust, C++.

| | Go (chosen) | Rust | C++ |
|---|---|---|---|
| Ecosystem fit (Vault/K8s/cloud-native) | ★★★ best | ★★ growing | ★ weak |
| Contributor pool for this domain | ★★★ | ★★ | ★ |
| Memory safety | ★★ (safe, GC) | ★★★ (safe, no GC) | ✗ (unsafe) |
| Deterministic secret zeroization / mlock | ★ (GC relocates) | ★★★ | ★★★ |
| Native HSM/PKCS#11 / FIPS module integration | ★★ | ★★ | ★★★ |
| Time-to-MVP | ★★★ | ★★ | ★ |

**Why Go over C++:** for a *security* product, C++'s manual memory management adds an
entire class of CVEs (buffer overflow, UAF) — the opposite of what we're selling. C++
only wins with a hard FIPS/HSM/embedded constraint *and* existing secure-C++ expertise.

**Why Go over Rust:** Rust is genuinely the strongest on the one thing Go is weak at
(deterministic secret handling, no GC). But the contributor pool, ecosystem libraries
(`hashicorp/raft`, go-plugin, cloud SDKs), and time-to-MVP all favor Go decisively for a
project that reuses the Go secrets-management ecosystem and targets wire-compatibility with
Vault. HashiCorp itself lives with Go's memory caveat via mlock and short secret lifetimes;
we take the same approach.

**Escape hatch:** the crypto core sits behind an interface so a Rust/C++ module could be
swapped in if an extreme threat model ever becomes a first-order requirement.

## D-002 — MVP scope: core plus signature capabilities

**Status:** Accepted · 2026-07-18

**Decision:** lean core **plus** Transit and one dynamic DB engine (MariaDB reference; see D-006).

**Why not lean-core-only:** Transit (encryption-as-a-service) and dynamic secrets are the
two capabilities that most distinguish a secrets manager from a simple encrypted key-value
store. Including them in the MVP demonstrates the full model — including the dynamic-secret
lease lifecycle — end-to-end. Both are relatively self-contained.

**Why not full Community parity as MVP:** Raft HA + the full engine/auth matrix is months
of work; it would delay any shippable proof of the architecture. Deferred to the post-MVP
extensions (see `docs/ROADMAP.md`).

## D-003 — Compatibility: API-compatible with HashiCorp Vault

**Status:** Accepted · 2026-07-18

**Decision:** match Vault's REST paths/semantics per-subsystem.

**Why:** wire-compatibility lets us reuse Vault's mature client ecosystem — existing client
libraries, SDKs, and Terraform providers work by changing only the address — instead of
building and maintaining our own tooling. This is compatibility at the API/wire level per
subsystem, **not** feature-complete parity with Vault (see `docs/POSITIONING.md`). The cost
is some design freedom, since we inherit certain Vault API conventions; the trade is worth
it for the tooling reuse. Compatibility is verified per subsystem in CI using real Vault
client libraries.

## D-004 — Scope: a small complete core, not Vault parity

**Status:** Accepted · 2026-07-18

**Decision:** ship a finished, polished, tested single-node core (barrier + Shamir
seal/unseal, KV v2, Transit, dynamic MariaDB, token auth, ACL policies, audit) and
treat breadth (Raft HA, the full auth/engine matrix, enterprise features) as optional,
uncommitted extensions.

**Why:** the value is in the *hard, complete* parts done well — applied crypto, a clean
seal state machine, the dynamic-secret lease lifecycle. A small system that is finished,
tested, and documented is more useful and more maintainable than a large half-finished
clone. See `docs/ROADMAP.md`.

## D-005 — Build our own vs. use OpenBao

**Status:** Accepted · 2026-07-18

**Decision:** build uBix Vault rather than adopt OpenBao — a lightweight, from-scratch,
uBixCore-native implementation with full control over the design. See
`docs/POSITIONING.md` for the prior-art acknowledgment and rationale.

## D-006 — Dynamic DB engine: plugin interface, MariaDB reference

**Status:** Accepted · 2026-07-18

**Decision:** implement the dynamic database engine against a small `DatabasePlugin`
interface and ship **MariaDB** as the MVP reference plugin. Postgres/MySQL/etc. are
follow-on plugins.

**Why:** the lease lifecycle (issue → track TTL → auto-revoke) is database-agnostic; only
the driver and the credential SQL differ between databases. Modeling this as a plugin
(as Vault does) means "which database" is a configuration choice, not a code change, and
each additional backend is a small, well-bounded effort. MariaDB is the reference because
it is the target for uBixCore. This is the Open/Closed and Interface-Segregation principles
applied concretely — see D-007.

## D-007 — Engineering standards: SOLID + industry norms as hard requirements

**Status:** Accepted · 2026-07-18

**Decision:** adopt SOLID (expressed through Go's interface idioms), plus security
engineering norms (default-deny, fail-closed, no hand-rolled crypto, OWASP ASVS as review
checklist), idiomatic-Go tooling (lint/vet/gofmt, `govulncheck`), table-driven tests with
high coverage on the crypto/seal core, OpenAPI-documented API, Semantic Versioning, and
Conventional Commits — as *hard* standards enforced in review and CI, not aspirations.

**Why:** for a security-critical system the discipline *is* the product. Defining the core
interfaces first (`StorageBackend`, `Barrier`, `Seal`, `AuthMethod`, `SecretsEngine`,
`DatabasePlugin`, `AuditDevice`) is what makes every later feature additive rather than a
rewrite, and it is the structural expression of Open/Closed + Dependency Inversion. Full
detail in `docs/DESIGN.md` §7.

## D-008 — Secret delivery to pods: direct API first, operator only if needed

**Status:** Accepted · 2026-07-18

**Decision:** the primary way workloads get secrets is to **call the vault API directly**
(authenticated via the Kubernetes auth method) and hold secrets in memory. An operator that
syncs secrets into native Kubernetes `Secret` objects — and environment-variable injection
in general — is treated as an *optional* extension, built only for apps that cannot be
modified to call the API.

**Why:** the direct-API pattern is both simpler (no operator, sidecar, or injection layer)
and more secure (secrets never touch disk or etcd, never appear in env vars, and can be
re-fetched when they rotate). Environment-variable injection is the weakest option on both
axes: env vars leak readily (child processes, `/proc`, crash dumps, logs), cannot rotate on
a running pod, and to produce them you must sync secrets into base64-only K8s `Secret`
objects in etcd (requiring etcd encryption-at-rest + tight RBAC to be even reasonably safe).
Since uBixCore's own workloads can call the API, the operator/env-var machinery solves a
problem we may not have — so it is deferred until a real unmodifiable-app case appears.
This avoids over-engineering the delivery path. See `docs/DESIGN.md` §4.1.

## D-009 — Implement Shamir Secret Sharing in-house (a narrow carve-out from "no hand-rolled crypto")

**Status:** Accepted · 2026-07-18

**Decision:** implement Shamir's Secret Sharing over GF(2^8) in-house (`internal/shamir`)
rather than adding a third-party dependency, as a deliberate and narrow exception to the
"no hand-rolled cryptography" standard (D-007 / DESIGN §7.2).

**Why:** Shamir is an information-theoretic **secret-sharing scheme, not a cipher**. The
actual cryptographic primitives — AES, GCM, hashing, the CSPRNG — remain standard-library
only; this exception does not extend to them. Implementing Shamir ourselves keeps the
project dependency-free (no supply-chain surface for a security-critical component) and is
a well-understood, ~200-line construction.

**Safeguards that make this acceptable** (without them, we would use a vetted library):
- GF(2^8) arithmetic is **constant-time** with respect to its byte operands — no
  data-dependent branches and no table lookups — to avoid timing side channels.
- Multiplication is validated against the **FIPS-197 (AES) field test vectors**, and the
  inverse against a full `a * a⁻¹ == 1` sweep of the field.
- **Property tests** cover round-trip, every threshold subset recovering, and
  fewer-than-threshold shares failing to recover.
- Randomness (coefficients and share x-coordinates) comes from `crypto/rand`.

**Scope of the carve-out:** this applies to Shamir only. Any future need for a
cryptographic primitive uses the standard library or a vetted library — we do not
generalize this into a license to roll our own crypto.
