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

## D-010 — First third-party dependency: the MariaDB/MySQL driver

**Status:** Accepted · 2026-07-19

**Decision:** add `github.com/go-sql-driver/mysql` (the project's first
third-party dependency) for the MariaDB reference plugin, rather than
reimplementing the MySQL wire protocol.

**Why:** the dynamic database engine must speak a database's native protocol to
create and drop users; a wire-protocol client is exactly the kind of large,
well-solved component that belongs in a vetted library. `go-sql-driver/mysql` is
the de-facto standard, pure-Go, and widely audited. This does not weaken the
"no hand-rolled cryptography" rule (D-007) — a database driver is not crypto —
nor the minimal-dependency posture: dependencies are added when reimplementing
would be wasteful or risky, and each is scanned by `govulncheck` in CI.

**Isolation:** the driver is imported only by `internal/database/mariadb`, so
packages that do not talk to MariaDB do not pull it in. Integration tests that
require a real database are gated behind the `integration` build tag and run in a
dedicated CI job against a MariaDB service container.

## D-011 — HCL policy support via an in-house parser (no new dependency)

**Status:** Accepted · 2026-07-23

**Decision:** accept HashiCorp-style **HCL** policy documents (in addition to JSON)
via a small, purpose-built parser in `internal/policy`, rather than adding the
`hashicorp/hcl` dependency.

**Why:** the policy grammar is a tiny, well-defined subset — `path "<pattern>" {
capabilities = [...] }` blocks with comments — so a ~200-line lexer/parser covers
it cleanly and keeps the project dependency-light (consistent with the
minimal-dependency posture; the only third-party dependency remains the MySQL
driver, D-010). `ParseDocument` auto-detects the format (leading `{` → JSON, else
HCL). This is parsing, not cryptography, so it does not touch the
"no hand-rolled crypto" rule.

**Trade-off / follow-up:** the in-house parser is **not full HCL** — no heredocs,
interpolation, nested blocks, or number/bool values beyond the policy grammar.
For complete compatibility with arbitrary Vault policy files, switch to
`github.com/hashicorp/hcl` later. That library is **MPL 2.0**, which as a
dependency does **not** affect this project's BSD-3-Clause license (MPL is
file-level copyleft governing only its own files); it would be recorded as its
own ADR when added.

## D-012 — Prometheus metrics via an in-house text exporter (no client library)

**Status:** Accepted · 2026-07-24

**Decision:** expose Prometheus metrics at `GET /v1/sys/metrics` by rendering the
text exposition format directly from a small `internal/metrics` package, rather
than depending on `prometheus/client_golang`.

**Why:** the vault exposes only a handful of series (build info, seal state,
uptime, HTTP request counts by status code). The Prometheus text format for
these is trivial to emit correctly, and `client_golang` pulls in a non-trivial
transitive dependency graph. A small, auditable dependency graph is itself a
security feature here, so — consistent with D-009 (in-house Shamir) and D-011
(in-house HCL) — a ~100-line exporter is preferred. This is serialization, not
cryptography, so it does not touch the "no hand-rolled crypto" rule.

**Shape:** counters incremented inline; gauges gathered from a callback at scrape
time (so seal state and uptime are always current). The endpoint is
unauthenticated and exposes only operational data (no secret names or values),
like `/v1/sys/health`; restrict it at the network layer as usual for `/metrics`.

**Trade-off / follow-up:** no histograms/summaries (request-duration buckets) and
no Go runtime/process collectors that `client_golang` provides for free. If those
are wanted later, adding `client_golang` would be its own ADR; it is Apache-2.0,
which as a dependency does not affect this project's BSD-3-Clause license.

## D-013 — A seal interface, with a self-hosted Transit auto-unseal seal

**Status:** Accepted · 2026-07-29

**Decision:** abstract auto-unseal behind a small `Seal` interface
(`internal/seal`) with two implementations — a static-KEK seal (the existing
`-auto-unseal-key`) and a **Transit** seal that wraps the master key via a remote
Vault-compatible Transit engine — rather than only supporting a locally-supplied
KEK. The core stores the opaque wrapped key and calls `Wrap`/`Unwrap`; the seal
type (`auto`, `transit`) is recorded in the seal config, and both share the
recovery-key / root-regeneration path.

**Why:** the known-limitations list called out that "the KEK is supplied
directly." The Transit seal removes that: the wrapping key lives in another vault
and never reaches this host, which only holds a token authorized to
encrypt/decrypt with it. It is **self-hosted and dependency-free** — the Transit
paths are Vault-compatible, so the seal vault can be another uBix Vault or a
HashiCorp Vault — consistent with the minimal-dependency posture (no cloud-KMS
SDK). The interface also leaves a clean seam for a future cloud-KMS/HSM seal.

**Trade-off / follow-up:** the Transit seal introduces a runtime dependency on
the seal vault at startup (unreachable → stays sealed, fail-safe). A pluggable
cloud-KMS/HSM seal (AWS/GCP/Azure) would be its own implementation behind the
same interface, added only if wanted, and would be its own ADR (with its
dependency recorded there).

---

## D-014 — A SQL (MySQL/MariaDB) storage backend for durable, replaceable-node storage

**Status:** Accepted · 2026-08-06

**Decision:** add a `storage.Backend` implementation over MySQL/MariaDB (reusing
the existing `go-sql-driver/mysql` dependency from D-010 — no new dependency),
selectable with a `-storage mysql` server flag while `file` stays the default.
The database stores the vault's key/value state in a single `VARBINARY`-keyed
table; the barrier still encrypts every value first, so the database holds only
ciphertext. Full design in [`docs/design/sql-storage-backend.md`](design/sql-storage-backend.md).

**Why:** single-node file storage is the project's production ceiling — durability
rests on one disk and the node cannot be replaced. A SQL backend turns that into a
**replaceable node over managed, replicated storage**: the vault process can
restart on another node against the same durable database, whose own HA handles
durability. It is the pragmatic durability step *before* integrated storage
(Raft), which is months of far harder work; a SQL backend de-risks and may
obviate it for single-org use (`docs/ROADMAP.md` Tier 1). Reusing the sole
existing dependency preserves the minimal-dependency, "readable in an afternoon"
posture (D-009/D-011/D-012); the trust model is unchanged because the database,
like the file backend, never sees plaintext (DESIGN §3.2). `storage.Backend`
needs no change — it already anticipates substitutable backends (D-007) — so the
new backend is validated by the *same* conformance suite every backend passes.

**Trade-off / follow-up:** it adds a runtime dependency on the database
(unreachable at startup → fail fast) and a credential to manage (the DSN, kept in
a Secret). Critically it is **not multi-writer HA**: exactly one active vault
process per database, since barrier/lease/unseal state is in-memory —
`replicaCount` stays 1, and the win is storage surviving node loss, not multiple
serving nodes. Leader election / Raft coordination for true HA is a later,
separate ADR. Postgres and other engines are viable behind the same interface
later; MySQL is first only because it reuses the existing driver.

---

## D-015 — Cloud-KMS / HSM auto-unseal via an external command, not native SDKs

**Status:** Accepted · 2026-08-26

**Decision:** reach cloud KMS (AWS/GCP/Azure) and hardware HSMs for auto-unseal
through a generic **external-command (exec) seal** — a new `Seal` implementation
(`type: external`) that pipes the master key to an operator-supplied command
(`<cmd> wrap` reads plaintext on stdin → wrapped on stdout; `<cmd> unwrap` the
reverse) — rather than importing cloud provider SDKs. The provider-specific logic
and credentials live in that command; uBix Vault adds **no new dependency**. Full
design in [`docs/design/kms-hsm-seal.md`](design/kms-hsm-seal.md).

**Why:** the last production seal gap is "the KEK is supplied directly"; the
Transit seal (D-013) already closes it when you run a Vault-compatible transit
engine, but not for cloud-native KMS or a local HSM. Native SDK seals (as
HashiCorp Vault uses) would be the turnkey option but mean importing large,
per-provider dependency graphs into the security-critical seal path — directly
against the minimal-dependency posture (D-009/D-010/D-014). Hand-rolling each
provider's request signing over HTTP, or a CGo PKCS#11 binding (which also breaks
the static distroless build), are worse. Delegating to a small operator-supplied
command is the zero-dependency mechanism that covers **every** KMS/HSM at once,
maps directly onto the existing `Seal` interface (nothing above it changes), and
keeps provider code and credentials out of the vault. The master key (32 bytes)
is under every KMS's direct-encrypt limit, so no envelope indirection is needed.

**Trade-off / follow-up:** the master key transits the command's stdin/stdout —
bounded (in-memory pipe, a child in the same trust domain, no worse than
StaticKEK holding the KEK in-process, better than a KEK persisted on the host,
since the wrapping key lives in the KMS/HSM). The operator must supply and secure
the wrap command and its credentials, and provide it into the shell-less
distroless image (a mounted script/binary or an image variant). A missing/failing
command leaves the vault sealed (fail-safe). Native in-vault SDK seals remain a
possible later opt-in behind the same interface — their own ADR, their own
recorded dependency — only if the exec seal proves insufficient.

## D-016 — Identity (entities, aliases, groups) as barrier records with request-time policy resolution

**Status:** Accepted · 2026-09-02 (phases 1–3 — entities + aliases + entity policies, internal groups, external/IdP-asserted groups — shipped; identity templating to follow)

**Decision:** add an identity layer — *entities* (the canonical subject),
*aliases* (per-auth-method logins that resolve to an entity), and *groups*
(internal or externally-asserted collections of entities, with their own
policies) — as JSON records on the existing barrier under `identity/`. Tokens
gain an `EntityID`; `authorize()` unions the entity's and its groups' policies
with the token's own policies **on each request**, rather than snapshotting them
at login. Auth methods resolve `(mountType, loginName)` to an alias at login,
auto-creating an entity+alias on first sight (with an opt-out). Full design in
[`docs/design/identity-entities-groups.md`](design/identity-entities-groups.md).

**Why:** the six auth methods are self-contained — each login mints a token with
the role's static policies and no notion of who is behind it, so one subject's
several logins are unrelated, policy is duplicated across every role, and
IdP-asserted group membership is discarded. Identity is the single largest
Vault-Community parity gap (`docs/POSITIONING.md`). Resolving policy at request
time (not at login) is what makes a group or entity edit take effect immediately,
matching operator expectations; a per-request cache keyed by `EntityID` bounds
the cost. Identity only *adds* policies, never subtracts, so it cannot silently
narrow an existing grant. The whole thing is storage records plus a resolver over
the existing `policy` package — **no new dependency** (D-009/D-010/D-014).

**Trade-off / follow-up:** per-request entity/group lookups (mitigated by a
cache invalidated on writes); auto-created entities accumulate (listing + delete
+ opt-out suffice for the first cut, as in Vault); disabling an entity or
removing an alias blocks future logins but does not retroactively revoke live,
TTL-bounded tokens (documented, same model as Vault). Ships in phases —
entities+aliases, then internal groups, then external groups, then identity
templating in ACL paths (`{{identity.*}}`, its own note and ADR) — each a small
CI-green PR.

## D-017 — Identity templating: expand {{identity.*}} in ACL paths at evaluation time

**Status:** Accepted · 2026-09-02 (phase 4 of identity, D-016)

**Decision:** allow ACL policy rule paths to contain `{{identity.entity.id}}`,
`{{identity.entity.name}}`, and `{{identity.entity.metadata.<key>}}`
placeholders, expanded against the requesting token's entity at authorize time
before the ACL is evaluated. A placeholder that does not resolve drops that rule
(fail-closed). The policy engine gains a generic `Policy.Templated(resolve
func(key string)(string,bool)) *Policy` expander; `internal/api`'s `authorize()`
sources the entity's template values from the identity engine and runs each
loaded policy through it. Full design in
[`docs/design/identity-templating.md`](design/identity-templating.md).

**Why:** identity (D-016) gives every token a subject, but without templating a
"let each user reach their own subtree" policy must be written per user — the
toil identity was meant to remove. Templating lets one policy
(`secret/data/users/{{identity.entity.name}}/*`) serve everyone. Expanding at
evaluation time (not policy-write time) is required because the value is
per-request; a `resolve` callback keeps the policy package identity-agnostic and
unit-testable, with the identity engine supplying only a flat value map. Dropping
unresolved placeholders keeps a templated grant worthless to a token lacking the
identity value.

**Trade-off / follow-up:** template values are inserted literally, so a
metadata value containing `*` could widen a prefix match — metadata is
operator-set and entity writes are root/ACL-gated, so this is trusted input
(documented, not sanitized, matching Vault). `id`/`name` are safe by
construction. Alias- and group-scoped placeholders can be added later by growing
the value map; the expander does not change. No new dependency.

## D-018 — LDAP / Active Directory auth via go-ldap: the project's second dependency

**Status:** Accepted (option A) · 2026-09-02

**Decision:** add an LDAP/AD auth method built on **`github.com/go-ldap/ldap/v3`**,
the standard Go LDAP client — the project's **second** direct dependency. LDAP is
the last Vault-Community auth method uBix Vault lacked; Go has no stdlib LDAP
client and LDAP is ASN.1-BER over TLS, and a vetted library for a protocol-heavy,
security-sensitive login flow is exactly when a dependency earns its place (the
same reasoning that admitted the MySQL driver, D-010). The LDAP protocol handling
is confined to one thin adapter behind a `connector` seam; the method's own logic
(config, group→policy mapping, token issuance) is stdlib and unit-tested with a
fake connector. A user's LDAP groups feed identity external groups (D-016) as
well as an in-method group→policy map. The alternatives (hand-rolled BER, an
external-command bind helper, or OIDC-only) were rejected — see the analysis
below.

**Historical — the options considered:** whether to add an LDAP/AD auth method,
and if so how.
LDAP is the last Vault-Community auth method uBix Vault lacks, but Go's standard
library has no LDAP client and LDAP is ASN.1-BER over TLS, so there is no
stdlib path. The options (full analysis in
[`docs/design/ldap-auth.md`](design/ldap-auth.md)):

- **A —** add `github.com/go-ldap/ldap/v3` (the standard Go LDAP client): the
  project's second direct dependency, but a vetted library for a
  protocol-heavy, security-sensitive feature. LDAP groups feed identity external
  groups (D-016) directly.
- **B —** hand-roll a minimal BER/LDAP client (stdlib only): keeps the
  dependency count but puts hand-written ASN.1-BER in the auth path — the wrong
  risk; **not recommended**.
- **C —** external-command bind helper (like the KMS/HSM seal, D-015): credentials
  transit an exec per login; the seal trick does not fit a login flow; **not
  recommended**.
- **D —** don't add LDAP; document fronting LDAP with the existing OIDC support
  (Keycloak/Entra/Okta/Dex), leaving the box deliberately unchecked.

**Recommendation:** **A** if LDAP-without-OIDC is a target audience (a vetted
library is exactly when a dependency earns its place, as the MySQL driver did in
D-010); otherwise **D**. Explicitly not B or C. This is a product/philosophy call
about the "essentially no dependencies" posture — deferred to the maintainer.
This ADR moves to Accepted once that call is made.
