# uBix Vault — Roadmap

> **Status:** Active · Last updated 2026-07-19

The project's deliverable is a **single-node secrets manager with a small, complete,
deeply-implemented core** — not feature parity with HashiCorp Vault. The goal is a
finished, polished, tested system that gets the hard parts of a real secrets manager
(encryption barrier, seal/unseal, dynamic secret lifecycle) right end-to-end.

Everything below the core is an **optional extension**, recorded for context and to show
the shape of the full problem space — explicitly *not* committed scope.

---

## The project — v1.0 core

Goal: an initialize → unseal → authenticate → use → audit flow that works end-to-end and
includes the two signature capabilities of a real secrets manager (encryption-as-a-service
and dynamic secrets). Every item here ships **finished, tested, and documented**.

- [x] Project scaffolding: Go module, CLI/server split, config loading, TLS listener.
- [x] **Storage backend interface** + file backend + in-memory (test) backend.
- [x] **Barrier**: AES-256-GCM encryption at rest, barrier key hierarchy.
- [x] **Seal / unseal**: Shamir k-of-n, init, unseal, seal status.
- [x] **Token auth** + root token bootstrap + child token creation.
- [~] **Lease manager**: dynamic-secret leases with TTLs, revoke, and an expiry sweep. *(General renew / cascading revocation across all secret types is a post-MVP refinement.)*
- [x] **Policy (ACL) engine**: JSON policies, default-deny, capability checks. *(HCL parity is a follow-up.)*
- [x] **KV v2** secrets engine (versioned static secrets).
- [x] **Transit** secrets engine (encrypt/decrypt; key never leaves). *(sign/HMAC endpoints are a follow-up.)*
- [x] **`DatabasePlugin` interface** + **Database dynamic** engine — **MariaDB** reference plugin, short-lived credentials, auto-revoke (PostgreSQL/MySQL as follow-on plugins).
- [x] **Audit device**: file backend, HMAC'd sensitive fields, fail-closed.
- [x] **HTTP API** (Vault-path-compatible for implemented subsystems) + **`ubixvault server`**. *(A thin `operator` CLI over the API is a follow-up.)*

**Quality bar (part of done, not optional polish):**
- [x] Real test coverage, especially the crypto core and the seal/unseal state machine.
- [x] CI (build, test, lint, govulncheck, MariaDB integration) green on every commit.
- [x] Quickstart (README) + the design docs in `docs/`. *(A generated API reference is a follow-up.)*
- [ ] A short screencast demonstrating the end-to-end flow.

**Definition of done:** see `docs/DESIGN.md` §6. The MVP core is complete; remaining
unchecked/partial items are refinements, not blockers.

---

## Possible extensions (NOT committed scope)

Recorded to show the full problem space. These are undertaken only after the v1.0 core is
complete, and only where they add value — never at the expense of finishing the core.

**Likely next step — Kubernetes integration**

The natural first extension for a uBixCore deployment. Note the deliberately minimal shape:

- **Kubernetes auth method** (server side) — pods authenticate using their ServiceAccount
  token; the vault validates it and issues a policy-scoped token. *This alone is enough:*
  a pod's app can then call the vault API directly at startup and read its secrets into
  memory — no injection layer, no secrets on disk or in etcd. This is the recommended
  pattern for apps you control (i.e. uBixCore's own workloads).
- **Web UI** — a browser interface to manage secrets/policies/tokens. It is just another
  client of the HTTP API, so it comes *after* the API is stable, not before.
- **uBix Vault Operator** *(only if needed)* — syncs secrets into native Kubernetes
  `Secret` objects for `envFrom` injection. Build this **only** for third-party apps you
  cannot modify to call the API. It trades security for convenience (secrets land in etcd,
  base64-only; requires etcd encryption-at-rest + tight RBAC) and cannot deliver rotating
  dynamic secrets to env vars. Prefer the direct-API pattern above wherever possible.
  See `docs/DECISIONS.md` (D-008).

**Toward Community-level breadth**
- Integrated Storage (Raft) — HA cluster, no external dependency.
- Auto-unseal via cloud KMS (AWS/GCP/Azure) behind the seal interface.
- More auth methods: AppRole, JWT/OIDC, TLS cert, userpass, LDAP.
- PKI secrets engine (certificate authority, short-lived TLS certs).
- Cloud dynamic secrets (AWS/GCP/Azure IAM); more DB plugins (PostgreSQL, MySQL, Mongo, MSSQL).
- Identity (entities + groups), response wrapping, cubbyhole, SSH, TOTP.
- Metrics (Prometheus), syslog/socket audit devices.

**Advanced (multi-tenancy, HA replication, and approval workflows)**
- Namespaces — in-vault multi-tenancy (administratively isolated policy/mount/auth trees
  within a single instance). Distinct from Kubernetes namespaces, and **not** required to
  share a secret across apps in different Kubernetes namespaces — that is handled by ACL
  policies plus the Kubernetes auth method (see above).
- Replication (multi-DC HA/DR), control groups (M-of-N approval).
- Policy-as-code / ABAC (OPA/Rego), login-enforced MFA, seal-wrap.

**Hard compliance**
- HSM/PKCS#11 auto-unseal & seal-wrap, FIPS 140-3 validated crypto build, KMIP engine,
  transform/tokenization/FPE.

---

## Sequencing notes

- Interfaces first (storage, seal, auth, engine, audit) so extensions are additive, never rewrites.
- The barrier + Shamir seal/unseal is the highest-value, most-differentiating work — build it first and make it excellent.
- API paths mirror HashiCorp Vault's per subsystem; validating against real Vault client libraries in CI is a follow-up.
