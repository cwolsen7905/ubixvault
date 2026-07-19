# uBix Vault — Roadmap

> **Status:** Active · Last updated 2026-07-18

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

- [ ] Project scaffolding: Go module, CLI/server split, config loading, TLS listener.
- [ ] **Storage backend interface** + file backend + in-memory (test) backend.
- [ ] **Barrier**: AES-256-GCM encryption at rest, barrier key hierarchy.
- [ ] **Seal / unseal**: Shamir k-of-n, `operator init`, `operator unseal`, seal status.
- [ ] **Token auth** + root token bootstrap + child token creation.
- [ ] **Lease manager**: TTLs, renew, revoke, cascading revocation.
- [ ] **Policy (ACL) engine**: HCL/JSON policies, default-deny, capability checks.
- [ ] **KV v2** secrets engine (versioned static secrets).
- [ ] **Transit** secrets engine (encrypt/decrypt/sign/HMAC; key never leaves).
- [ ] **`DatabasePlugin` interface** + **Database dynamic** engine — **MariaDB** reference plugin, short-lived credentials, auto-revoke (PostgreSQL/MySQL as follow-on plugins).
- [ ] **Audit device**: file backend, HMAC'd sensitive fields, fail-closed.
- [ ] **HTTP API** (Vault-path-compatible for implemented subsystems) + **`ubixvault` CLI**.

**Quality bar (part of done, not optional polish):**
- [ ] Real test coverage, especially the crypto core and the seal/unseal state machine.
- [ ] CI (build, test, lint) green on every commit.
- [ ] Quickstart + API reference for shipped endpoints + the design docs in `docs/`.
- [ ] A short screencast demonstrating the end-to-end flow.

**Definition of done:** see `docs/DESIGN.md` §6.

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
- API compatibility is validated **per subsystem** in CI using real Vault client libraries.
