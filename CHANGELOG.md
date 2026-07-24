# Changelog

All notable changes to uBix Vault are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/).

## [0.2.0-beta.1] — 2026-07-23

Beta: hardening and completeness on top of the MVP. uBix Vault is now usable for
real workloads (see `docs/DEPLOYMENT.md`), though it has not had an external
security review.

### Added

- **Token TTLs, expiry, and renewal** — tokens now expire (default TTL; explicit
  TTL on create; root non-expiring). The auth middleware rejects expired tokens;
  `POST /v1/auth/token/renew-self` extends a token.
- **Auto-unseal** — protect the master key with a 32-byte KEK instead of Shamir
  shares, so a restarted server unseals itself (`-auto-unseal-key`).
- **Health/readiness endpoint** — `GET /v1/sys/health`, with a readiness status
  code (200/503/501) for load balancers and probes.
- **Backup / restore** — consistent, encrypted snapshots via
  `POST /v1/sys/snapshot` and `operator snapshot save`/`restore`.
- **Root-token regeneration** — recover a new root token from a quorum of unseal
  shares (`/v1/sys/generate-root/*`).
- **Lease renewal, lookup, and cascading revocation** — dynamic-database leases
  can be renewed/looked up, and revoking a token (`revoke-self`) revokes the
  credentials it created.
- **Kubernetes auth method** — pods exchange a ServiceAccount token for a
  policy-scoped token (`/v1/auth/kubernetes/*`), validated via the TokenReview API.
- **HCL policy documents** — accept HashiCorp-style HCL policies in addition to
  JSON (auto-detected), via an in-house parser (no new dependency).
- **Deployment guide** (`docs/DEPLOYMENT.md`).

### Changed

- **TLS hardening** — without TLS the server binds to loopback only; serving
  plaintext HTTP on a non-loopback address is refused unless `-dev-no-tls` is set.
- Seal status now reports the seal `type` (`shamir` or `auto`).

### Known limitations

- Not production-hardened; no external security review.
- Auto-unseal takes the KEK directly (a pluggable cloud-KMS/HSM seal is future
  work); root regeneration is Shamir-only.
- The in-house HCL parser is a policy-grammar subset, not full HCL.
- Cascading revocation and lease renewal cover dynamic-database leases.

[0.2.0-beta.1]: https://github.com/cwolsen7905/ubixvault/releases/tag/v0.2.0-beta.1

## [0.1.0] — 2026-07-19

First release: the complete MVP core (see `docs/DESIGN.md` §6). uBix Vault can be
initialized, unsealed, and used to store and generate secrets over an
authenticated, authorized, audited HTTP API.

> **Status:** working MVP, not yet production-hardened. No external security
> review or operational hardening yet.

### Added

- **Storage** — a durable key/value backend interface with file and in-memory
  implementations, path-traversal-safe and covered by a shared conformance suite.
- **Barrier** — AES-256-GCM encryption at rest; the storage path is bound into
  the ciphertext (AEAD additional data) so blobs cannot be relocated between
  paths.
- **Shamir seal/unseal** — in-house Shamir Secret Sharing over GF(2⁸) with
  constant-time field arithmetic, validated against FIPS-197 vectors. The master
  key is split into k-of-n unseal shares.
- **Core** — initialization and the seal/unseal lifecycle, issuing the initial
  root token at init.
- **Token authentication** — tokens indexed by a hash of their value (never
  stored in the clear); root and scoped tokens.
- **ACL policies** — JSON policy documents, default-deny with deny-override,
  exact and prefix path matching.
- **KV v2 secrets engine** — versioned secrets with soft-delete, undelete,
  destroy, and max-versions aging.
- **Transit secrets engine** — encryption-as-a-service; versioned keys that never
  leave the vault and rotate without breaking existing ciphertext.
- **Dynamic database secrets engine** — short-lived credentials via a
  `DatabasePlugin` interface, with a MariaDB reference plugin; leases are revoked
  on expiry by a background sweeper.
- **Audit logging** — a fail-closed file device recording who accessed what,
  with the client token HMAC'd (never logged in the clear).
- **HTTP API** — Vault-path-compatible endpoints for the above, behind an
  authentication + ACL middleware.
- **Server & operator CLI** — `ubixvault server` runs the API (with optional TLS
  and audit logging); `ubixvault operator init/unseal/seal-status/seal` drives
  the lifecycle over the API.
- **Engineering** — CI running build, race tests, `golangci-lint` (incl. gosec),
  `govulncheck`, and a MariaDB integration job; design docs, decision records
  (ADRs), and a threat model in `docs/`.

### Known limitations

- Not production-hardened; no external security review.
- The lease manager covers dynamic-secret leases (TTL + revoke + expiry sweep);
  general renew and cross-type cascading revocation are future work.
- Policies are JSON only (HCL parity pending); Transit sign/HMAC and asymmetric
  keys are not yet implemented.
- The in-memory unseal progress and the audit device's HMAC salt are
  per-process; cross-restart correlation of audit entries is future work.

[0.1.0]: https://github.com/cwolsen7905/ubixvault/releases/tag/v0.1.0
