# Changelog

All notable changes to uBix Vault are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **MySQL/MariaDB storage backend** — run the vault against a database instead of
  a local disk with `-storage mysql` (`-storage-mysql-dsn` or
  `$UBIXVAULT_STORAGE_DSN`); `file` remains the default. The node becomes
  replaceable: it can die and restart against the same durable, replicated
  database. The vault creates its tables automatically. Values stay barrier
  ciphertext — the database never sees plaintext, so a database or DSN compromise
  yields ciphertext, not secrets. Single active writer (durability, not multi-writer
  HA). Helm: `storage.type=mysql` with the DSN supplied via a Secret
  (`storage.mysql.dsnSecret`), never a chart value; chart bumped to 0.1.10. No new
  dependency (reuses the MySQL driver). See ADR D-014 and
  `docs/design/sql-storage-backend.md`.

- **Rekey** — rotate the Shamir unseal shares without downtime or data
  re-encryption. `POST /v1/sys/rekey/init` starts an attempt (new share
  count/threshold), `POST /v1/sys/rekey/update` feeds a quorum of the *current*
  shares, and on completion a fresh set of unseal shares is returned once; the
  old shares stop working. Internally the master key is regenerated and the
  barrier keyring re-wrapped under it — the barrier key and all data are
  untouched, so the vault keeps serving throughout. Shamir-unseal vaults only.
  Driveable from the CLI: `ubixvault operator rekey init | update | status | cancel`.
- **Scheduled backups (Helm chart)** — an opt-in `backup.enabled` CronJob runs
  `operator snapshot save` against the running vault on a schedule and writes the
  snapshot to a separate PVC (put it on network-backed storage for off-node
  durability), using a least-privilege `sys/snapshot` token. Chart bumped to
  0.1.9; the README documents the token/policy setup and the restore procedure.

## [0.2.0-beta.8] — 2026-08-06

Eighth beta: Transit grows into full crypto-as-a-service, plus response wrapping.

### Added

- **Response wrapping** — `POST /v1/sys/wrapping/wrap` stores a JSON payload
  behind a fresh single-use token (TTL from the `X-Vault-Wrap-TTL` header,
  default 5m, max 24h), and `POST /v1/sys/wrapping/unwrap` returns it exactly
  once before destroying the token. Wrapped payloads are barrier-encrypted and
  indexed by the token's hash. This is the secure-introduction pattern: hand a
  consumer a short-lived token instead of the secret itself.

- **Transit rewrap & data keys** — `POST /v1/transit/rewrap/{name}` re-encrypts a
  ciphertext under a key's latest version without exposing the plaintext, so old
  key versions can be retired after a rotation. `POST /v1/transit/datakey/{plaintext|wrapped}/{name}`
  generates a random 128/256/512-bit data key wrapped under the named key — for
  envelope encryption where the caller encrypts bulk data locally and stores only
  the wrapped key.
- **Transit HMAC** — `POST /v1/transit/hmac/{name}` computes an HMAC over the
  input using the key's latest version (sha2-256/384/512; default sha2-256), and
  `POST /v1/transit/verify/{name}` checks one in constant time. The MAC is
  version-tagged so it keeps verifying across key rotations.
- **Transit signing keys** — Transit keys can now be asymmetric signing keys
  (`ecdsa-p256/384/521`, `ed25519`), selected with `{"type":...}` at creation.
  `POST /v1/transit/sign/{name}` signs input (ECDSA hashes with `sha2-256/384/512`;
  Ed25519 signs directly) and `POST /v1/transit/verify/{name}` checks a
  `signature` (or an `hmac`). A key's PEM public keys are returned per version so
  signatures can be verified without the vault. Symmetric-only operations
  (encrypt/decrypt/hmac) reject signing keys and vice versa.

[0.2.0-beta.8]: https://github.com/cwolsen7905/ubixvault/releases/tag/v0.2.0-beta.8

## [0.2.0-beta.7] — 2026-07-30

Seventh beta: JWT/OIDC login, completing the auth-method set.

### Added

- **JWT/OIDC auth method** — exchange a signed JWT for a token
  (`POST /v1/auth/jwt/login`). Signatures are verified with the standard library
  (RS256/384/512 and ES256/384/512) against static PEM public keys and/or a
  fetched JWKS — no new dependency. Configure validation under
  `/v1/auth/jwt/config` (JWKS URL, validation public keys, bound issuer) and
  define roles under `/v1/auth/jwt/role/{name}` that bind audiences and claims to
  a policy set and token TTL. Login validates `exp`/`nbf`, the bound issuer,
  audiences, and per-claim bindings before issuing the token.

[0.2.0-beta.7]: https://github.com/cwolsen7905/ubixvault/releases/tag/v0.2.0-beta.7

## [0.2.0-beta.6] — 2026-07-30

Sixth beta: human login (userpass) and certificate management from the console.

### Added

- **userpass auth method** — human login with a username and password
  (`POST /v1/auth/userpass/login/{username}`) returning a token with the user's
  policies. Passwords are stored only as a PBKDF2-HMAC-SHA256 hash (600k
  iterations, per-user salt) via the Go 1.24 stdlib `crypto/pbkdf2` — no new
  dependency; login compares in constant time and equalizes timing for unknown
  users. User management under `/v1/auth/userpass/users/*`.
- **PKI in the web console** — the `/ui/` console gains a PKI panel: generate or
  view the root CA, manage roles (allowed domains, subdomains, max TTL, key
  type), and issue certificates. Issued cert/key/CA render as copy-able PEM
  blocks, with a "shown once" warning on the private key.

[0.2.0-beta.6]: https://github.com/cwolsen7905/ubixvault/releases/tag/v0.2.0-beta.6

## [0.2.0-beta.5] — 2026-07-29

Fifth beta: an internal certificate authority (PKI), self-hosted transit
auto-unseal, and security hardening.

### Security

- Internal security-review pass. **Hardened:** `500` responses now return a
  generic message and log the detail server-side, instead of echoing internal
  error strings to clients. Documented that seal secrets should be passed by
  environment variable rather than a CLI flag (visible in `ps`). Verified no ACL
  bypass via path traversal, no weak randomness, path-bound AEAD with random
  nonces, constant-time recovery-key checks, hash-indexed tokens, and
  fail-closed audit.

### Added

- **PKI secrets engine** — an internal certificate authority: generate a
  self-signed root CA (its key never leaves the vault), define roles that
  constrain issuance (allowed domains, subdomains, max TTL, key type), and issue
  short-lived leaf certificates. Vault-compatible paths under `/v1/pki/*`
  (`root/generate/internal`, `roles/{name}`, `issue/{role}`, `ca`). Built on
  `crypto/x509`; no new dependency. (Intermediate CAs and CRL are future work.)
- **Transit auto-unseal seal** — unseal by wrapping the master key via another
  Vault-compatible Transit engine (`-seal-transit-address/-key/-token`), so no
  KEK lives on this host. Introduces a `Seal` interface (`internal/seal`) with
  static-KEK and Transit implementations (ADR D-013); recovery keys work in both
  modes. Chart: `sealTransit.*` (mutually exclusive with `autoUnseal`). No new
  dependency — the Transit paths are Vault-compatible.

[0.2.0-beta.5]: https://github.com/cwolsen7905/ubixvault/releases/tag/v0.2.0-beta.5

## [0.2.0-beta.4] — 2026-07-29

Fourth beta: machine authentication and API hardening.

### Added

- **AppRole auth method** — machine clients present a stable `role_id` and a
  `secret_id` (password-equivalent, stored only as a hash) to
  `POST /v1/auth/approle/login` and receive a token carrying the role's policies.
  Roles set policies, token TTL, and an optional secret-id TTL; role/secret-id
  management is authenticated, login is not. Vault-compatible paths under
  `/v1/auth/approle/*`.
- **Rate limiting** — optional per-client token-bucket throttling of the API
  (`-rate-limit`, `-rate-limit-burst`, `-rate-limit-trust-forwarded`), in-house
  with no new dependency. Keyed by client IP (or `X-Forwarded-For` behind a
  trusted proxy); health, metrics, and the console are exempt; over-limit
  requests get `429` with `Retry-After`. Exposed in the Helm chart via
  `rateLimit.*`.

[0.2.0-beta.4]: https://github.com/cwolsen7905/ubixvault/releases/tag/v0.2.0-beta.4

## [0.2.0-beta.3] — 2026-07-25

Third beta: the web console gains full read/write management.

### Added

- **Web console — write operations & management** — the `/ui/` console now goes
  well beyond read-only:
  - **KV v2:** create/edit secrets (key/value editor → new version), version
    **history**, read a specific version, and per-version soft-delete / undelete
    / **destroy** (with an inline confirm).
  - **ACL policies:** list, read, create/edit (JSON or HCL), and delete.
  - **Tokens:** mint a child token scoped to policies with an optional TTL.

  Still token-in-header (no cookies/CSRF), strict-CSP, secret values rendered via
  `textContent`, and every write is an audited `/v1` call requiring the token's
  capabilities.

[0.2.0-beta.3]: https://github.com/cwolsen7905/ubixvault/releases/tag/v0.2.0-beta.3

## [0.2.0-beta.2] — 2026-07-25

Second beta: Kubernetes deployment (Helm chart, image publishing, ingress,
Prometheus metrics, a read-only web console) plus an auto-unseal recovery-key
fix.

### Added

- **Prometheus metrics** — `GET /v1/sys/metrics` exposes operational series
  (build info, seal state, uptime, HTTP request counts) in Prometheus text
  format, via an in-house exporter (no new dependency, ADR D-012). The Helm
  chart can create a `ServiceMonitor` (`metrics.serviceMonitor.enabled`).
- **Auto-unseal recovery keys** — auto-unseal `init` now generates *k-of-n*
  recovery keys (default 5/3) and returns them once. The KEK still unseals the
  vault automatically; the recovery keys authorize **root-token regeneration**,
  closing a lockout gap where a lost root token was unrecoverable under
  auto-unseal. `POST /v1/sys/generate-root/*` accepts recovery keys in
  auto-unseal mode. (Vaults initialized before this have no recovery keys.)
- **Helm chart** (`deploy/charts/ubixvault`), multi-arch image publishing to
  ghcr.io, an optional chart Ingress, and TLS options for the operator CLI
  (`-ca-cert`, `-tls-skip-verify`).
- **Web console (read-only)** — an embedded, self-contained admin console at
  `/ui/` (with `/` redirecting to it). It shows the vault's seal state and
  reads/lists KV v2 secrets with a token the operator supplies in the browser.
  Vanilla HTML/JS/CSS served from the binary under a strict CSP (no external
  assets, no new dependency).

[0.2.0-beta.2]: https://github.com/cwolsen7905/ubixvault/releases/tag/v0.2.0-beta.2

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
