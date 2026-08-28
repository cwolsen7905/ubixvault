# uBix Vault — Security review scope & brief

> A brief for anyone assessing uBix Vault's security — a firm, an independent
> reviewer, or a funded-OSS audit program. It states what we most want examined,
> the model to work from, the specific questions we care about, and what we
> provide. An external review is the one remaining gate on the road to `1.0`
> (`docs/ROADMAP.md`); this brief is meant to make that review easy to scope and
> kick off.

## What uBix Vault is

A self-hosted, single-node secrets manager in Go (a HashiCorp Vault–style
system): an AES-256-GCM encryption barrier, in-house Shamir seal/unseal, KV v2,
Transit (crypto-as-a-service), dynamic database credentials, PKI, five auth
methods, ACL policies, and a fail-closed audit log, over a Vault-compatible HTTP
API. It is built on a **minimal-dependency** ethos — one third-party library (the
MySQL driver); all cryptography is Go standard-library primitives wrapped in
in-house logic. Full architecture in `docs/DESIGN.md`; decisions in
`docs/DECISIONS.md`.

**Status:** pre-1.0 beta, not production-hardened, **not previously reviewed**.
The engineering gates for 1.0 (durable storage, hardening, KMS/HSM seal) have
landed; this review is the remaining gate.

## Threat model

Work from `docs/DESIGN.md` §5 — assets, trust boundaries, in-scope adversary
positions, residual risks, and explicit out-of-scope. The load-bearing property
to validate throughout: **storage sees only ciphertext**; the master key never
reaches storage, and a compromised unsealed host is accepted as out of scope.

## Scope — the crown jewels (in priority order)

Focus effort here first; these are where a defect is catastrophic.

1. **Barrier** (`internal/barrier`) — AES-256-GCM at rest with the storage path
   and format version bound as AAD. Nonce handling and uniqueness, AAD binding,
   the master-key → barrier-key wrapping, and the rewrap-on-rekey path. Can a
   ciphertext be relocated, downgraded, or replayed? Any nonce-reuse risk?
2. **Shamir seal/unseal** (`internal/shamir`, `internal/core`) — the in-house
   GF(2⁸) secret-sharing. Correctness of the field arithmetic and Lagrange
   interpolation, constant-time behavior, share validation, and the seal/unseal
   state machine. Can the vault be coerced into an unsafe state? Are `rekey`,
   `generate-root`, and the recovery-key flows sound (no unseal-without-quorum,
   no key disclosure)?
3. **Seals** (`internal/seal`) — the static-KEK, transit, and external-command
   seals. For the external seal: the master key transits a child process's
   stdin/stdout — argument/command handling, fail-safe on error/timeout, and the
   bounds of that exposure. Fail-open is a critical-severity concern anywhere.
4. **AuthN/AuthZ** — the ACL policy engine and token store (`internal/policy`,
   `internal/token`): default-deny correctness, path/glob matching, privilege
   escalation, and the in-house HCL parser's robustness. The auth methods
   (`internal/jwtauth`, `approle`, `userpass`, `kubeauth`): JWS/JWT verification
   (algorithm confusion, `kid`/JWKS handling, `exp`/`aud`/issuer checks), AppRole
   secret-id hashing, userpass PBKDF2 parameters and timing behavior.

## Scope — secondary

5. **Transit** (`internal/transit`) — encrypt/decrypt, sign/verify (ECDSA/Ed25519),
   HMAC, key versioning; correct algorithm/key-type separation.
6. **Storage backends** (`internal/storage`) — path-traversal defenses (file),
   the crash-recovery/temp-file handling, and the MySQL backend (bound parameters
   / injection surface, case-exact `VARBINARY` keys, the single-active-writer
   assumption).
7. **Audit** (`internal/audit`) — fail-closed guarantees and the HMAC'ing of
   sensitive fields (no secret leakage into the log).
8. **PKI** (`internal/pki`) and **dynamic DB credentials** (`internal/database`).
9. **Supply chain** — the release pipeline (keyless cosign signing + SBOM
   attestation) and the one-dependency posture.

## Out of scope / lower priority

- Multi-writer HA, in-vault multi-tenancy (namespaces), M-of-N approval, MFA — not implemented.
- A compromised, unsealed host with the master key in memory (accepted, per the threat model).
- Nation-state memory forensics / physical extraction / FIPS-140 physical.
- The example deployment material (`docs/DEPLOYMENT.md`, Helm chart integrations) beyond obvious misconfiguration footguns.

## Questions we most want answered

- Is the **in-house cryptography** (Shamir, the barrier's AEAD usage, PBKDF2,
  JWS verification) correct and free of timing/side-channel issues?
- Can any path **unseal without a proper quorum/KEK**, disclose a key, or leave a
  seal **fail-open**?
- Any **authorization bypass** — ACL evaluation, path matching, token scoping, or
  auth-method verification (esp. JWT algorithm/`kid` confusion)?
- Any **injection or memory-safety** issue in the parsers (HCL, JWS, ciphertext,
  snapshot) or the storage backends?
- Is the **fail-closed audit** actually fail-closed?
- Is the overall design's **honest claim** — "storage/DSN compromise yields
  ciphertext, not secrets" — actually true end to end?

## What we provide

- Full source (public, BSD-3-Clause), `docs/DESIGN.md`, `docs/DECISIONS.md`
  (ADRs), and this brief.
- Build/run instructions and a reproducible test environment (single binary +
  Helm chart; MariaDB via container).
- Our own prior testing to build on, not to trust: native **fuzz targets** for
  the parsers, **property tests** for Shamir and the barrier, backend
  **conformance** tests, and CI (lint, `govulncheck`, MariaDB integration).
- A specific commit/tag to review, and prompt engagement on questions.

## Working model & deliverable

- **Private disclosure of unfixed findings** through the channel in `SECURITY.md`
  (GitHub private vulnerability reporting) — please do not open public issues for
  vulnerabilities.
- Expected deliverable: a **written report with severity-rated findings and a
  methodology note.** We fix, then (with the reviewer's agreement) **publish the
  final report** — remediated findings and all.
- Reviewer profile sought: **independence** (not affiliated with the project) and
  **relevant expertise** (applied cryptography + Go / systems security), with a
  documented methodology.

## Engagement paths

Any of these can satisfy the gate, provided the profile above is met:

- A specialist firm (e.g. Trail of Bits, NCC Group, Cure53, Doyensec, Latacora) —
  full or **scoped to the crown jewels** above.
- A qualified independent auditor / applied-cryptographer under contract.
- A **funded-OSS audit program** (e.g. OSTIF), which can broker/fund a firm audit.

Contact: via GitHub — [github.com/cwolsen7905/ubixvault](https://github.com/cwolsen7905/ubixvault)
(Security tab → *Report a vulnerability*, or the maintainer's profile).
