# uBix Vault — External Security Review Brief (1.0)

> A scoping brief for anyone assessing uBix Vault's security — a firm, an
> independent reviewer, or a funded-OSS program. It gives the hard scoping facts,
> a pass/fail definition of the 1.0 gate, the crown-jewels scope, the specific
> questions we care about, and the working model. An external review is the one
> remaining gate on the road to `1.0` (`docs/ROADMAP.md`); this brief makes it
> easy to scope and kick off.

## At a glance (scoping facts)

| | |
|---|---|
| **Review target** | A tag frozen at engagement start. Current reviewable release: `v0.2.0-beta.11`; a `1.0.0-rc.1` tag will be cut for the engagement and docs frozen to it. |
| **Language / toolchain** | Go 1.24 (`go.mod`), standard library + **one** third-party dependency (`github.com/go-sql-driver/mysql`). |
| **Size** | ~10.5k LoC production (55 non-test `.go` files) + ~7.4k LoC tests. |
| **Build** | Single **static** binary, **CGO disabled** (`CGO_ENABLED=0`), multi-arch (amd64/arm64), distroless runtime image. |
| **Entry points** | `cmd/ubixvault/main.go` (server + `operator` CLI); HTTP API under `internal/api` (routes in `internal/api/sys.go`, Vault-compatible `/v1/*` paths). |
| **Attack surface** | The HTTP API; the storage backend (file or MySQL); the auto-unseal seal (KEK, transit, or external command); operator CLI/flags/env. **`net/http/pprof` is not exposed.** |
| **Storage backends** | File (local dir) and **MySQL/MariaDB** (`-storage mysql`); both hold only barrier ciphertext. |

## What uBix Vault is

A self-hosted, single-node secrets manager in Go (HashiCorp Vault–style): an
AES-256-GCM encryption barrier, in-house Shamir seal/unseal, KV v2, Transit
(crypto-as-a-service), dynamic MySQL/MariaDB credentials, PKI, five auth methods,
ACL policies, and a fail-closed audit log, over a Vault-compatible HTTP API. All
cryptography is Go standard-library primitives wrapped in in-house logic; the only
third-party dependency is the MySQL driver. Architecture in `docs/DESIGN.md` §3;
decisions in `docs/DECISIONS.md`.

**Status:** pre-1.0 beta, not production-hardened, **not previously reviewed**.
The engineering gates for 1.0 (durable storage, hardening, KMS/HSM seal) have
landed; this review is the remaining gate.

## The 1.0 gate (pass/fail)

The gate is satisfied when, against the frozen review tag:

- **No open Critical or High findings on the crown-jewels scope** (below).
- The **fail-closed audit** guarantee is verified (an unwritable audit sink stops the vault serving).
- The load-bearing invariant **"storage / DSN compromise yields ciphertext, not secrets"** holds end to end.
- **Medium/Low findings may be accepted** for 1.0 with documented mitigations or a tracked follow-up.

## Threat model

Full model in `docs/DESIGN.md` §5. In two sentences: **in scope** — a network
attacker, a storage/DSN compromise (reads the backend), a holder of a leaked
token, a malicious client, and a supply-chain tamper of the release image; **out
of scope** — a compromised, *unsealed* host with the master key already in memory,
and multi-writer/multi-tenant concerns. The central trust boundary is the
**barrier**: everything below it is ciphertext.

## Scope — Primary (must-review; catastrophic if broken)

1. **`internal/barrier`** — AES-256-GCM at rest. AEAD construction, **nonce
   uniqueness under crash/retry**, AAD = storage path + format version (relocation
   / downgrade / replay), and the master-key → barrier-key wrapping incl. the
   **rewrap-on-rekey** path.
2. **`internal/shamir` + `internal/core` seal state machine** — the in-house
   GF(2⁸) secret-sharing: field arithmetic and Lagrange interpolation correctness,
   **constant-time** behavior, share validation, and **quorum enforcement**. Can
   the vault be coerced to unseal without a quorum/KEK, or leak a key? Soundness of
   `rekey`, `generate-root`, and the recovery-key flows.
3. **`internal/seal`** — static-KEK, transit, and **external-command** seals (see
   [External seal](#external-seal--process-model) for the process model). Any
   **fail-open** path is Critical.
4a. **`internal/policy` + `internal/token`** — ACL **default-deny** correctness,
   path/**glob** semantics, token hierarchy/scoping. The policy parser is an
   **in-house HCL parser (not `hashicorp/hcl`)** — it needs a parser
   differential / injection review.
4b. **`internal/jwtauth`, `internal/approle`, `internal/userpass`, `internal/kubeauth`**
   — JWS/JWT verification (**algorithm confusion**, `kid`/JWKS handling,
   `exp`/`aud`/issuer checks), AppRole secret-id **constant-time** hash compare,
   userpass PBKDF2 parameters + timing, Kubernetes TokenReview handling.

## Scope — Secondary (important; High if broken)

5. **`internal/transit`** — encrypt/decrypt, sign/verify (ECDSA/Ed25519), HMAC,
   key versioning; correct algorithm/key-type separation.
6. **`internal/storage`** — file backend path-traversal defenses and
   **crash-recovery/temp-file** handling; MySQL backend bound-parameter / injection
   surface, case-exact `VARBINARY` keys, and the single-active-writer assumption.
7. **Snapshot / restore / rekey APIs** — the ciphertext/snapshot parsers,
   **downgrade risk**, and whether a crafted snapshot can corrupt or mislead a restore.
8. **Config / CLI / env handling** — a frequent leak point for the KEK, DSN, or
   transit token (flags vs. env, process args, error messages).
9. **Token lifetime / revocation / lease GC** — can a stale token or lease bypass
   ACL or outlive a revocation?
10. **`internal/audit`** — fail-closed guarantees and HMAC'ing of sensitive fields.
11. **`internal/pki`**, and the **supply chain** (cosign signing + SBOM; one-dependency posture).

## External seal — process model

The external-command seal (`-seal-external-command`) is how cloud-KMS/HSM
auto-unseal works without a provider SDK. The exact model to review:

- The command and its args are **operator-supplied server configuration** (flags),
  not network input. It is invoked as `<cmd> [args] wrap|unwrap`.
- **`wrap`** reads the 32-byte master key on stdin → writes the wrapped blob to
  stdout at init; **`unwrap`** reverses it at each unseal. The master key transits
  a child process's stdin/stdout (an in-memory pipe) during that call.
- **Timeout:** each call is bounded (`-seal-external-timeout`, default 30s) via a
  context; on timeout or non-zero exit the child is killed and the operation fails.
- **Fail-safe means:** the vault **stays sealed** — it never falls back to an
  unprotected key. A wrong `unwrap` yields a wrong master key that fails barrier
  authentication (so a bad KMS response also just keeps it sealed).
- **Env:** the child inherits the vault's environment (plus optional appended
  vars); KMS credentials are the operator's to supply there.
- **Known residual:** we do not explicitly wipe the pipe buffers after use
  (best-effort only) — please assess. Implementation: `internal/seal/external.go`.

## Explicitly in / out of scope

- **In:** everything above; the honesty of the "ciphertext-only storage" claim.
- **Out:** a compromised *unsealed* process (master key in memory — accepted);
  multi-writer HA and in-vault namespaces (not implemented); nation-state memory
  forensics / physical extraction / FIPS-140 physical.
- **DoS / resource exhaustion:** **lower priority.** A per-client token-bucket
  rate limiter exists (opt-in). Note obvious unauthenticated amplification, but a
  full DoS assessment is not the focus.

## Questions we most want answered

- Is the **in-house cryptography** (Shamir, the barrier's AEAD usage, PBKDF2, JWS
  verification) correct and free of timing / side-channel issues?
- Can any path **unseal without a proper quorum/KEK**, disclose a key, or leave a
  seal **fail-open**?
- Any **authorization bypass** — ACL evaluation, glob/path matching, token
  scoping, or auth-method verification (esp. JWT algorithm/`kid` confusion)?
- Any **injection or memory-safety** issue in the parsers (in-house HCL, JWS,
  ciphertext, snapshot) or the storage backends?
- Are there **key-zeroization or logging side-channels** that leak key material via
  error messages, metrics, or (were it enabled) profiling endpoints?
- Is the **fail-closed audit** actually fail-closed, and is
  **"storage compromise = ciphertext only"** true end to end?

## Constant-time & zeroization (what we attempt — please validate)

- **Constant-time:** the in-house Shamir GF(2⁸) multiply, PBKDF2 password compare
  (userpass), AppRole secret-id compare, and recovery-key compare use
  constant-time paths (`crypto/subtle` / branch-free field math). We claim intent;
  please confirm.
- **Zeroization:** the master key, barrier key, and Shamir shares are
  best-effort-overwritten (`zero()`) after use. This is **best-effort only** — the
  Go GC may relocate or retain copies, and `mlock` is not used; assess the real
  residual exposure.

## Supply chain

- **Toolchain:** Go 1.24; `go.sum` pins all module hashes; standard Go module
  resolution (module proxy), **not vendored**. `govulncheck ./...` runs in CI on
  every change.
- **Releases:** multi-arch images are **keyless-signed with cosign** and carry an
  **SPDX SBOM attestation**; both are stored in the registry (OCI) alongside the
  image and logged to the Rekor transparency log, verifiable via the GitHub OIDC
  identity (see `docs/DEPLOYMENT.md` §9).

## What we provide

- Full source (public, BSD-3-Clause), `docs/DESIGN.md` (architecture, §5 threat
  model), `docs/DECISIONS.md` (ADRs), and this brief — frozen to the review tag.
- **`docs/REVIEWER_QUICKSTART.md`** — build, run (incl. MariaDB via a container),
  and a happy-path API walk-through, plus how to run the tests and fuzz targets.
- The Vault-compatible route list (`internal/api/sys.go`); an OpenAPI spec is not
  yet published — API semantics mirror HashiCorp Vault per subsystem (D-003).
- Our own prior testing, to build on rather than trust: native **fuzz targets**
  (parsers), **property tests** (Shamir, barrier), backend **conformance** tests,
  and `govulncheck` output on request.
- A specific frozen commit/tag, and prompt engagement on questions.

## Working model & deliverable

- **Private disclosure** of unfixed findings via the channel in `SECURITY.md`
  (GitHub private vulnerability reporting) — **not** public issues. NDA available
  on request; a direct comms channel (email / Signal / Slack) set at kickoff.
- **Coordinated disclosure:** a private fix window before publication (see the
  90-day default in `SECURITY.md`). We provide a **fix branch for re-test**.
- Expected deliverable: a **written report with severity-rated findings and a
  methodology note.** After remediation, we intend to **publish the final report**
  (with the reviewer's agreement) — findings and fixes.
- **Reviewer profile sought:** independence (unaffiliated) and relevant expertise
  (applied cryptography + Go / systems security), with a documented methodology.

## Engagement paths & effort

Any of these satisfies the gate, given the profile above:

- **Scoped crown-jewels review** — our preferred first step: roughly a
  **1-week, 1–2-reviewer** pass over Primary scope (§Primary).
- **Full-scope firm audit** (e.g. Trail of Bits, NCC Group, Cure53, Doyensec,
  Latacora) — typically **~2–3 weeks, 2 auditors** for a codebase this size.
- **Funded-OSS program** — e.g. **OSTIF**, which can broker/fund a firm audit.

Budget: we are a solo open-source project **seeking pro-bono / OSTIF / grant
funding or a scoped paid engagement** — happy to right-size scope to fit.

## Contact

- **Vulnerabilities:** GitHub Security tab → *Report a vulnerability*
  ([repo](https://github.com/cwolsen7905/ubixvault)).
- **Scoping / engagement:** `cwolsen@brainchurts.com`.
