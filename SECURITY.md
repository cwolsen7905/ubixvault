# Security Policy

uBixVault is a secrets manager, so security is the project's first priority. We
take vulnerability reports seriously and appreciate coordinated disclosure.

## Project status (read this first)

uBixVault is a **1.x release**: the HTTP API, CLI, storage format and chart
values are stable under SemVer ([`docs/VERSIONING.md`](docs/VERSIONING.md)). The
cryptographic core — the AES-256-GCM barrier, in-house Shamir seal/unseal, and
all cryptography — is implemented and tested, and the project builds from the Go
standard library plus a small set of third-party dependencies. But:

- it has **not had an independent security audit**, and
- Raft integrated storage is **experimental** (no production soak yet).

API stability is not a security assurance. For high-blast-radius production
secrets, prefer [HashiCorp Vault](https://www.vaultproject.io/) or
[OpenBao](https://openbao.org/) until an external review lands (an open
milestone in [`docs/ROADMAP.md`](docs/ROADMAP.md)), and start with
low-criticality secrets. The threat model is documented in
[`docs/DESIGN.md` §5](docs/DESIGN.md) and the honest scope in
[`docs/POSITIONING.md`](docs/POSITIONING.md).

## Supported versions

Security fixes ship in the latest `1.x` release. The 1.x API is stable under
SemVer (`docs/VERSIONING.md`), so upgrading within 1.x is the supported way to
receive a fix; earlier minors are not patched separately.

| Version | Supported |
| --- | --- |
| latest `1.x` | ✅ |
| earlier `1.x` minors | ❌ — upgrade to the latest 1.x |
| `0.x` betas | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through GitHub's **[Private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)**
— the **"Report a vulnerability"** button under this repository's **Security**
tab. If you cannot use that channel, reach the maintainer privately through their
GitHub profile ([@cwolsen7905](https://github.com/cwolsen7905)).

### What to include

- A description of the vulnerability and its impact.
- Steps to reproduce, or a proof of concept.
- The affected version / commit and any relevant configuration.

## Our commitment

- We will acknowledge your report as promptly as we can.
- We will keep you informed as we investigate and work on a fix.
- We will credit reporters who wish to be credited once a fix is released.

## Coordinated disclosure

We follow coordinated disclosure with a **90-day** default embargo:

- We aim to acknowledge within a few days and to agree a fix timeline with you.
- Please keep the report **private until a fix is released or 90 days have
  passed**, whichever comes first. We will ask for more time only for a genuinely
  complex fix, and only with your agreement.
- We provide a **fix branch for re-test** before release where practical, and
  publish an advisory (crediting you, if you wish) when the fix ships.

This is a solo-maintained project, so timelines are best-effort; we will
communicate openly if a fix needs longer.

## Raft integrated storage (experimental)

`-storage raft` / chart `storage.type=raft` is **experimental** in 1.6.0: it has
had no production soak and no independent review, and the points below are the
security-relevant parts of running it. Full detail:
[`docs/design/raft-storage.md`](docs/design/raft-storage.md) and
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

- **Cluster CA and node TLS.** Replica-to-replica traffic (Raft and request
  forwarding, ALPN-multiplexed on the cluster port, 8201) uses mutual TLS under
  a per-cluster CA. The CA record is stored in the encrypted store (barrier
  data), has a 10-year life, and node leaf certificates are issued from it and
  held only in memory, so they are reissued on unseal. Anyone holding a valid
  leaf, or the CA key, can act as a cluster peer; treat the unsealed process
  memory and the barrier as the trust boundary, as for any backend.
- **Join token.** A node joins with a single-use, short-lived (15 minute
  default) token minted by an operator with `sudo` on
  `sys/storage/raft/join-token`. Only its SHA-256 is stored; it is burned on
  first use, and every failure (invalid, expired, used) returns the same 403. A
  leaked unburned token lets a rogue node join and replicate ciphertext: remove
  it with `remove-peer`, and rotate the cluster CA if its leaf may have been
  exfiltrated. Keep tokens out of logs and shell history; the chart delivers
  them through a Secret.
- **Rotating the CA.** Rotate when the CA key may be exposed, or around year 8.
  It is disruptive, not rolling: take a snapshot, run `operator raft
  rotate-ca` on the leader, then re-seal or restart every node (followers first)
  and unseal. A node that missed the new CA must be removed, wiped and re-joined
  with a fresh token. The runbook is in the design note under *Cluster CA
  rotation*; rehearse it before you need it.
- **`peers.json` recovery can lose acknowledged writes.** `operator raft
  recover` rewrites the membership of a stopped survivor after quorum is
  permanently lost. Writes acknowledged only by the dead majority are gone, and
  the data directory must not be shared with any node that is still running.
  Use it only when quorum cannot be restored, snapshot first, and re-join the
  other nodes from scratch afterwards.
- **Network policy on the raft port.** Port 8201 must be reachable only from
  the cluster's own replicas. Enable `storage.networkPolicy.enabled` in the
  chart (or the equivalent in your platform) and do not expose 8201 through any
  Service, Ingress or load balancer. Peer authentication is mutual TLS, but the
  policy keeps the port off the attack surface entirely. Note that some CNIs
  (kind's default among them) do not enforce NetworkPolicy; verify yours does.
- **Unseal.** Use auto-unseal for Raft clusters; with Shamir seals every
  restart waits for an operator holding the key shares.

## Scope

**In scope** — the confidentiality, integrity, or availability of secrets and the
mechanisms that protect them:

- the encryption barrier and the seal/unseal (Shamir, KEK, transit seal) paths;
- authentication (all auth methods), tokens/leases, and the ACL policy engine;
- the secrets engines (KV, Transit, PKI, dynamic database);
- the storage backends (file, MySQL, Raft) and the snapshot/restore path;
- the audit log (it is fail-closed by design);
- the release supply chain (image signing / SBOM attestation).

**Out of scope**

- The example deployment material (`docs/DEPLOYMENT.md`, the Helm chart's optional
  third-party integrations) — these are references you adapt and secure for your
  environment.
- Vulnerabilities in third-party dependencies themselves — please report those
  upstream (we will update once a fixed version is available).
- Attacks that require capabilities the threat model already assumes the attacker
  does not have (see [`docs/DESIGN.md` §5](docs/DESIGN.md)) — e.g. that storage
  compromise yields only ciphertext, and that a compromised unsealed host with the
  master key in memory is game over.
