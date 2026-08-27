# Security Policy

uBix Vault is a secrets manager, so security is the project's first priority. We
take vulnerability reports seriously and appreciate coordinated disclosure.

## Project status (read this first)

uBix Vault is a **pre-1.0 beta** (currently `v0.2.0-beta.10`). The cryptographic
core — the AES-256-GCM barrier, in-house Shamir seal/unseal, and all
cryptography — is implemented and tested, and the project builds from the Go
standard library plus a single third-party dependency (the MySQL driver). But:

- it has **not had an external security review**, and
- it is **not production-hardened**.

Treat it accordingly: it is suitable for sandbox, development, and
internal/low-blast-radius use. For production secrets, use
[HashiCorp Vault](https://www.vaultproject.io/) or [OpenBao](https://openbao.org/)
until the 1.0 gates in [`docs/ROADMAP.md`](docs/ROADMAP.md) — including an
external review — are met. The threat model is documented in
[`docs/DESIGN.md` §5](docs/DESIGN.md) and the honest scope in
[`docs/POSITIONING.md`](docs/POSITIONING.md).

## Supported versions

While the project is pre-1.0, only the latest beta receives security fixes.

| Version | Supported |
| --- | --- |
| latest `0.2.0-beta.N` | ✅ |
| older betas / `0.1.x` | ❌ |

When 1.0 ships, this will move to a maintained-release model.

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

This is a solo-maintained project, so response and fix timelines are best-effort.
Please give us a reasonable window to release a fix before any public disclosure.

## Scope

**In scope** — the confidentiality, integrity, or availability of secrets and the
mechanisms that protect them:

- the encryption barrier and the seal/unseal (Shamir, KEK, transit seal) paths;
- authentication (all auth methods), tokens/leases, and the ACL policy engine;
- the secrets engines (KV, Transit, PKI, dynamic database);
- the storage backends (file, MySQL) and the snapshot/restore path;
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
