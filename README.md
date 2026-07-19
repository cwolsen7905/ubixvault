# uBix Vault

**Open, self-hosted secrets & encryption management — a focused, from-scratch secrets
manager in Go.** uBix Vault is designed as the core of a HashiCorp Vault–style system:
an encrypted storage barrier, Shamir seal/unseal, token auth with ACL policies,
versioned KV secrets, encryption-as-a-service, and dynamic database credentials — behind
a Vault-API-compatible HTTP interface.

> **Status: planning / early development — not production-ready.** For production secrets
> management today, use [HashiCorp Vault](https://www.vaultproject.io/) or
> [OpenBao](https://openbao.org/). Why uBix Vault exists alongside them:
> [`docs/POSITIONING.md`](docs/POSITIONING.md).

## Capabilities (v1.0 target)

A secrets manager is the central authority that stores, generates, and controls access to
secrets — API keys, database credentials, certificates, encryption keys. The v1.0 core
covers the foundational, security-critical parts:

- **Encryption barrier** — all data at rest is AES-256-GCM encrypted; storage never sees plaintext.
- **Seal / unseal** — the vault boots *sealed*; the master key is reconstructed from **Shamir k-of-n** key shares before any secret is readable.
- **Transit** — encryption-as-a-service: applications encrypt/decrypt/sign over the API and the key never leaves the vault.
- **Dynamic secrets** — short-lived MariaDB credentials generated on demand and auto-revoked on lease expiry, via a pluggable `DatabasePlugin` interface.
- **Token auth + ACL policies** — default-deny, path-based capabilities.
- **Audit logging** — every request is logged with sensitive values HMAC'd so secrets are not exposed in the log.

## Why it exists

uBix Vault is a lightweight, from-scratch secrets manager. It was created to provide secrets
management for [uBixCore](https://github.com/cwolsen7905/uBixCore), but it is **framework-agnostic**
— any application or platform can use it over its HTTP API. HashiCorp Vault and OpenBao are
excellent and cover the general case; this is a focused implementation of the core.
Full rationale in [`docs/POSITIONING.md`](docs/POSITIONING.md).

## Design & documentation

The architecture and reasoning are first-class parts of the project:

- **[docs/DESIGN.md](docs/DESIGN.md)** — architecture, subsystems, threat model, MVP definition of done.
- **[docs/DECISIONS.md](docs/DECISIONS.md)** — architecture decision records (Go vs. Rust vs. C++, scope, compatibility).
- **[docs/ROADMAP.md](docs/ROADMAP.md)** — the committed v1.0 core and optional extensions.
- **[docs/POSITIONING.md](docs/POSITIONING.md)** — prior art and why this was built.

## Technology

Go — chosen for its cloud-native ecosystem fit, memory safety, and domain libraries.
Full trade-off analysis in [docs/DECISIONS.md](docs/DECISIONS.md).

## License

BSD 3-Clause. See [LICENSE](LICENSE).
