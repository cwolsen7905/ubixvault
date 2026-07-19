# uBix Vault

**Open, self-hosted secrets & encryption management — a from-scratch secrets
manager in Go.** uBix Vault stores and generates secrets behind an encrypted,
sealed barrier: an encryption barrier, Shamir seal/unseal, token auth with ACL
policies, versioned KV secrets, encryption-as-a-service, and dynamic database
credentials — over a Vault-API-compatible HTTP interface.

> **Status: working MVP — not yet production-hardened.** The core is built,
> tested, and demonstrated end-to-end, but it has not had the security review or
> operational hardening a production secrets store needs. For production today,
> use [HashiCorp Vault](https://www.vaultproject.io/) or
> [OpenBao](https://openbao.org/). Why uBix Vault exists alongside them:
> [`docs/POSITIONING.md`](docs/POSITIONING.md).

## Capabilities

- **Encryption barrier** — all data at rest is AES-256-GCM encrypted (storage never sees plaintext); the storage path is bound into the ciphertext so blobs can't be relocated.
- **Seal / unseal** — the vault boots *sealed*; the master key is reconstructed from **Shamir k-of-n** key shares (implemented in-house, constant-time GF(2⁸)) before any secret is readable.
- **Token auth + ACL policies** — default-deny, path-based capabilities; scoped, non-root tokens.
- **KV v2** — versioned secrets with soft-delete / undelete / destroy and max-versions.
- **Transit** — encryption-as-a-service: apps encrypt/decrypt over the API; keys never leave the vault, and rotate without breaking old ciphertext.
- **Dynamic database credentials** — short-lived MariaDB users generated on demand and auto-revoked on lease expiry.
- **Audit logging** — fail-closed; records who accessed what, with the client token HMAC'd (never logged in the clear).

## Quickstart

```sh
# Build and run the server (dev mode: plain HTTP, audit log enabled)
go build -o bin/ubixvault ./cmd/ubixvault
./bin/ubixvault server -data ./data -audit-log ./audit.log
```

In another terminal (`export VAULT=http://127.0.0.1:8200`):

```sh
# 1. Initialize (3 unseal shares, threshold 2). Save the keys and root token!
curl -s -X POST $VAULT/v1/sys/init -d '{"secret_shares":3,"secret_threshold":2}'
# -> {"keys":["<k0>","<k1>","<k2>"], "root_token":"uv...."}

# 2. Unseal with any 2 shares.
curl -s -X POST $VAULT/v1/sys/unseal -d '{"key":"<k0>"}'
curl -s -X POST $VAULT/v1/sys/unseal -d '{"key":"<k1>"}'   # -> "sealed":false

export T="X-Vault-Token: <root_token>"

# 3. KV v2: write and read a versioned secret.
curl -s -H "$T" -X POST $VAULT/v1/secret/data/app -d '{"data":{"api_key":"sk-123"}}'
curl -s -H "$T" $VAULT/v1/secret/data/app

# 4. Transit: encryption-as-a-service (keys never leave the vault).
curl -s -H "$T" -X POST $VAULT/v1/transit/keys/orders
curl -s -H "$T" -X POST $VAULT/v1/transit/encrypt/orders \
  -d "{\"plaintext\":\"$(printf 'card-4242' | base64)\"}"     # -> {"ciphertext":"ubix:v1:..."}

# 5. Scoped access: a read-only token that can read app secrets but not write them.
curl -s -H "$T" -X PUT $VAULT/v1/sys/policies/acl/app-ro \
  -d '{"path":{"secret/data/app":{"capabilities":["read"]}}}'
curl -s -H "$T" -X POST $VAULT/v1/auth/token/create -d '{"policies":["app-ro"]}'
# -> {"auth":{"client_token":"uv...."}}   # this token gets 200 on read, 403 on write

# 6. Dynamic database credentials (requires a reachable MariaDB).
curl -s -H "$T" -X POST $VAULT/v1/database/config \
  -d '{"connection_url":"root:pw@tcp(127.0.0.1:3306)/db"}'
curl -s -H "$T" -X POST $VAULT/v1/database/roles/readonly \
  -d '{"creation_statements":["CREATE USER '\''{{username}}'\''@'\''%'\'' IDENTIFIED BY '\''{{password}}'\''","GRANT SELECT ON *.* TO '\''{{username}}'\''@'\''%'\''"],"default_ttl":"1h"}'
curl -s -H "$T" $VAULT/v1/database/creds/readonly
# -> {"username":"uv_readonly_...","password":"...","lease_id":"...","lease_duration":3600}
```

TLS is enabled by passing `-tls-cert` and `-tls-key`; without them the server
logs a prominent no-TLS warning (dev only).

## Architecture

uBix Vault is layered, with everything resting on the encryption barrier:

```
HTTP API  ·  auth + ACL middleware  ·  audit
Secrets engines: KV v2 · Transit · Dynamic Database
Tokens · Policies · Core (init / seal / unseal)
BARRIER (AES-256-GCM at rest) · Shamir seal/unseal
Storage backend (file)
```

Each subsystem is a small Go package behind an interface (`storage`, `barrier`,
`shamir`, `core`, `token`, `policy`, `kv`, `transit`, `database`, `audit`, `api`),
which is what lets engines and backends be swapped and tested independently.

## Design & documentation

The architecture and reasoning are first-class parts of the project:

- **[docs/DESIGN.md](docs/DESIGN.md)** — architecture, subsystems, threat model, engineering standards, operational considerations.
- **[docs/DECISIONS.md](docs/DECISIONS.md)** — architecture decision records (Go vs. Rust vs. C++, in-house Shamir, first dependency, …).
- **[docs/ROADMAP.md](docs/ROADMAP.md)** — the v1.0 core and possible extensions.
- **[docs/POSITIONING.md](docs/POSITIONING.md)** — prior art and why this was built.

## Development

```sh
make test    # go test -race with coverage
make lint    # golangci-lint (also gofmt, vet)
make build   # build the binary
make help    # all targets
```

CI runs build/test (`-race`), lint (incl. gosec), `govulncheck`, and a MariaDB
integration job on every change.

## Why it exists

uBix Vault is a lightweight, from-scratch secrets manager built to support
[uBixCore](https://github.com/cwolsen7905/uBixCore), but it is
**framework-agnostic** — any application can use it over its HTTP API. Full
rationale in [`docs/POSITIONING.md`](docs/POSITIONING.md).

## License

BSD 3-Clause. See [LICENSE](LICENSE).
