# uBix Vault — Deployment Guide

> **Status:** beta (`v0.2.0-beta`). uBix Vault is usable for real workloads but has
> not had an external security review. Read the [Security notes](#security-notes)
> before depending on it.

This guide covers running a single uBix Vault node. It assumes the `ubixvault`
binary (`go build -o ubixvault ./cmd/ubixvault`).

## 1. Storage

uBix Vault persists everything through a pluggable storage backend. Whatever the
backend, it holds **only ciphertext** — the barrier encrypts every value before
it is stored, so the store never sees plaintext.

### File backend (default)

Stores the encrypted data under a directory:

```sh
ubixvault server -data /var/lib/ubixvault           # -storage file is the default
```

Back this directory up (see [Backups](#6-backups)). It is single-node and its
durability rests on one disk.

### MySQL/MariaDB backend

Stores the encrypted data in a MySQL/MariaDB database, so the node becomes
**replaceable**: it can die and restart — on another host — against the same
durable, replicated database, and the database's own HA handles durability.

```sh
ubixvault server -storage mysql -storage-mysql-dsn "$UBIXVAULT_STORAGE_DSN"
# or just set $UBIXVAULT_STORAGE_DSN and pass -storage mysql
```

**Setup is minimal — the vault creates its own tables.** You only provide a
database and a user:

```sql
CREATE DATABASE ubixvault CHARACTER SET binary;
CREATE USER 'ubixvault'@'%' IDENTIFIED BY 'a-strong-password';
-- SELECT/INSERT/UPDATE/DELETE for normal operation; CREATE so the vault can
-- create its two tables on first boot (you may drop CREATE afterward, or
-- pre-create the tables and never grant it).
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE ON ubixvault.* TO 'ubixvault'@'%';
```

The DSN is a [go-sql-driver](https://github.com/go-sql-driver/mysql#dsn-data-source-name)
string, e.g. `ubixvault:PASSWORD@tcp(db-host:3306)/ubixvault?tls=true`.

**Single active writer.** Exactly one vault process may write to a given
database: the barrier key, leases, and unseal progress live in memory, so two
processes on one database would race and diverge. This is durable,
replaceable-node storage, **not** multi-writer HA (keep `replicaCount: 1`).

#### Securing the database credentials

The DSN contains a database username and password. Two facts shape how much this
matters, and how to protect it:

- **The blast radius is bounded.** The database stores only barrier ciphertext,
  and the master key (unseal shares / KEK) never touches the database or the DSN.
  So a leaked DSN — or a fully compromised database — yields *ciphertext, not
  secrets*. An attacker would still need the master key, which lives elsewhere.
- **It is still a credential ("secret zero").** A secrets manager needs one
  credential to start; you can shrink and protect it, not eliminate it.

Protect it, roughly weakest to strongest:

1. **Never put the DSN on the command line.** Pass it via `$UBIXVAULT_STORAGE_DSN`
   (arguments are visible in `/proc/<pid>/cmdline` and `ps`). The Helm chart does
   this for you — see below.
2. **Least privilege + TLS to the database.** Scope the user to only the
   `ubixvault` database, and use `?tls=true` in the DSN so credentials are
   encrypted in transit. (`tls=true` and `tls=skip-verify` work out of the box; a
   custom CA or client-certificate config is a planned enhancement.)
3. **On Kubernetes:** keep the DSN in a `Secret` (the chart references it by name,
   so it never appears in `values.yaml`, git, or `helm get values`), enable **etcd
   encryption-at-rest**, and restrict `get secret` RBAC on it. Optionally source
   the Secret from an external secret store (External Secrets Operator, etc.).
4. **Remove the password entirely** (strongest): MariaDB `REQUIRE X509`
   client-certificate (mTLS) auth, or cloud IAM auth / an auth-proxy sidecar
   (RDS/Cloud SQL). The DSN then carries no password.

#### Migrating an existing vault onto MySQL

Use the snapshot machinery — it round-trips the whole encrypted store through the
backend, so no data re-encryption or new tooling is needed:

```sh
# 1. Snapshot the file-backed vault (see Backups).
ubixvault operator snapshot save -token "$ROOT" backup.snapshot
# 2. Restore it into the MySQL backend (offline), then start on MySQL.
ubixvault operator snapshot restore -storage mysql -storage-mysql-dsn "$DSN" backup.snapshot
```

The same unseal shares / KEK still work — only the physical store moved.

## 2. TLS

**Always run with TLS outside of local development.** Without a certificate the
server binds to loopback only and refuses non-loopback plaintext:

```sh
# Refused — would serve secrets in the clear:
ubixvault server -listen 0.0.0.0:8200

# Correct:
ubixvault server -listen 0.0.0.0:8200 -tls-cert /etc/ubixvault/tls.crt -tls-key /etc/ubixvault/tls.key
```

`-dev-no-tls` overrides the check for trusted-network development only. Never use
it in production.

## 3. Unsealing

The vault starts **sealed** and cannot serve secrets until unsealed. Choose one:

**Shamir (default).** `operator init` returns *k-of-n* unseal shares; distribute
them to separate holders. After every restart, provide a threshold of shares:

```sh
ubixvault operator init -shares 5 -threshold 3      # save the keys + root token
ubixvault operator unseal <key>                     # repeat until unsealed
```

**Auto-unseal.** The master key is wrapped by a 32-byte key-encryption key (KEK),
so the server unseals itself on startup — no manual step:

```sh
export UBIXVAULT_AUTO_UNSEAL_KEY=$(head -c32 /dev/urandom | xxd -p | tr -d '\n')
ubixvault server -data /var/lib/ubixvault -auto-unseal-key "$UBIXVAULT_AUTO_UNSEAL_KEY" ...
```

The KEK protects the entire vault — store it in a secrets manager or KMS, not on
the same disk as the data.

**Transit auto-unseal.** Instead of holding a KEK locally, unseal by wrapping the
master key via another Vault-compatible **Transit** engine (uBix Vault or
HashiCorp Vault). The wrapping key lives in that vault and never reaches this
host, which only needs a token authorized to encrypt/decrypt with the key:

```sh
ubixvault server -data /var/lib/ubixvault \
  -seal-transit-address https://seal-vault:8200 \
  -seal-transit-key unseal \
  -seal-transit-token "$UBIXVAULT_SEAL_TRANSIT_TOKEN"   # or the env var
```

On restart the server calls the seal vault's `transit/decrypt` to recover the
master key. If the seal vault is unreachable it stays sealed (fail-safe). Like
KEK auto-unseal, `init` returns recovery keys for root-token regeneration. In the
chart, set `sealTransit.*` (mutually exclusive with `autoUnseal`).

**External (cloud-KMS / HSM) auto-unseal.** Reach any cloud KMS (AWS/GCP/Azure)
or HSM without a provider SDK in the vault: point `-seal-external-command` at a
command that wraps/unwraps the master key. The vault invokes it in two modes,
piping raw bytes:

```
<command> [args...] wrap     # plaintext master key on stdin  -> wrapped blob on stdout
<command> [args...] unwrap   # wrapped blob on stdin          -> plaintext master key on stdout
```

Success is exit status 0 with non-empty stdout; the wrapped blob is opaque (the
command owns its format). A non-zero exit or a timeout leaves the vault **sealed**
(never fail-open). `unwrap` must emit exactly the original 32 bytes — no trailing
newline. The command's KMS/HSM credentials come from its environment (instance
role, workload identity, a mounted key), never from the vault.

```sh
ubixvault server -data /var/lib/ubixvault \
  -seal-external-command /usr/local/bin/uv-kms-seal \
  -seal-external-timeout 30s
```

Reference wrapper commands (each is a tiny script you provide — the KMS logic
lives here, not in the vault). The master key is 32 bytes, under every KMS's
direct-encrypt limit, so no envelope indirection is needed:

```sh
# AWS KMS — /usr/local/bin/uv-kms-seal
#!/bin/sh
case "$1" in
  wrap)   aws kms encrypt --key-id "$KMS_KEY_ID" --plaintext fileb:///dev/stdin \
            --query CiphertextBlob --output text | base64 -d ;;
  unwrap) aws kms decrypt --ciphertext-blob fileb:///dev/stdin \
            --query Plaintext --output text | base64 -d ;;
esac

# GCP Cloud KMS
case "$1" in
  wrap)   gcloud kms encrypt --key "$KMS_KEY" --plaintext-file - --ciphertext-file - ;;
  unwrap) gcloud kms decrypt --key "$KMS_KEY" --ciphertext-file - --plaintext-file - ;;
esac

# PKCS#11 HSM — via pkcs11-tool / openssl pkeyutl -engine pkcs11 (same shape).
```

**Image note:** the published vault image is distroless (no shell, no cloud CLI),
so the wrap command must be provided into the container — mount a static binary,
or build a derived image that bundles your provider CLI plus the script above.
Like the other auto-unseal modes, `init` returns recovery keys and only one seal
mode may be configured at a time.

Auto-unseal `init` also returns **recovery keys** (k-of-n, like Shamir shares).
The vault unseals itself with the KEK, so you never enter them to unseal — but a
threshold of them is the *only* way to regenerate a lost root token (see
[§7](#7-lost-root-token)). Save them as carefully as the KEK.

## 4. Running as a service

### systemd

```ini
# /etc/systemd/system/ubixvault.service
[Unit]
Description=uBix Vault
After=network-online.target

[Service]
ExecStart=/usr/local/bin/ubixvault server \
  -listen 0.0.0.0:8200 \
  -data /var/lib/ubixvault \
  -tls-cert /etc/ubixvault/tls.crt -tls-key /etc/ubixvault/tls.key \
  -audit-log /var/log/ubixvault/audit.log
# For auto-unseal, provide the KEK via the environment (e.g. an EnvironmentFile
# with restrictive permissions, or a credential from your init system):
# Environment=UBIXVAULT_AUTO_UNSEAL_KEY=...
User=ubixvault
Group=ubixvault
Restart=on-failure
# Hardening:
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/ubixvault /var/log/ubixvault

[Install]
WantedBy=multi-user.target
```

### Docker

```sh
docker run -d --name ubixvault \
  -p 8200:8200 \
  -v ubixvault-data:/data \
  -v /etc/ubixvault:/tls:ro \
  ubixvault server -listen 0.0.0.0:8200 -data /data \
    -tls-cert /tls/tls.crt -tls-key /tls/tls.key
```

Provide the auto-unseal KEK via `-e UBIXVAULT_AUTO_UNSEAL_KEY=...` (ideally from a
Docker/Kubernetes secret, not a plain env var in your compose file).

### Kubernetes (Helm)

A single-node Helm chart lives in [`deploy/charts/ubixvault`](../deploy/charts/ubixvault).
It deploys a StatefulSet with a persistent data volume, auto-unseal by default,
split TCP-liveness / HTTP-readiness probes (a sealed vault returns `503`, so an
httpGet liveness probe would crash-loop it), and the `system:auth-delegator`
binding the Kubernetes auth method needs. Build and push the image from the
repo-root `Dockerfile` first (no official image is published yet), then:

```sh
kubectl create ns ubixvault
kubectl -n ubixvault create secret generic ubixvault-kek \
  --from-literal=auto-unseal-key="$(head -c32 /dev/urandom | xxd -p | tr -d '\n')"

helm install vault ./deploy/charts/ubixvault -n ubixvault \
  --set image.repository=<your-registry>/ubixvault \
  --set tls.existingSecret=ubixvault-tls \
  --set autoUnseal.existingSecret=ubixvault-kek
```

Then run `operator init` once inside the pod. With TLS on (the chart default),
the CLI must target HTTPS and skip verifying the cert (it is issued for the
ingress host, not localhost):

```sh
kubectl -n ubixvault exec vault-ubixvault-0 -- \
  ubixvault operator init -address https://127.0.0.1:8200 -tls-skip-verify \
    -shares 5 -threshold 3
```

Use `-ca-cert <pem>` instead of `-tls-skip-verify` to verify against a specific
CA. It is single-node only — the chart refuses `replicaCount > 1`. See the chart
[README](../deploy/charts/ubixvault/README.md) for all values.

## 5. Health checks

`GET /v1/sys/health` is unauthenticated and encodes readiness in its status code
— point load balancers and liveness/readiness probes at it:

- `200` — initialized and unsealed (ready)
- `503` — sealed (not ready)
- `501` — not initialized

**Metrics.** `GET /v1/sys/metrics` returns Prometheus text-format metrics
(build info, seal state, uptime, HTTP request counts) — unauthenticated and free
of secret material, so it is safe to scrape; restrict it at the network layer as
you would any `/metrics`. The Helm chart can create a Prometheus Operator
`ServiceMonitor` (`metrics.serviceMonitor.enabled=true`).

**Web console.** A console is served at `/ui/` (`/` redirects there). It shows
the vault's seal state and lets an operator, with a token they supply in the
browser, manage KV v2 secrets (read/list/edit, version history, soft-delete /
undelete / destroy), ACL policies (list/read/write/delete), and mint scoped
tokens. The assets are static and embedded in the binary; the token is held only
in the browser tab, and every write goes through the audited `/v1` API.

## 6. Backups

Snapshots are consistent, encrypted copies of the whole store — safe to store at
rest (they contain only ciphertext). Restoring still requires the unseal shares
or the KEK.

```sh
# Back up (schedule this, e.g. via cron):
UBIXVAULT_ADDR=https://vault:8200 UBIXVAULT_TOKEN=<token> \
  ubixvault operator snapshot save /backups/ubixvault-$(date +%F).snapshot

# Restore into a fresh data directory (offline), then start the server on it:
ubixvault operator snapshot restore -data /var/lib/ubixvault-restored /backups/ubixvault-2026-07-23.snapshot
ubixvault server -data /var/lib/ubixvault-restored ...   # then unseal / auto-unseal
```

## 7. Lost root token

Recover a new root token from a quorum of keys (the vault must be unsealed):

- **Shamir mode:** use a threshold of the **unseal shares**.
- **Auto-unseal mode:** use a threshold of the **recovery keys** returned at
  `init` (the KEK unseals the vault; the recovery keys exist for exactly this).

```sh
# Over the API: POST /v1/sys/generate-root/init returns a nonce, then
# POST /v1/sys/generate-root/update with the nonce + each unseal/recovery key
# until it returns a new root_token.
```

If an auto-unseal vault was initialized before recovery-key support, it has no
recovery keys and a lost root token cannot be regenerated — reinitialize.

## 8. Upgrades

Stored entries are format-versioned, so a newer binary reads an older store.
Upgrade in place: stop the service, replace the binary, start it, and unseal (or
let auto-unseal run). Take a snapshot first.

## 9. Verifying released images

Published images are **keyless-signed with [cosign](https://github.com/sigstore/cosign)**
and carry an **SPDX SBOM attestation**, both produced in CI via GitHub OIDC and
bound to the image digest. Verify a release before deploying:

```sh
IMAGE=ghcr.io/cwolsen7905/ubixvault:0.2.0-beta.10
IDENTITY='https://github.com/cwolsen7905/ubixvault/.github/workflows/image.yml@refs/tags/v0.2.0-beta.10'

# Verify the signature came from this repo's release workflow.
cosign verify "$IMAGE" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Verify and extract the SBOM attestation.
cosign verify-attestation "$IMAGE" --type spdxjson \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  | jq -r '.payload | @base64d | fromjson | .predicate' > sbom.spdx.json
```

Use `--certificate-identity-regexp 'https://github.com/cwolsen7905/ubixvault/.*'`
instead of the exact identity to accept any tag. A failed verification means the
image is not a genuine, unmodified release — do not deploy it.

## Security notes

- **Not production-hardened / no external security review.** Treat accordingly.
- Run **behind TLS**; never expose plaintext over a network.
- Protect the **unseal shares** and the **auto-unseal KEK** — they are the keys to
  everything. Losing all of them means unrecoverable data.
- Use **separate instances per environment** (sandbox / dev / prod). Do not share
  one instance across trust boundaries.
- Issue **scoped tokens** with least-privilege policies; avoid using the root
  token for routine work.
- Enable **audit logging** (`-audit-log`) and monitor it; note that a full or
  unavailable audit sink is fail-closed and will stop the vault from serving.
- Consider **rate limiting** (`-rate-limit <req/s>`) to blunt brute-force against
  unseal shares and tokens. Behind a proxy, add `-rate-limit-trust-forwarded`
  (chart: `rateLimit.trustForwarded`) so limits key on the real client rather
  than the proxy IP. Health, metrics, and the console are exempt.
- **Pass secrets by environment, not flags.** The auto-unseal KEK and the
  transit-seal token accept flags for convenience, but a value on the command
  line is visible in the process list (`ps`). Prefer the environment variables
  (`UBIXVAULT_AUTO_UNSEAL_KEY`, `UBIXVAULT_SEAL_TRANSIT_TOKEN`) — which is what
  the Helm chart uses (sourced from Secrets).
