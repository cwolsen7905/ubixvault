# uBix Vault — Deployment Guide

> **Status:** beta (`v0.2.0-beta`). uBix Vault is usable for real workloads but has
> not had an external security review. Read the [Security notes](#security-notes)
> before depending on it.

This guide covers running a single uBix Vault node. It assumes the `ubixvault`
binary (`go build -o ubixvault ./cmd/ubixvault`).

## 1. Storage

uBix Vault stores everything, encrypted, under a data directory:

```sh
ubixvault server -data /var/lib/ubixvault
```

Back this directory up (see [Backups](#5-backups)). It contains only ciphertext,
but losing it — or the means to unseal it — means losing the data.

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
the same disk as the data. (A pluggable cloud-KMS seal is on the roadmap; today
the KEK is supplied directly.)

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
