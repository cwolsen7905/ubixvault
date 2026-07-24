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

## 5. Health checks

`GET /v1/sys/health` is unauthenticated and encodes readiness in its status code
— point load balancers and liveness/readiness probes at it:

- `200` — initialized and unsealed (ready)
- `503` — sealed (not ready)
- `501` — not initialized

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

Recover a new root token from a quorum of unseal shares (Shamir mode; the vault
must be unsealed):

```sh
# Over the API: POST /v1/sys/generate-root/init returns a nonce, then
# POST /v1/sys/generate-root/update with the nonce + each unseal key until
# it returns a new root_token.
```

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
