# Reviewer quickstart

A one-page path to a running uBix Vault and its tests, for security reviewers.
Pairs with the scope in [`docs/security/audit-scope.md`](security/audit-scope.md)
and the threat model in [`docs/DESIGN.md`](DESIGN.md) §5.

## Build

```sh
go build -o bin/ubixvault ./cmd/ubixvault    # Go 1.24; static, CGO-free
```

## Happy path (file storage, loopback plaintext)

The server binds `127.0.0.1:8200` by default; on loopback it serves plain HTTP
(TLS is required only on non-loopback addresses).

```sh
./bin/ubixvault server -data ./data -audit-log ./audit.log &
V=http://127.0.0.1:8200

# Initialize: 3 unseal shares, threshold 2. Save the keys + root token it returns.
curl -s -X POST $V/v1/sys/init -d '{"secret_shares":3,"secret_threshold":2}'

# Unseal with two shares (k0, k1 from the init response).
curl -s -X POST $V/v1/sys/unseal -d '{"key":"<k0>"}'
curl -s -X POST $V/v1/sys/unseal -d '{"key":"<k1>"}'
curl -s $V/v1/sys/seal-status                       # sealed:false

# Write + read a secret (T = the root token).
T=<root_token>
curl -s -H "X-Vault-Token: $T" -X POST $V/v1/secret/data/app -d '{"data":{"api_key":"sk-123"}}'
curl -s -H "X-Vault-Token: $T" $V/v1/secret/data/app
```

Routes are registered in `internal/api/sys.go` (Vault-compatible `/v1/*`). There
is a read-only web console at `/ui/`.

## MySQL/MariaDB storage backend

```sh
docker run --rm -e MARIADB_ROOT_PASSWORD=root -e MARIADB_DATABASE=ubixvault \
  -p 3306:3306 mariadb:11
# The vault creates its own tables.
./bin/ubixvault server \
  -storage mysql \
  -storage-mysql-dsn 'root:root@tcp(127.0.0.1:3306)/ubixvault' &
# then init/unseal as above. Inspect the DB: every value is barrier ciphertext.
```

## External (KMS/HSM) seal — auto-unseal path

```sh
cat > /tmp/kmsseal.sh <<'EOF'
#!/bin/sh
case "$1" in wrap) openssl base64 -A ;; unwrap) openssl base64 -A -d ;; esac
EOF
chmod +x /tmp/kmsseal.sh
./bin/ubixvault server -data ./data2 -seal-external-command /tmp/kmsseal.sh &
# init once (wraps the master key via the command), then restart the server:
# it logs "auto-unsealed" and comes back unsealed (the command unwrapped the key).
```

## Tests, fuzzing, and scanners

```sh
go test ./...                                   # unit + property tests + fuzz seed corpora
go test -race ./internal/barrier/... ./internal/core/...

# Integration (real MariaDB); build tag + DSN env, as CI runs it:
UBIXVAULT_MARIADB_DSN='root:root@tcp(127.0.0.1:3306)/ubixvault' \
  go test -tags integration ./internal/database/... ./internal/storage/...

# Fuzz a parser directly (targets: internal/policy, internal/jwtauth, internal/transit, internal/snapshot):
go test -run=x -fuzz=FuzzParseDocument -fuzztime=60s ./internal/policy/

golangci-lint run ./...                         # config: .golangci.yml
govulncheck ./...
```

## Where the crown jewels live

| Area | Path |
|------|------|
| Encryption barrier (AEAD, AAD, rekey) | `internal/barrier` |
| Shamir (GF(2⁸)) + seal state machine | `internal/shamir`, `internal/core` |
| Seals (KEK / transit / external) | `internal/seal` |
| ACL + in-house HCL parser | `internal/policy` |
| Tokens & leases | `internal/token` |
| Auth methods (JWT/OIDC, AppRole, userpass, k8s) | `internal/jwtauth`, `internal/approle`, `internal/userpass`, `internal/kubeauth` |
| Audit (fail-closed, HMAC) | `internal/audit` |
| Storage (file, MySQL) | `internal/storage` |
