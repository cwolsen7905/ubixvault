# uBix Vault Helm chart

Deploys a **single-node** uBix Vault to Kubernetes.

> **Beta / single-node.** There is no Raft HA yet and no external security
> review. This chart is for sandbox / dev / internal use, not a production HA
> deployment. It runs exactly one replica and refuses `replicaCount > 1`.

## Prerequisites

- Kubernetes ≥ 1.24
- A container image built from the repo-root `Dockerfile`, pushed somewhere your
  cluster can pull. No image is published yet — build and push your own:

  ```sh
  docker build -t <your-registry>/ubixvault:0.2.0-beta.1 \
    --build-arg VERSION=0.2.0-beta.1 .
  docker push <your-registry>/ubixvault:0.2.0-beta.1
  ```
- A `StorageClass` for the encrypted data volume (or an existing PVC).
- For TLS: either a `kubernetes.io/tls` Secret, or cert-manager.

## Install

```sh
# Minimal (TLS via an existing Secret, auto-unseal via an existing Secret):
helm install vault ./deploy/charts/ubixvault \
  --namespace ubixvault --create-namespace \
  --set image.repository=<your-registry>/ubixvault \
  --set tls.existingSecret=ubixvault-tls \
  --set autoUnseal.existingSecret=ubixvault-kek
```

Create the auto-unseal KEK Secret first (32 random bytes, 64 hex chars):

```sh
kubectl -n ubixvault create secret generic ubixvault-kek \
  --from-literal=auto-unseal-key="$(head -c32 /dev/urandom | xxd -p | tr -d '\n')"
```

Then **initialize once** — see the post-install notes (`helm status`), or:

```sh
kubectl -n ubixvault exec -it vault-ubixvault-0 -- \
  ubixvault operator init -shares 5 -threshold 3    # save the shares + root token
```

## Design notes

- **StatefulSet, 1 replica** with a `volumeClaimTemplate` for the encrypted data
  directory. The chart hard-fails on `replicaCount > 1` because there is no HA.
- **Auto-unseal first.** In Kubernetes, Shamir unseal after every restart is
  painful, so auto-unseal (a KEK in a Secret) is the default. Shamir still works
  — set `autoUnseal.enabled=false` and unseal manually via `kubectl exec`.
- **Probes are split on purpose.** A sealed vault returns `503` on
  `/v1/sys/health`. Liveness is therefore a **TCP** check (process is up), so a
  sealed-but-alive pod is not crash-looped; **readiness** is an httpGet on the
  health endpoint, so only an unsealed vault (`200`) receives traffic.
- **Kubernetes auth method.** When `kubernetesAuth.enabled` (default), the
  release's ServiceAccount is bound to `system:auth-delegator` so the vault can
  validate pod ServiceAccount tokens via TokenReview.
- **TLS.** With `tls.enabled` (default) the server serves HTTPS from a mounted
  Secret. Disabling TLS requires `devNoTLS=true` and is INSECURE.
- **Audit is off by default** and fail-closed: enable it with a dedicated volume
  (`audit.enabled=true`), never sharing the data disk.
- **Ingress is optional and encrypted end to end.** When `ingress.enabled`, the
  Ingress is annotated `backend-protocol: HTTPS` so ingress-nginx re-encrypts to
  the vault (which serves HTTPS) — the ingress never sees plaintext secrets. A
  secrets manager is sensitive: prefer internal access, or lock it down with
  `ingress.whitelistSourceRange`.
- **Hardened pod:** non-root (uid 65532), read-only root filesystem, all
  capabilities dropped, `RuntimeDefault` seccomp.

## Key values

| Key | Default | Description |
|-----|---------|-------------|
| `replicaCount` | `1` | Must be 1 (single-node). |
| `image.repository` | `ghcr.io/cwolsen7905/ubixvault` | Build/push your own; no official image yet. |
| `image.tag` | `""` | Defaults to the chart `appVersion`. |
| `persistence.enabled` / `.size` | `true` / `1Gi` | Encrypted data volume. |
| `autoUnseal.enabled` | `true` | Wrap the master key with a KEK for self-unseal. |
| `autoUnseal.existingSecret` | `""` | Secret holding the KEK (key `auto-unseal-key`). |
| `tls.enabled` | `true` | Serve HTTPS. |
| `tls.existingSecret` | `""` | `kubernetes.io/tls` Secret to mount. |
| `tls.certManager.enabled` | `false` | Issue the cert via cert-manager instead. |
| `devNoTLS` | `false` | Allow plaintext on a non-loopback address (INSECURE). |
| `audit.enabled` | `false` | Fail-closed audit log; use a dedicated volume. |
| `kubernetesAuth.enabled` | `true` | Bind SA to `system:auth-delegator`. |
| `service.type` / `.port` | `ClusterIP` / `8200` | In-cluster Service. |
| `ingress.enabled` | `false` | Expose over an Ingress (requires `tls.enabled`). |
| `ingress.host` | `""` | Hostname, e.g. `vault.prod.ubixsys.com`. |
| `ingress.tlsSecret` | `""` | TLS Secret in this namespace (e.g. a Replikate-synced wildcard). |
| `ingress.whitelistSourceRange` | `""` | Optional CIDR allow-list to restrict access. |

See [`values.yaml`](values.yaml) for the full list.

## Backups

Snapshots are encrypted and safe to store at rest:

```sh
kubectl -n ubixvault exec -it vault-ubixvault-0 -- \
  ubixvault operator snapshot save /var/lib/ubixvault/backup.snapshot
```

Restoring still requires the unseal shares or the KEK. See the top-level
[`docs/DEPLOYMENT.md`](../../../docs/DEPLOYMENT.md).
