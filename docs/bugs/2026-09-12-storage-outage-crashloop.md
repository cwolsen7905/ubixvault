# BUG: uBixVault crash-loops when MySQL storage has a brief outage

**Found:** 2026-09-12, in production on the BrainChurts k3s cluster
**Affects:** `0.2.0-beta.10` (deployed); code paths unchanged through `v1.0.0-rc.2`
**Severity:** availability — a secrets manager should survive its database blinking
**Wanted in:** `v1.0.0`, since `rc.1` and `rc.2` are already cut

> **This file is a handoff from the cluster side.** It is written to be
> self-contained: everything observed is below, so you should not need to go
> asking. When you have landed a fix, fill in [§ Reply](#reply-from-the-ubixvault-side)
> at the bottom — that is how the cluster side finds out, since agent sessions
> cannot notify each other.

## What happens

Both instances restart repeatedly: `ubixvault-prod-0` 5 times, `ubixvault-0`
(dev) 6 times, over ~12 days. Both point at the same external MySQL at
`10.50.25.45:3306`, which sits outside the Kubernetes cluster.

One full episode from the prod container log, 2026-09-09:

```
04:21:04 auto-unsealed
04:21:04 uBix Vault 0.2.0-beta.10 listening on https://0.0.0.0:8200 (storage: mysql)
07:03:41 api: internal error: core: read seal config: storage: mysql get: context canceled
07:03:51 api: internal error: core: read seal config: storage: mysql get: dial tcp 10.50.25.45:3306: operation was canceled
07:04:01 api: internal error: core: read seal config: storage: mysql get: dial tcp 10.50.25.45:3306: operation was canceled
   ... repeating every ~10s for roughly 90 seconds ...
07:04:42 api: internal error: core: read seal config: storage: mysql get: dial tcp 10.50.25.45:3306: operation was canceled
```

The container then terminated with **exit 255, reason `Unknown`**. In Kubernetes
that combination usually means the kubelet killed it rather than the process
choosing to exit.

Every restart is also an unseal cycle, which on a Shamir/auto-unseal deployment
is not free.

## Already ruled out — please do not spend time here

The connection pool is configured sensibly in `internal/storage/mysql.go`:

```go
db.SetMaxOpenConns(10)
db.SetMaxIdleConns(5)
db.SetConnMaxLifetime(3 * time.Minute)   // line 46
...
db.PingContext(ctx)                      // line 51
```

So this is **not** the classic stale-idle-connection bug, and `ConnMaxLifetime`
is not too long. The pool is fine.

## Two suspected defects

### 1. No retry on transient storage errors — confirmed absent

`grep -rn "retry\|backoff\|Retry" internal/storage/ internal/core/` returns
nothing. `MySQLBackend.Get` (`internal/storage/mysql.go:97`) wraps whatever it
gets and returns it:

```go
if err != nil {
    return nil, fmt.Errorf("storage: mysql get: %w", err)
}
```

There is no classification of retryable vs permanent. A dial failure or
`driver.ErrBadConn` is treated identically to a malformed key. `core.go:760`
then surfaces it as `core: read seal config`.

So a network blip fails **every** request for its whole duration rather than
being absorbed.

### 2. The process dies instead of degrading — suspected, NOT verified

The deployed StatefulSet has:

```yaml
livenessProbe:  { httpGet: /v1/sys/livez,  timeoutSeconds: 1, failureThreshold: 3, periodSeconds: 15 }
readinessProbe: { httpGet: /v1/sys/health, timeoutSeconds: 1, failureThreshold: 3, periodSeconds: 10 }
```

If `/v1/sys/livez` touches storage — or its handler can be blocked by storage
contention — then three consecutive 1-second timeouts during a MySQL outage get
the container SIGKILLed, which matches exit 255 / `Unknown` exactly.

**This part is unverified.** I could not find the `livez` handler from the
cluster side; it appears in `internal/api/audit.go:68`'s audit-exclusion list and
in tests, but I did not locate its implementation. **Check this first** — if
`livez` is already storage-independent then hypothesis 2 is wrong, the whole
cause is defect 1, and the probe theory should be discarded rather than worked
around.

The intended split is presumably the right one:

- `livez` — "the process is alive." Must not depend on storage.
- `health` — "I can serve requests." Should fail fast and clean (503, no hang)
  when storage is away, so readiness drops and traffic stops **without the
  process dying**.

A vault that returns 503 while its storage is unreachable is behaving correctly.
A vault that gets killed and restarts is not.

## What a fix should include

- Retry transient storage failures with bounded backoff, **classifying**
  retryable vs permanent rather than blanket-retrying.
- A guarantee that `/v1/sys/livez` cannot be affected by storage state.
- `/v1/sys/health` failing fast rather than hanging when storage is down.
- Tests. `internal/storage/` already has `conformance_test.go`,
  `mysql_unit_test.go` and `file_crash_test.go`, so there is an existing
  fault-injection pattern — please follow it rather than inventing another.
  Two cases worth having: a backend that fails N times then succeeds should see
  requests succeed; `livez` should stay 200 with the backend hard-down.
- A `CHANGELOG.md` entry — this is user-visible reliability behaviour.

## A design question that should be decided, not emergent

**Should a sustained storage outage eventually reseal?** Staying
unsealed-but-erroring indefinitely and resealing after some threshold are both
defensible, and they have different security properties. For a 1.0 this should be
a deliberate decision with a rationale in `docs/DECISIONS.md` (it is ADR-shaped),
not whatever the code happens to do. If the answer is "reseal", it needs to be in
the docs too.

## Cluster-side context

- Storage host `10.50.25.45` is outside the k3s cluster and outside that repo's
  inventory. Whether it is *itself* flaky is being investigated separately — but
  the vault should survive it either way, which is why this is filed as a vault
  bug and not an infrastructure one.
- The probe timeouts (`timeoutSeconds: 1`) come from this repo's chart. If you
  conclude they are simply too aggressive for any realistic storage latency, say
  so in the reply and the cluster side will raise them. The preference is for the
  server not to die in the first place rather than papering over it with a longer
  timeout.
- This bug is the **gate** on a cluster project to move credentials into uBixVault
  as a single source of truth (External Secrets Operator against the
  Vault-compatible API, Kubernetes auth). That work is deliberately blocked until
  this is fixed — nothing should depend on a secrets manager that cannot survive
  a storage blip.

## Reply from the uBixVault side

> Fill this in when a fix lands. The cluster side checks for: a tag newer than
> `v1.0.0-rc.2`, a `CHANGELOG.md` entry mentioning storage retry or probe
> behaviour, or a commit touching `internal/storage/mysql.go`.

- [ ] Fixed in: `<tag / commit>`
- [ ] Which hypothesis was right: `<1 only / 1 and 2 / something else>`
- [ ] Was `livez` storage-dependent? `<yes / no>`
- [ ] Reseal-on-sustained-outage decision: `<stays unsealed / reseals after N / ADR link>`
- [ ] Do the chart's probe timeouts need raising cluster-side? `<yes / no>`
- [ ] Anything the cluster side must change when upgrading: `<notes>`
