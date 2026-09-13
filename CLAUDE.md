# CLAUDE.md

Working notes for this repo. The authoritative docs are in `docs/` — this file is
the map plus the things that are easy to get wrong.

## Agent coordination — read first

More than one agent session may work this repo, and sibling repos hand work over
(notably `kubernetes`, which runs uBixVault in production).

**Before you branch, edit a shared file, or open a PR:** register your lane in
`AGENTS-COORD.md` at the repo root. It is **untracked per-sandbox state** — seed
it once with `cp AGENTS-COORD.template.md AGENTS-COORD.md` if missing. Committing
live coordination state causes cross-lane merge races, which is why it is
gitignored (pattern ported from `ubixcore`, originally `project-neptune`).

Check `AGENTS-COORD.md` §4 for **open cross-repo requests**. A request is not done
until you have answered it in §3 — the asker is polling, not listening. Agent
sessions cannot notify each other.

## What this is

A self-hosted secrets and encryption manager in Go: encrypted barrier, Shamir
seal/unseal, token auth with ACL policies, and a HashiCorp-Vault-compatible HTTP
API. `docs/POSITIONING.md` is honest about what is and is not covered — read it
before claiming parity with anything.

**API compatibility is a deliberate design decision** (ADR D-003), not a
coincidence. It is what lets existing Vault tooling work unmodified — including
External Secrets Operator, which the `kubernetes` repo plans to point at this.
Breaking the wire format breaks consumers that were never tested against this
codebase.

## Build and test

```sh
make help          # every target, self-documenting
make test          # go test -race -covermode=atomic, all packages
make cover         # total coverage, one line
make ci            # what CI runs — use this before pushing
make lint          # golangci-lint (installs if missing)
make vet fmtcheck  # cheap, run often
make vuln          # govulncheck
make integration   # integration tests (needs a real MySQL)
make fuzz          # fuzz the parsers
make helm-lint helm-template   # the chart in deploy/charts/ubixvault
```

Go 1.25, module `github.com/cwolsen7905/ubixvault`. `make test` runs with the race
detector — keep it that way; the concurrency here is load-bearing.

## Layout

`internal/` holds one package per concern: `core` (the brain), `barrier`,
`seal`, `shamir`, `storage`, `api`, `policy`, plus the engines (`kv`, `transit`,
`pki`, `database`, `cubbyhole`, `wrapping`, `identity`) and the auth methods
(`token`, `userpass`, `certauth`, `jwtauth`, `ldapauth`, `kubeauth`, `approle`).
`cmd/ubixvault` is the entry point. `deploy/charts/ubixvault` is the Helm chart.

## Git flow

**`main` is not written to directly.** Everything goes through a GitHub pull
request. Branch prefixes in use: `fix/*`, `docs/*`, `ci/*`.

Claim these in `AGENTS-COORD.md` §3 before editing — they are the usual collision
points: `README.md`, `CHANGELOG.md`, `docs/ROADMAP.md`, `docs/DECISIONS.md`,
`deploy/charts/ubixvault/*`, anything under `internal/core/`.

## Versioning — two things, deliberately separate

`docs/VERSIONING.md` is the authority, and the distinction matters enough to
restate: **the version number communicates public-interface stability, and nothing
about security assurance.** `1.0` means the API is stable. It does not mean an
external security review has happened — that is tracked separately in
`docs/ROADMAP.md` and is explicitly *not* a version gate.

Do not let a release note blur those two. Conflating them is how people end up
believing they are safer than they are.

## Decisions are recorded, not re-litigated

`docs/DECISIONS.md` is the ADR log. Before changing something structural, check
whether it was already decided and why — D-001 through D-018 cover the language,
MVP scope, Vault API compatibility, build-vs-OpenBao, the DB engine plugin
interface, engineering standards, SQL storage, and the external-command seal.

If you disagree with an ADR, write a new one superseding it. Do not quietly do
the other thing.

## Things that are easy to get wrong

- **Storage errors are not all the same.** A dial failure or `driver.ErrBadConn`
  is transient; a malformed key is not. As of 2026-09-12 `internal/storage/` does
  not distinguish them and has no retry, which crash-loops the process in
  production when MySQL blinks — see
  `docs/bugs/2026-09-12-storage-outage-crashloop.md`. Bear this in mind when
  touching storage.
- **`/v1/sys/livez` must never depend on storage.** `livez` answers "the process is
  alive"; `/v1/sys/health` answers "I can serve requests". If `livez` can be
  blocked by storage, Kubernetes kills the container during a storage outage, and
  on an auto-unseal deployment every restart is also an unseal cycle.
- **Every restart costs an unseal.** Treat crash-on-error as more expensive here
  than in an ordinary service.
- **The auto-unseal key cannot live in the vault.** Obvious once stated, easy to
  design around wrongly. Same for the storage DSN.
- **Release → docs.** Per the root `~/git/CLAUDE.md` convention, every uBixVault
  release means updating `ubixsys-web`, which carries the man-page-style public
  docs. Treat that as part of the release, not a follow-up.

## Who consumes this

The `kubernetes` repo runs `ubixvault-prod` and `ubixvault-dev` on a k3s cluster,
backed by external MySQL, with auto-unseal and the Kubernetes auth method already
configured. Its plan to make this the cluster's single source of truth for
credentials is in that repo at `docs/projects/secrets-management.md`. Changes to
the auth methods, the KV path shape, or the chart's probes affect it directly.
