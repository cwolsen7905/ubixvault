# Item 288: stop Kelpie's CI read token from reading `kelpie/dev/app`

Status: plan only. Nothing here was applied; no vault was contacted (no vault access in this lane).

## Finding: this is a live-vault change, not a file change

The policy `kelpie-ci-ro` is **not defined in any repo**. It was searched for in `ubixvault`
(`origin/main`), `ubixkelpie` (`dev`, `origin/main`, all worktrees), `ubixcore` (tag `v0.47.0`)
and `kubernetes`; the only mentions are prose. It exists only as an ACL policy on the dev and prod
vault servers (`vault.dev.ubixsys.com`, `vault.prod.ubixsys.com`), so **the person applies it**.
Nothing is to be changed from a lane.

Where it is referenced (documentation only, ubixkelpie):

- `.gitlab-ci.yml:14-16` – "CI reads secret/kelpie/{db-<tier>,test-db} with UBIXVAULT_CI_TOKEN_DEV / _PROD (policy kelpie-ci-ro)".
- `docs/operations/database.md:47` – "policy `kelpie-ci-ro`: read `secret/kelpie/*`".
- `docs/operations/ci-variables.md` – lists `UBIXVAULT_CI_TOKEN_DEV` / `_PROD`.

Not verified: the live policy text. The documented grant is the single glob below; the live
policy may differ, so read it first (step 1 of Apply).

## Current grant (as documented)

```json
{"path": {"secret/data/kelpie/*": {"capabilities": ["read"]}}}
```

That covers every Kelpie secret on the vault, so the token can read, among others:

| Path | Vault | Should CI read it? |
|---|---|---|
| `kelpie/dev/app` | dev | **No** (runtime secrets: `KELPIE_BOT_GITLAB_TOKEN`, `OPENROUTER_API_KEY`, ...) |
| `kelpie/dev/db`, `kelpie/staging/db`, `kelpie/staging/app` | dev (staging uses vault.dev) | No (pod secrets) |
| `kelpie/prod/app`, `kelpie/prod/db` | prod | No (same problem on the prod token; see Scope) |

## What CI actually reads

From ubixcore `v0.47.0` (`ci/ubixcore-pipeline.yml`, `ci/bin/lib/notify.sh`) with
`UBIX_VAULT_PREFIX: kelpie`, KV v2 at mount `secret`:

| Path | Used by | Required? |
|---|---|---|
| `kelpie/db-<tier>` (`db-dev`, `db-staging` on dev vault; `db-prod` on prod vault) | `migrate-verify/apply-<tier>`, deploy | yes |
| `kelpie/test-db` | `phpunit-<tier>` | yes |
| `kelpie/composer` | runtime image build (falls back to `CI_JOB_TOKEN` if absent) | optional |
| `kelpie/discord` | notify (falls back to `secret/ubixcore/discord`, then env) | optional |
| `ubixcore/discord` | notify fallback | optional |

Branch to vault: `dev` and `staging` use the dev vault and `UBIXVAULT_CI_TOKEN_DEV`
(`UBIX_STAGING_VAULT: dev`); `main` uses the prod vault and `UBIXVAULT_CI_TOKEN_PROD`. The two tokens
share the policy name but live on different servers, so the policy is edited on each.

## Narrowed policy (exact paths)

`kelpie-ci-ro` on **vault.dev** (and the same on **vault.prod**; entries for absent paths are harmless):

```json
{
  "path": {
    "secret/data/kelpie/db-dev":      {"capabilities": ["read"]},
    "secret/data/kelpie/db-staging":  {"capabilities": ["read"]},
    "secret/data/kelpie/db-prod":     {"capabilities": ["read"]},
    "secret/data/kelpie/test-db":     {"capabilities": ["read"]},
    "secret/data/kelpie/composer":    {"capabilities": ["read"]},
    "secret/data/kelpie/discord":     {"capabilities": ["read"]},
    "secret/data/ubixcore/discord":   {"capabilities": ["read"]}
  }
}
```

No globs, so `kelpie/dev/*`, `kelpie/staging/*` and `kelpie/prod/*` are all denied. A path listed
here that CI doesn't need is a leak, so drop `db-prod` from the dev vault's copy and
`db-dev`/`db-staging` from the prod vault's copy if the person prefers a tighter fit (recommended:
dev vault gets `db-dev`, `db-staging`, `test-db`; prod vault gets `db-prod`, `test-db`; both get the
optional three if those secrets exist there).

Scope note: the item names `kelpie/dev/app`. The same narrowing also removes the prod token's read of
`kelpie/prod/app` (the webhook secret etc.), which is the same exposure. This plan treats that as in scope;
the person should confirm.

## Apply (the person; live change)

Using an admin token, per vault (dev, then prod):

1. Save the current policy first: `GET $VAULT/v1/sys/policies/acl/kelpie-ci-ro` to a file kept outside the repo.
2. `PUT $VAULT/v1/sys/policies/acl/kelpie-ci-ro` with the JSON above.
3. Do not rotate or reissue the tokens; they keep the policy by name.

## Verify

Using the existing CI token (`UBIXVAULT_CI_TOKEN_DEV`) against `https://vault.dev.ubixsys.com`; never print it:

```sh
H="X-Vault-Token: $UBIXVAULT_CI_TOKEN_DEV"; V=https://vault.dev.ubixsys.com/v1/secret/data
for p in kelpie/db-dev kelpie/db-staging kelpie/test-db; do
  printf '%s -> ' "$p"; curl -s -o /dev/null -w '%{http_code}\n' -H "$H" "$V/$p"; done   # expect 200
for p in kelpie/dev/app kelpie/dev/db kelpie/staging/app kelpie/prod/app; do
  printf '%s -> ' "$p"; curl -s -o /dev/null -w '%{http_code}\n' -H "$H" "$V/$p"; done   # expect 403
```

Then repeat on `vault.prod` with `UBIXVAULT_CI_TOKEN_PROD` (`kelpie/db-prod`, `kelpie/test-db` 200; `kelpie/prod/app` 403).
Also `GET /v1/sys/capabilities-self` (v1.7.0) with the CI token on `secret/data/kelpie/dev/app` shows no `read`.

CI check: run a pipeline on `dev` in ubixkelpie and confirm `phpunit-dev`, `migrate-verify-dev` and the
notify step still pass; on `staging` for `db-staging`; for prod, the next `main` pipeline's
`migrate-verify-prod` (manual apply stays the release click). A 403 shows up as
"no db-<tier> credentials from vault" or "no test-db credentials from vault".

## Rollback

`PUT` the saved policy from Apply step 1 (or `{"path":{"secret/data/kelpie/*":{"capabilities":["read"]}}}`)
back to `sys/policies/acl/kelpie-ci-ro` on the affected vault. Effect is immediate; no token changes.

## Follow-ups (file changes, a lane can be opened once the live change is done)

- Repo `ubixkelpie`, files `docs/operations/database.md` (line 47, the `secret/kelpie/*` text) and `.gitlab-ci.yml` (comment lines 14-16): record the exact narrowed paths. Docs only.
- Do not do this before the live change, or the docs will be wrong.
- If the person wants the policy kept in code, a new home (for example `ubixkelpie` `ops/vault/kelpie-ci-ro.json` or the `kubernetes` repo's vault configure step) would need a decision; today it is not in any repo.
