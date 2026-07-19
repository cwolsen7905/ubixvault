# uBix Vault — Positioning & Prior Art

> **Status:** Draft — pre-implementation design · 2026-07-18
> Why this project exists alongside HashiCorp Vault and OpenBao.

## Prior art (acknowledged up front)

Secrets management is a mature space with strong existing implementations, and it's worth
being clear about them:

- **HashiCorp Vault** — the reference implementation and uBix Vault's API-compatibility
  target. Relicensed from MPL 2.0 to the source-available **BUSL** in 2023; now IBM-owned.
- **OpenBao** — the MPL 2.0, Linux Foundation fork of Vault's last open version. A drop-in,
  actively-maintained, fully open secrets manager. For a production deployment that just
  needs an open Vault, OpenBao is the right choice.

## Why build uBix Vault

uBix Vault is a lightweight, from-scratch secrets manager with full control over its design
and footprint. It originated to provide secrets management for
[uBixCore](https://github.com/cwolsen7905/uBixCore), but it is framework-agnostic and works with
any stack over its HTTP API. The reasons to build rather than adopt:

- **First-class uBixCore support, without coupling.** Purpose-built to integrate cleanly
  with uBixCore, while remaining a general-purpose secrets manager any project can use.
- **Lightweight and opinionated.** A small, focused core — the parts that matter most —
  instead of the full breadth (and operational weight) of Vault/OpenBao.
- **Full design control.** Owning the barrier, seal/unseal, policy, and lease-lifecycle
  design end-to-end, so the system can evolve with its users' needs.

## Scope philosophy

Depth over breadth: a small, finished, tested, well-documented core rather than a partial
clone chasing feature parity. The committed scope and the optional extensions are separated
explicitly in `docs/ROADMAP.md`, with the reasoning in `docs/DECISIONS.md` (D-004).

## What this project is *not*

- Not a drop-in replacement for the full Vault/OpenBao feature set — see the roadmap's
  committed-vs-extension split.
- Not aiming to displace Vault or OpenBao — for general production use, prefer those.
