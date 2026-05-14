# RAXIS

> **R**untime **A**ttestation e**X**change for **I**ntelligent **S**ystems
> — Structural confinement kernel for autonomous AI agents.

Twelve non-negotiable invariants enforce that intelligence can't do
anything authority didn't structurally permit. Isolated microVMs,
cryptographic audit chains, credential proxies, fail-closed intent
admission. See [`raxis/specs/invariants.md`](raxis/specs/invariants.md)
for the full invariant catalogue and [`raxis/README.md`](raxis/README.md)
for a project-level overview.

## Repository layout

```
.
├── raxis/         # Rust workspace — kernel, planner-core, ipc, audit, store, dashboard backend, …
├── raxis-site/    # Marketing & docs site (Next.js)
├── .github/       # GitHub Actions (build-images, release, spec-graph) + branch-protection script
├── LICENSE        # SSPL — see raxis/LICENSE-SSPL.txt for the full SSPL text
└── README.md
```

`raxis/` is a self-contained Cargo workspace; `raxis-site/` is a
self-contained Next.js project that mirrors `raxis/specs/` /
`raxis/guides/` for the public docs site at <https://raxis.io>.

## Building

```sh
# Rust kernel + crates
cd raxis && cargo build --workspace

# Marketing site
cd raxis-site && npm install && npm run dev
```

The `.github/workflows/` jobs run from the repository root with
`working-directory: raxis` for Rust steps and from `raxis-site/`
for the site build — no path rewriting needed.

## License

SSPL-1.0. See [`LICENSE`](LICENSE) (the SSPL header) and
[`raxis/LICENSE-SSPL.txt`](raxis/LICENSE-SSPL.txt) (the full SSPL text).

Contributions require sign-off via the project CLA: see
[`raxis/CLA.md`](raxis/CLA.md).

## Provenance

This repository was split out of `chika5105/aegis-ai` on
2026-05-14 to give RAXIS its own independent repository identity.
The `raxis/` and `.github/` history was migrated verbatim with
`git filter-repo` (preserving the `main` branch only); `raxis-site/`
was joined as a `git subtree` so its 28 commits are fully reachable
under that prefix. The original `chika5105/aegis-ai` repository
remains in place as a read-only fallback.
