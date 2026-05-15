# `raxis/release/` — release-pipeline assets

This directory holds the static assets the V2 release pipeline
consumes. **Normative reference:** `raxis/specs/v2/release-and-distribution.md`.

```text
release/
├── README.md                       — this file
├── raxis.entitlements              — macOS Virtualization.framework
│                                     entitlements consumed by `codesign`
│                                     (release-and-distribution.md §6.3)
├── templates/
│   ├── raxis-kernel.rb.tmpl        — Homebrew formula template for the
│   │                                 main kernel + planner-binaries +
│   │                                 canonical-images bundle
│   └── raxis-cli.rb.tmpl           — Homebrew formula template for the
│                                     standalone CLI (raxis-kernel-dependent)
└── scripts/
    ├── render-formula.sh           — populate templates with version +
    │                                 per-(os, arch) sha256 sums
    └── notarize.sh                 — codesign + notarytool + staple
                                      wrapper for the macOS bottle build
```

## Workflow

The two GitHub Actions workflows under `.github/workflows/`
consume this directory:

* `build-images.yml` (PR + main reproducibility check) — does NOT
  touch `release/scripts/` because no signing happens on PRs.
* `release.yml` (tag-driven signed release) — reads the
  entitlements file, runs `notarize.sh` per macOS bottle, and runs
  `render-formula.sh` once per architecture to emit the final
  `Formula/raxis-{kernel,cli}.rb` files that get force-pushed to
  `chika5105/homebrew-tap`.

Both workflows are spec'd at `release-and-distribution.md §5`.

## Local dry-run

```bash
# Render the templates locally with placeholder values to confirm
# the substitution works without running cargo or curl.
RAXIS_VERSION=0.1.0-dev \
RAXIS_DARWIN_ARM64_URL=https://example/raxis-darwin-arm64.tar.gz \
RAXIS_DARWIN_ARM64_SHA256=$(printf '%64s' 0 | tr ' ' '0') \
RAXIS_DARWIN_X86_64_URL=https://example/raxis-darwin-x86_64.tar.gz \
RAXIS_DARWIN_X86_64_SHA256=$(printf '%64s' 0 | tr ' ' '0') \
RAXIS_LINUX_ARM64_URL=https://example/raxis-linux-arm64.tar.gz \
RAXIS_LINUX_ARM64_SHA256=$(printf '%64s' 0 | tr ' ' '0') \
RAXIS_LINUX_X86_64_URL=https://example/raxis-linux-x86_64.tar.gz \
RAXIS_LINUX_X86_64_SHA256=$(printf '%64s' 0 | tr ' ' '0') \
RAXIS_REVIEWER_IMG_URL=https://example/raxis-reviewer-core.tar.gz \
RAXIS_REVIEWER_IMG_SHA256=$(printf '%64s' 0 | tr ' ' '0') \
RAXIS_ORCHESTRATOR_IMG_URL=https://example/raxis-orchestrator-core.tar.gz \
RAXIS_ORCHESTRATOR_IMG_SHA256=$(printf '%64s' 0 | tr ' ' '0') \
RAXIS_EXECUTOR_STARTER_IMG_URL=https://example/raxis-executor-starter.tar.gz \
RAXIS_EXECUTOR_STARTER_IMG_SHA256=$(printf '%64s' 0 | tr ' ' '0') \
release/scripts/render-formula.sh raxis-kernel
```

## Why these files live in-tree (not in the tap repo)

The formula **templates** live here so they version together with
the kernel binary they describe. A breaking change to the
binary's bottle layout (renaming `bin/raxis-tproxy` to
`libexec/raxis-tproxy`, for example) is a single PR that updates
both the binary code and the matching template. The tap repo
holds only the rendered formulas — products of this directory.
