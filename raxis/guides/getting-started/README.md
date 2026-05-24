# Getting Started with RAXIS

> **Audience.** A fresh operator on a clean macOS or Linux box who wants
> to run their first RAXIS initiative end-to-end.
>
> **Time budget.** 15 minutes from `brew install raxis` to "the kernel ran my
> plan, my file landed on `main`, the audit chain verifies".

Start with the lane that matches you:

| You are... | Use this path |
|---|---|
| **An operator / evaluator** who installed RAXIS from Homebrew | Start at the [website get-started flow](https://www.raxis.io/get-started), then use pages 01-02 for details. |
| **A source builder** who wants to compile RAXIS locally | Use [`../SETUP.md`](../SETUP.md), then return to page 02. |
| **A maintainer** changing release artifacts, bottles, or notarization | Use [`../../release/README.md`](../../release/README.md) and [`../../specs/v2/release-and-distribution.md`](../../specs/v2/release-and-distribution.md). |

Five short pages, in order. The Homebrew path skips all source-build
tooling: no Rust toolchain, no dashboard build, no image bake. The
bottle ships the CLI, kernel, gateway, dashboard bundle, canonical VM
images, and guest kernel.

| #   | Page                                               | What you do                                                                         | Time      |
| --- | -------------------------------------------------- | ----------------------------------------------------------------------------------- | --------- |
| 00  | [`00-overview.md`](00-overview.md)                 | Build the mental model: what RAXIS does, what it doesn't. Skim — no commands.       | 5 min     |
| 01  | [`01-prereqs.md`](01-prereqs.md)                   | Install with Homebrew and verify the shipped runtime bundle.                        | 2-5 min   |
| 02  | [`02-first-initiative.md`](02-first-initiative.md) | Genesis → start the kernel → submit a one-task plan → watch it complete.            | 10 min    |
| 03  | [`03-dashboard-tour.md`](03-dashboard-tour.md)     | Open the operator dashboard, walk the five views you'll use daily.                  | 5 min     |
| 04  | [`04-troubleshooting.md`](04-troubleshooting.md)   | The first ten things that go wrong, and the exact command to fix each.              | reference |

> **Already set up?** Jump straight to
> [`02-first-initiative.md`](02-first-initiative.md). The prereqs page
> ends with a single `raxis doctor` check; if it exits green you're
> ready.

---

## Beyond getting started

Once your first initiative completes:

- The fifty runnable end-to-end **scenarios** under
  [`../scenarios/`](../scenarios/) cover every shape of multi-task
  initiative (panel review, parallel decomposition, credential
  proxies, egress allowlists, crash recovery, …).
- The **recipe book** at [`../recipes/`](../recipes/) is the
  scope-one-concept-at-a-time reference: every CLI subcommand, every
  `policy.toml` section, every `plan.toml` field, every operational
  task.
- The **concepts** primer at [`../CONCEPTS.md`](../CONCEPTS.md) is the
  10-minute deep-dive on path allowlists, lane budgets, the agent-type
  model, and how agents talk through the kernel rather than to each
  other.
- The **specs** under [`../../specs/`](../../specs/) are normative —
  every claim a recipe makes is reproducible from a named section in
  the V1 or V2 spec set.
