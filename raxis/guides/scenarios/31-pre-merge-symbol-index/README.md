# Scenario 31 — Pre-Merge Symbol Index

> **Complexity:** ⭐⭐⭐ Advanced | **Wall clock:** ~12 min | **Provider:** Anthropic

A pre-merge verifier that walks the candidate merge tree and emits a
JSON index of every public symbol; the kernel attaches the index to
the IntegrationMerge audit. Once `raxis-verifier-runtime` lands, this
scenario showcases the full `[[plan.verifiers.pre_merge]]` flow.

> **Note (current state):** Until raxis-verifier-runtime ships, the
> kernel rejects any plan declaring pre-merge verifiers with
> `FAIL_VERIFIER_INVALID_ON_FAILURE`. This guide therefore documents
> the *intended* surface; ‹`raxis plan validate ./plan.toml`› will
> currently reject it.

---

## Prerequisites

Same as scenario 04.

---

## What this scenario demonstrates

- The `[[plan.verifiers.pre_merge]]` declaration surface.
- The `--strict` validate mode that catches placeholder verifiers.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-31"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

cargo init --lib --name demo31 -q
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

---

## Run it (after raxis-verifier-runtime lands)

```bash
raxis plan validate ./plan.toml
raxis submit plan ./plan.toml --no-dry-run
```

---

## Cross-references

- Spec: `specs/v2/integration-merge.md §Check 5d`.
