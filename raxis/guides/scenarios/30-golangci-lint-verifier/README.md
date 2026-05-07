# Scenario 30 — golangci-lint Verifier

> **Complexity:** ⭐⭐ Intermediate | **Wall clock:** ~10 min | **Provider:** Anthropic

A Go project gated on `golangci-lint`.

---

## Prerequisites

Same as scenario 04 plus a Go 1.22+ install and `golangci-lint` on
$PATH.

---

## What this scenario demonstrates

- A Go-toolchain mechanical witness.

---

## Repository setup

```bash
export DEMO_ROOT="/tmp/raxis-scenario-30"
rm -rf "$DEMO_ROOT" && mkdir -p "$DEMO_ROOT"
cd "$DEMO_ROOT"

git init -q
go mod init demo30 > /dev/null 2>&1
cat > main.go <<'GO'
package main
import "fmt"
func main() { fmt.Println("hi") }
GO
git -c user.email=demo@raxis.local -c user.name=Demo add . > /dev/null
git -c user.email=demo@raxis.local -c user.name=Demo commit -qm "init"
```

---

## Run it

```bash
raxis plan validate ./plan.toml
raxis submit plan ./plan.toml --no-dry-run
INIT_ID="$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')"
raxis plan approve "$INIT_ID"
```
