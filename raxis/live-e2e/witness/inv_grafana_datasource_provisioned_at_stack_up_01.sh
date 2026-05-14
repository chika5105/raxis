#!/usr/bin/env bash
# inv_grafana_datasource_provisioned_at_stack_up_01.sh
#
# Witness for INV-GRAFANA-DATASOURCE-PROVISIONED-AT-STACK-UP-01:
#
#   After `docker compose up --wait` returns on the extended-e2e
#   stack, Grafana MUST have the Prometheus datasource registered
#   at uid `prometheus` AND all eleven raxis dashboards loaded under
#   the `raxis` folder, and the datasource MUST be able to proxy
#   a `up` query through to Prometheus successfully.
#
# This script is the live-stack counterpart to the Rust unit tests
# that witness the per-metric observability invariants — Grafana
# provisioning is necessarily a container-runtime contract (YAML
# files on a bind mount, applied by the Grafana process during
# its startup), so the witness has to run against a real container.
#
# Usage:
#
#   live-e2e/witness/inv_grafana_datasource_provisioned_at_stack_up_01.sh
#       Use whatever extended-e2e stack is currently up.
#       Exits 1 if the stack is not up.
#
#   live-e2e/witness/inv_grafana_datasource_provisioned_at_stack_up_01.sh --bounce
#       `docker compose down -v` then `up -d --wait` the extended
#       stack from a clean slate (wipes the named volumes so the
#       provisioning runs against a fresh Grafana DB), then verify.
#       This is the cold-boot path the invariant actually pins.
#
# Exit codes:
#   0  every assertion passes
#   1  at least one assertion failed (diagnostics printed)
#   2  prerequisites missing (curl / jq / docker / stack not up)
#
# Stack-touch contract:
#   * `curl` GETs only — never writes to Grafana.
#   * Without `--bounce`, leaves the stack untouched.
#   * With `--bounce`, the stack is left UP at exit (operator can
#     keep poking at it).

set -u
set -o pipefail

# ---------------------------------------------------------------------------
# CLI

BOUNCE=0
for arg in "$@"; do
    case "$arg" in
        --bounce)   BOUNCE=1 ;;
        -h|--help)
            sed -n '1,/^set -u/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown flag: $arg" >&2
            echo "usage: $0 [--bounce]" >&2
            exit 2
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Constants — keep in lockstep with raxis/live-e2e/docker-compose.extended.e2e.yml

PROJECT="raxis-live-e2e-test"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$HERE/../docker-compose.extended.e2e.yml"
GRAFANA_BASE="http://127.0.0.1:3000"
# Pinned admin creds — must match GF_SECURITY_ADMIN_USER /
# GF_SECURITY_ADMIN_PASSWORD in the compose file. Hard-coded here
# because the witness's whole point is that the canonical creds
# work; if you rotate the admin password, rotate it here in the
# same commit.
GRAFANA_USER="admin"
GRAFANA_PASS="raxis-e2e"
# uid pinned in
# raxis/observability/grafana/provisioning/datasources/prometheus.yaml
# AND referenced by every dashboard JSON's `datasource.uid`.
DATASOURCE_UID="prometheus"
DATASOURCE_TYPE="prometheus"
DATASOURCE_URL="http://prometheus:9090"
EXPECTED_DASHBOARDS=11
OVERVIEW_UID="raxis-00-overview"
OVERVIEW_TITLE_SUBSTR="00 Overview"

EXPECTED_DASHBOARD_UIDS=(
    "raxis-00-overview"
    "raxis-10-isolation"
    "raxis-15-ipc"
    "raxis-20-lifecycle"
    "raxis-30-audit"
    "raxis-40-planner"
    "raxis-50-credproxies"
    "raxis-60-egress"
    "raxis-70-dashboard"
    "raxis-80-budget-reviewer"
    "raxis-90-git"
)

# ---------------------------------------------------------------------------
# Helpers

PASS_COUNT=0
FAIL_COUNT=0
FAIL_LINES=()

bold()    { printf '\033[1m%s\033[0m\n' "$*"; }
green()   { printf '\033[32m%s\033[0m'   "$*"; }
red()     { printf '\033[31m%s\033[0m'   "$*"; }

pass() {
    local msg="$1"
    PASS_COUNT=$((PASS_COUNT + 1))
    printf '  %s %s\n' "$(green PASS)" "$msg"
}

fail() {
    local msg="$1"
    local detail="${2:-}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf '  %s %s\n' "$(red FAIL)" "$msg"
    if [ -n "$detail" ]; then
        printf '       %s\n' "$detail"
    fi
    FAIL_LINES+=("$msg")
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required tool: $1" >&2
        exit 2
    fi
}

require_tool curl
require_tool jq
require_tool docker

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "compose file not found: $COMPOSE_FILE" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Optional cold-boot

if [ "$BOUNCE" -eq 1 ]; then
    bold "[bounce] docker compose -p $PROJECT -f \$COMPOSE_FILE down -v"
    docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down -v >/dev/null
    bold "[bounce] docker compose -p $PROJECT -f \$COMPOSE_FILE up -d --wait"
    docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --wait >/dev/null
fi

# ---------------------------------------------------------------------------
# Sanity: stack must be up

if ! docker ps --filter "name=raxis-e2e-grafana" --filter "status=running" --format '{{.Names}}' \
        | grep -q '^raxis-e2e-grafana$'; then
    echo "raxis-e2e-grafana is not running." >&2
    echo "Bring the stack up with:" >&2
    echo "  docker compose -p $PROJECT -f $COMPOSE_FILE up -d --wait" >&2
    echo "or re-run this script with --bounce." >&2
    exit 2
fi

# Grafana health endpoint — re-check (compose --wait should have
# already gated on this, but a second probe makes the witness
# self-contained when the stack was brought up by another tool).
HEALTH=$(curl -fsS --max-time 5 "$GRAFANA_BASE/api/health" || true)
if ! echo "$HEALTH" | jq -e '.database == "ok"' >/dev/null 2>&1; then
    echo "Grafana /api/health did not report database=ok:" >&2
    echo "  $HEALTH" >&2
    exit 2
fi

bold "INV-GRAFANA-DATASOURCE-PROVISIONED-AT-STACK-UP-01 — witnessing against $GRAFANA_BASE"
echo

# ---------------------------------------------------------------------------
# §1 — Datasource is registered

bold "§1. Prometheus datasource is auto-provisioned"

DS_JSON=$(curl -fsS --max-time 5 \
    -u "$GRAFANA_USER:$GRAFANA_PASS" \
    "$GRAFANA_BASE/api/datasources" || true)

if [ -z "$DS_JSON" ]; then
    fail "GET /api/datasources returned empty body"
elif ! echo "$DS_JSON" | jq -e 'type == "array"' >/dev/null 2>&1; then
    fail "GET /api/datasources did not return a JSON array" "got: $(echo "$DS_JSON" | head -c 200)"
else
    DS_COUNT=$(echo "$DS_JSON" | jq 'length')
    if [ "$DS_COUNT" -lt 1 ]; then
        fail "no datasources registered" "GET /api/datasources returned []"
    else
        pass "GET /api/datasources returned $DS_COUNT datasource(s)"

        PROM_JSON=$(echo "$DS_JSON" | jq --arg uid "$DATASOURCE_UID" '.[] | select(.uid == $uid)')
        if [ -z "$PROM_JSON" ]; then
            fail "no datasource has uid=$DATASOURCE_UID" "registered uids: $(echo "$DS_JSON" | jq -r 'map(.uid) | join(",")')"
        else
            pass "found datasource with uid=$DATASOURCE_UID"

            check_field() {
                local field="$1"
                local want="$2"
                local got
                got=$(echo "$PROM_JSON" | jq -r ".$field")
                if [ "$got" = "$want" ]; then
                    pass "datasource.$field = $want"
                else
                    fail "datasource.$field mismatch" "want=$want got=$got"
                fi
            }

            check_field type      "$DATASOURCE_TYPE"
            check_field access    "proxy"
            check_field url       "$DATASOURCE_URL"
            check_field isDefault "true"
            check_field readOnly  "true"
        fi
    fi
fi

echo

# ---------------------------------------------------------------------------
# §2 — All 11 raxis dashboards are loaded under the raxis folder

bold "§2. All $EXPECTED_DASHBOARDS raxis dashboards are auto-provisioned"

DASH_JSON=$(curl -fsS --max-time 5 \
    -u "$GRAFANA_USER:$GRAFANA_PASS" \
    "$GRAFANA_BASE/api/search?type=dash-db&folderUIDs=raxis" || true)

if ! echo "$DASH_JSON" | jq -e 'type == "array"' >/dev/null 2>&1; then
    fail "GET /api/search?folderUIDs=raxis did not return a JSON array" "got: $(echo "$DASH_JSON" | head -c 200)"
else
    DASH_COUNT=$(echo "$DASH_JSON" | jq 'length')
    if [ "$DASH_COUNT" -ne "$EXPECTED_DASHBOARDS" ]; then
        fail "raxis folder has $DASH_COUNT dashboards, want $EXPECTED_DASHBOARDS" \
             "uids: $(echo "$DASH_JSON" | jq -r 'map(.uid) | join(",")')"
    else
        pass "raxis folder has exactly $EXPECTED_DASHBOARDS dashboards"
    fi

    REGISTERED_UIDS=$(echo "$DASH_JSON" | jq -r 'map(.uid) | sort | join("\n")')
    for want_uid in "${EXPECTED_DASHBOARD_UIDS[@]}"; do
        if echo "$REGISTERED_UIDS" | grep -qx "$want_uid"; then
            pass "dashboard $want_uid is provisioned"
        else
            fail "dashboard $want_uid is MISSING" "registered uids: $(echo "$DASH_JSON" | jq -r 'map(.uid) | join(",")')"
        fi
    done
fi

echo

# ---------------------------------------------------------------------------
# §3 — Overview dashboard is fetchable by uid and has its canonical title

bold "§3. Overview dashboard is fetchable by uid"

OV_JSON=$(curl -fsS --max-time 5 \
    -u "$GRAFANA_USER:$GRAFANA_PASS" \
    "$GRAFANA_BASE/api/dashboards/uid/$OVERVIEW_UID" || true)

if ! echo "$OV_JSON" | jq -e '.dashboard.title' >/dev/null 2>&1; then
    fail "GET /api/dashboards/uid/$OVERVIEW_UID did not return a dashboard envelope" \
         "got: $(echo "$OV_JSON" | head -c 200)"
else
    TITLE=$(echo "$OV_JSON" | jq -r '.dashboard.title')
    case "$TITLE" in
        *"$OVERVIEW_TITLE_SUBSTR"*) pass "dashboard.title=\"$TITLE\" matches \"*$OVERVIEW_TITLE_SUBSTR*\"" ;;
        *) fail "dashboard.title mismatch" "want substring \"$OVERVIEW_TITLE_SUBSTR\", got \"$TITLE\"" ;;
    esac
fi

echo

# ---------------------------------------------------------------------------
# §4 — Datasource proxies a Prometheus query end-to-end
#
# This catches the "datasource URL points at the wrong host" gotcha:
# if the YAML's `url:` were `http://127.0.0.1:9090` or
# `http://localhost:9090`, the datasource would still register, but
# the proxy query would 502 because those names resolve to the
# Grafana container itself, not Prometheus.

bold "§4. Datasource can proxy a Prometheus query"

PROXY_JSON=$(curl -fsS --max-time 5 \
    -u "$GRAFANA_USER:$GRAFANA_PASS" \
    "$GRAFANA_BASE/api/datasources/proxy/uid/$DATASOURCE_UID/api/v1/query?query=up" || true)

if ! echo "$PROXY_JSON" | jq -e '.status == "success"' >/dev/null 2>&1; then
    fail "proxy /api/v1/query?query=up did not return status=success" \
         "got: $(echo "$PROXY_JSON" | head -c 200)"
else
    pass "proxy /api/v1/query?query=up returned status=success"
    SERIES=$(echo "$PROXY_JSON" | jq '.data.result | length')
    if [ "$SERIES" -lt 1 ]; then
        fail "proxy /api/v1/query?query=up returned zero series" \
             "Prometheus has no scrape targets up — dashboards will be empty"
    else
        pass "proxy /api/v1/query?query=up returned $SERIES series (Prometheus is scraping)"
    fi
fi

echo

# ---------------------------------------------------------------------------
# Summary

bold "Summary"
printf '  %d checks passed\n' "$PASS_COUNT"
if [ "$FAIL_COUNT" -eq 0 ]; then
    printf '  %s\n' "$(green "INV-GRAFANA-DATASOURCE-PROVISIONED-AT-STACK-UP-01 — HOLDS")"
    exit 0
else
    printf '  %d checks failed:\n' "$FAIL_COUNT"
    for line in "${FAIL_LINES[@]}"; do
        printf '    - %s\n' "$line"
    done
    printf '  %s\n' "$(red "INV-GRAFANA-DATASOURCE-PROVISIONED-AT-STACK-UP-01 — VIOLATED")"
    exit 1
fi
