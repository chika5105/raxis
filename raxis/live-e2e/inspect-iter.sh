#!/usr/bin/env bash
# inspect-iter.sh — surface "what did iter N actually do" in one command.
#
# The realistic-scenario test (`extended_e2e_realistic_scenario::realistic_session_lifecycle`)
# tees its `cargo test` stderr to `/tmp/raxis-e2e-realistic-iter<N>.log`, but
# that file ONLY captures the harness preamble — the silent
# `poll_for_dual_lifecycle_completion` loop runs without printing anything.
# All actual task lifecycle events stream into the kernel daemon's stderr at
# `<data_dir>/kernel.stderr.log`, where `<data_dir>` is the per-iter
# ephemeral tmp dir printed in the cargo log's Tier-3 paths. This script
# joins those two artifacts and produces the summary you actually want:
#
#   - test verdict (running / ok / panic + reason)
#   - count + names of TaskCompleted intents
#   - failure-mode cluster (AVF spawn errors, deadlocks, planner HTTP 4xx, …)
#   - Tier-3 paths so you can drill in
#
# Usage:
#   live-e2e/inspect-iter.sh                    # latest iter
#   live-e2e/inspect-iter.sh 36                 # iter36
#   live-e2e/inspect-iter.sh latest --kernel    # also dump full kernel.stderr.log
#   live-e2e/inspect-iter.sh 36 --tasks         # also dump per-task intent envelopes
#   live-e2e/inspect-iter.sh 36 --planner-http  # also dump planner_fetch_response status_codes
#
# Exit code: 0 unless the iter explicitly FAILED (1) or the cargo log is
# missing entirely (2). "Still running" is exit 0 — the script is a probe,
# not a gate.

set -u

ITER_ARG="${1:-latest}"
shift || true

WANT_KERNEL=0
WANT_TASKS=0
WANT_PLANNER_HTTP=0
for flag in "$@"; do
    case "$flag" in
        --kernel)        WANT_KERNEL=1 ;;
        --tasks)         WANT_TASKS=1 ;;
        --planner-http)  WANT_PLANNER_HTTP=1 ;;
        *) echo "unknown flag: $flag" >&2; exit 2 ;;
    esac
done

if [[ "$ITER_ARG" == "latest" ]]; then
    CARGO_LOG=$(ls -1t /tmp/raxis-e2e-realistic-iter*.log 2>/dev/null | head -1)
    if [[ -z "$CARGO_LOG" ]]; then
        echo "no /tmp/raxis-e2e-realistic-iter*.log found" >&2
        exit 2
    fi
else
    CARGO_LOG="/tmp/raxis-e2e-realistic-iter${ITER_ARG}.log"
    if [[ ! -f "$CARGO_LOG" ]]; then
        echo "$CARGO_LOG not found" >&2
        exit 2
    fi
fi

ITER_LABEL=$(basename "$CARGO_LOG" .log | sed 's/raxis-e2e-realistic-//')

DATA_DIR=$(grep -E '^\[realism-e2e\] kernel data dir' "$CARGO_LOG" | tail -1 | awk -F': ' '{print $2}' | xargs)

if [[ -z "$DATA_DIR" ]]; then
    OTEL_PUSHER_DD=$(ps -axwwo command 2>/dev/null \
        | grep -E "raxis-fix-loop-respawn[0-9]*[/-]?[0-9]+/raxis/target/release/raxis-otel-pusher" \
        | grep -v grep \
        | tail -1 \
        | grep -oE -- '--data-dir [^ ]+' \
        | awk '{print $2}')
    if [[ -n "$OTEL_PUSHER_DD" && -d "$OTEL_PUSHER_DD" ]]; then
        DATA_DIR="$OTEL_PUSHER_DD"
    fi
fi

if [[ -z "$DATA_DIR" ]]; then
    CARGO_LOG_BIRTH=$(stat -f '%B' "$CARGO_LOG" 2>/dev/null)
    CARGO_LOG_MTIME=$(stat -f '%m' "$CARGO_LOG" 2>/dev/null || stat -c '%Y' "$CARGO_LOG" 2>/dev/null)
    REF_TS="${CARGO_LOG_BIRTH:-$CARGO_LOG_MTIME}"
    if [[ -n "$REF_TS" ]]; then
        WINDOW_START=$((REF_TS - 60))
        WINDOW_END=$((REF_TS + 7200))
        DATA_DIR=$(find /var/folders -name "kernel.stderr.log" -type f 2>/dev/null \
            | while read -r f; do
                MT=$(stat -f '%B' "$f" 2>/dev/null)
                [[ -z "$MT" ]] && MT=$(stat -f '%m' "$f" 2>/dev/null)
                [[ -z "$MT" ]] && continue
                if [[ "$MT" -ge "$WINDOW_START" && "$MT" -le "$WINDOW_END" ]]; then
                    echo "${MT} ${f}"
                fi
              done \
            | sort -n | head -1 | awk '{print $2}' | xargs dirname 2>/dev/null)
    fi
fi

KERNEL_LOG=""
if [[ -n "$DATA_DIR" ]]; then
    KERNEL_LOG="${DATA_DIR}/kernel.stderr.log"
fi

CARGO_LOG_BN=$(basename "$CARGO_LOG")
LATEST_LOG_BN=$(basename "$(ls -1t /tmp/raxis-e2e-realistic-iter*.log 2>/dev/null | head -1)")

if grep -qE '^test result: ok\. 1 passed' "$CARGO_LOG"; then
    VERDICT="PASSED"
    EXIT_CODE=0
elif grep -qE '^test result: FAILED' "$CARGO_LOG"; then
    VERDICT="FAILED"
    EXIT_CODE=1
elif [[ "$CARGO_LOG_BN" == "$LATEST_LOG_BN" ]] \
     && pgrep -f 'extended_e2e_realistic_scenario.*realistic_session_lifecycle' >/dev/null 2>&1; then
    VERDICT="RUNNING"
    EXIT_CODE=0
else
    VERDICT="EXITED (no test-result line; process gone — likely SIGKILL or harness panic before flush)"
    EXIT_CODE=0
fi

echo "──────────────────────────────────────────────────────────────────"
echo "  ${ITER_LABEL}  →  ${VERDICT}"
echo "──────────────────────────────────────────────────────────────────"
echo
echo "cargo log     : ${CARGO_LOG}"
if [[ -n "$DATA_DIR" ]]; then
    echo "data dir      : ${DATA_DIR}"
    echo "kernel log    : ${KERNEL_LOG}"
    AUDIT_DIR="${DATA_DIR}/audit"
    if [[ -d "$AUDIT_DIR" ]]; then
        AUDIT_BYTES=$(du -sh "$AUDIT_DIR" 2>/dev/null | awk '{print $1}')
        echo "audit dir     : ${AUDIT_DIR}  (${AUDIT_BYTES})"
    fi
else
    echo "(no kernel data dir found in cargo log — iter likely died before Tier-3 paths printed)"
fi
echo

PANIC_LINE=$(grep -E "panicked at" "$CARGO_LOG" | head -1)
if [[ -n "$PANIC_LINE" ]]; then
    echo "── panic ─────────────────────────────────────────────────────────"
    echo "${PANIC_LINE}"
    grep -A 5 "panicked at" "$CARGO_LOG" | tail -5 | sed 's/^/  /'
    echo
fi

if [[ -n "$KERNEL_LOG" && -f "$KERNEL_LOG" ]]; then
    echo "── task lifecycle (from kernel.stderr.log intent envelopes) ─────"
    COMPLETED=$(grep -c '"intent_kind":"CompleteTask".*"status":"accepted"\|"status":"accepted","task_id":"[^"]*","task_state":"Completed"' "$KERNEL_LOG" 2>/dev/null || echo 0)
    COMPLETED=$(grep -E '"event":"intent_response".*"task_state":"Completed"' "$KERNEL_LOG" 2>/dev/null | wc -l | xargs)
    ADMITTED=$(grep -E '"event":"intent_response".*"task_state":"Admitted"' "$KERNEL_LOG" 2>/dev/null | wc -l | xargs)
    REJECTED=$(grep -E '"event":"intent_response".*"status":"rejected"' "$KERNEL_LOG" 2>/dev/null | wc -l | xargs)
    echo "  CompleteTask accepted (Admitted → Completed) : ${COMPLETED}"
    echo "  ActivateSubTask accepted (→ Admitted)         : ${ADMITTED}"
    echo "  rejected intents                              : ${REJECTED}"
    echo
    if [[ "${COMPLETED}" -gt 0 ]]; then
        echo "  Completed task IDs (in order):"
        grep -E '"event":"intent_response".*"task_state":"Completed"' "$KERNEL_LOG" \
            | grep -oE '"task_id":"[^"]+"' \
            | awk -F'"' '{print "    " $4}' \
            | nl -ba -w3 -s'. '
        echo
    fi
    if [[ "${REJECTED}" -gt 0 ]]; then
        echo "  Rejected intents (error_code | task_id):"
        grep -E '"event":"intent_response".*"status":"rejected"' "$KERNEL_LOG" \
            | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        ev = json.loads(line)
        ec = ev.get('error_code', '?')
        tid = ev.get('task_id', '?')
        print(f'    {ec:28s} | {tid}')
    except Exception:
        pass"
        echo
    fi

    echo "── failure-mode cluster (kernel.stderr.log error events) ────────"
    SPAWN_FAILED=$(grep -cE '"event":"orchestrator_spawn_failed"' "$KERNEL_LOG" 2>/dev/null | xargs)
    SUBTASK_SPAWN_FAILED=$(grep -cE '"event":"ActivateSubTaskSpawnFailed"' "$KERNEL_LOG" 2>/dev/null | xargs)
    AVF_VM_START_FAILED=$(grep -cE '"event":"avf_vm_start_failed"' "$KERNEL_LOG" 2>/dev/null | xargs)
    DEADLOCK_DETECTED=$(grep -cE '"event":"deadlock_detected"' "$KERNEL_LOG" 2>/dev/null | xargs)
    HTTP_4XX=$(grep -cE '"event":"planner_fetch_response","[^}]*"status_code":4' "$KERNEL_LOG" 2>/dev/null | xargs)
    HTTP_5XX=$(grep -cE '"event":"planner_fetch_response","[^}]*"status_code":5' "$KERNEL_LOG" 2>/dev/null | xargs)
    echo "  orchestrator_spawn_failed         : ${SPAWN_FAILED}"
    echo "  ActivateSubTaskSpawnFailed         : ${SUBTASK_SPAWN_FAILED}"
    echo "  avf_vm_start_failed                : ${AVF_VM_START_FAILED}"
    echo "  deadlock_detected                  : ${DEADLOCK_DETECTED}"
    echo "  planner_fetch_response 4xx         : ${HTTP_4XX}"
    echo "  planner_fetch_response 5xx         : ${HTTP_5XX}"
    echo

    if [[ "${SPAWN_FAILED}" -gt 0 || "${SUBTASK_SPAWN_FAILED}" -gt 0 || "${AVF_VM_START_FAILED}" -gt 0 ]]; then
        echo "  First spawn-error error string:"
        grep -E '"avf_vm_start_failed"|"orchestrator_spawn_failed"|"ActivateSubTaskSpawnFailed"' "$KERNEL_LOG" \
            | head -1 \
            | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        ev = json.loads(line)
        msg = ev.get('err') or ev.get('error') or '<no err field>'
        hint = ev.get('hint', '')
        print(f'    {msg}')
        if hint:
            print(f'    hint: {hint}')
    except Exception:
        pass"
        echo
    fi

    if [[ "${HTTP_4XX}" -gt 0 ]]; then
        FIRST_4XX_TS=$(grep -E '"event":"planner_fetch_response","[^}]*"status_code":4' "$KERNEL_LOG" | head -1 | grep -oE '"ts":[0-9]+' | head -1 | cut -d: -f2)
        LAST_4XX_TS=$(grep -E '"event":"planner_fetch_response","[^}]*"status_code":4' "$KERNEL_LOG" | tail -1 | grep -oE '"ts":[0-9]+' | head -1 | cut -d: -f2)
        echo "  First HTTP 4xx ts: ${FIRST_4XX_TS}    Last: ${LAST_4XX_TS}"
        echo "  (likely upstream LLM credit/quota/rate-limit; check session subdirs for response body)"
        echo
    fi
fi

echo "── observability surface (Grafana / Prometheus / OTLP) ──────────"
grep -E "^\[realism-e2e\] (Grafana|Prometheus|OTLP|Grafana home)" "$CARGO_LOG" | tail -4 | sed 's/^/  /'
echo

echo "── dashboard URL (operator dashboard, alive only while iter is running) ──"
grep -E "^\[realism-e2e\] dashboard autologin URL" "$CARGO_LOG" | tail -1 | sed 's/^/  /'
echo

if [[ $WANT_TASKS -eq 1 && -n "$KERNEL_LOG" && -f "$KERNEL_LOG" ]]; then
    echo "── full intent envelope dump ─────────────────────────────────────"
    grep -E '"event":"intent_(request|response)"' "$KERNEL_LOG"
    echo
fi

if [[ $WANT_PLANNER_HTTP -eq 1 && -n "$KERNEL_LOG" && -f "$KERNEL_LOG" ]]; then
    echo "── planner_fetch_response history ────────────────────────────────"
    grep -E '"event":"planner_fetch_response"' "$KERNEL_LOG"
    echo
fi

if [[ $WANT_KERNEL -eq 1 && -n "$KERNEL_LOG" && -f "$KERNEL_LOG" ]]; then
    echo "── full kernel.stderr.log ────────────────────────────────────────"
    cat "$KERNEL_LOG"
fi

exit "$EXIT_CODE"
