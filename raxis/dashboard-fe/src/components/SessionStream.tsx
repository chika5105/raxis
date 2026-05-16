import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { LifecycleAnnotation } from "@/components/lifecycle/LifecycleAnnotation";
import { getStoredToken } from "@/lib/auth-store";
import type {
  LifecycleAnnotation as LA,
  StreamEventEnvelope,
} from "@/types/api";
import { Mono } from "@/components/Mono";

interface SessionStreamProps {
  sessionId: string;
  /// Maximum number of events held in the in-page ring (older
  /// events drop off the top to avoid unbounded DOM growth).
  bufferSize?: number;
  /// How long to coalesce inbound events before flushing them
  /// into React state, in milliseconds. A flood of `token`
  /// events would otherwise hammer setState 60+ times/sec.
  /// Default 80 ms — fast enough to feel live, slow enough to
  /// give React time to commit each render.
  flushIntervalMs?: number;
  /// Lifecycle annotations to interleave with the live stream.
  /// Annotations are sorted by `ts_unix` and rendered as cards
  /// at the matching position in the stream (the closest
  /// stream row by `at_ms`), so an operator scrolling a long
  /// session sees retries / revokes inline rather than only at
  /// the top of the page. `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01`.
  annotations?: LA[];
}

type StreamStatus =
  | "connecting"
  | "tail-replay"
  | "live"
  | "reconnecting"
  | "ended"
  | "missing";

/// Subset of SSE event kinds the backend ships as control
/// frames (no JSON payload). The renderer suppresses these from
/// the in-page event list but reflects them in the status pill.
const CONTROL_KINDS = new Set<string>([
  "tail-complete",
  "lagged",
  "closed",
  "keep-alive",
  "kernel-shutdown",
]);

/// Live SSE viewer for `/api/sessions/:id/stream`.
///
/// Wire contract — `INV-DASHBOARD-STREAM-ENVELOPE-01` (also
/// documented in `raxis/crates/dashboard/src/routes/sessions.rs`):
///
///   * **Data frames** are emitted as default-`message` SSE
///     events with the **full envelope** in the `data:` field:
///     `{at_ms, kind, payload}`. The `id:` field duplicates
///     `at_ms` so the browser's auto-reconnect `Last-Event-ID`
///     round-trip works. The renderer reads via `onmessage`
///     once, regardless of how many distinct `kind`s the kernel
///     publishes (the audit→stream bridge fans ~80 audit event
///     kinds onto the per-session stream — pre-registering each
///     via `addEventListener` would have silently dropped any
///     new kind the FE didn't know about).
///   * **Control frames** keep typed `event:` names so we can
///     branch on protocol semantics rather than JSON:
///     `tail-complete`, `lagged`, `closed`, `kernel-shutdown`,
///     `keep-alive`. None of them are rendered as stream rows.
///
/// The plain `EventSource` API does not allow custom headers, so
/// we attach the JWT via `?token=…`. The dashboard backend
/// accepts the bearer in either the `Authorization` header or
/// the `token` query string for SSE specifically.
///
/// Backpressure: token-streamed model output can arrive at >60
/// events/sec. The renderer buffers inbound events in a ref and
/// flushes them into React state on a `flushIntervalMs` ticker
/// so React only commits ~12 times/sec under load.
///
/// Reconnect: `EventSource` already retries transient errors,
/// but it gives up after the kernel returns a non-2xx (e.g. 404
/// for a session that hasn't started streaming yet). We layer a
/// manual exponential-backoff retry on top so the operator does
/// not have to refresh the page.
export function SessionStream({
  sessionId,
  bufferSize = 1_000,
  flushIntervalMs = 80,
  annotations = [],
}: SessionStreamProps) {
  const [events, setEvents] = useState<StreamEventEnvelope[]>([]);
  const [status, setStatus] = useState<StreamStatus>("connecting");
  const [lagged, setLagged] = useState(0);
  const [reconnectAttempt, setReconnectAttempt] = useState(0);
  const [pinned, setPinned] = useState(true);
  const containerRef = useRef<HTMLDivElement>(null);
  // Inbound batch — drained on the flush tick.
  const pending = useRef<StreamEventEnvelope[]>([]);
  // Bumped when the operator clicks "Reconnect" so the effect
  // re-runs even if no other deps changed.
  const [manualReset, setManualReset] = useState(0);

  useEffect(() => {
    const token = getStoredToken();
    if (!token) {
      setStatus("missing");
      return;
    }
    const url = `/api/sessions/${encodeURIComponent(
      sessionId,
    )}/stream?token=${encodeURIComponent(token)}`;

    setStatus("connecting");
    const es = new EventSource(url);
    let backoffTimer: number | undefined;
    let stopped = false;

    const flush = () => {
      if (pending.current.length === 0) return;
      const drained = pending.current;
      pending.current = [];
      setEvents((prev) => {
        const next = prev.concat(drained);
        if (next.length > bufferSize) {
          next.splice(0, next.length - bufferSize);
        }
        return next;
      });
    };

    const flushTimer = window.setInterval(flush, flushIntervalMs);

    const pushEnvelope = (envelope: StreamEventEnvelope) => {
      pending.current.push(envelope);
    };

    es.onopen = () => {
      if (!stopped) {
        setStatus("tail-replay");
      }
    };

    // Data frames arrive as default-`message` SSE events with
    // the full envelope (`{at_ms, kind, payload}`) packed into
    // the `data:` field per `INV-DASHBOARD-STREAM-ENVELOPE-01`.
    // The single `onmessage` handler catches every frame
    // regardless of the kernel-side `kind` — pre-registering
    // per-kind listeners is brittle when the audit-bridge fans
    // ~80 audit kinds onto the wire.
    es.onmessage = (e: MessageEvent) => {
      // The backend stamps `id: <at_ms>` on every data frame as
      // a defence-in-depth source for `at_ms` (also duplicated
      // inside the envelope). Fall back to wall-clock only when
      // both are absent, which never happens in practice.
      const fallbackMs =
        e.lastEventId && /^\d+$/.test(e.lastEventId)
          ? Number(e.lastEventId)
          : Date.now();
      if (e.data === "" || e.data == null) return;
      let parsed: unknown;
      try {
        parsed = JSON.parse(e.data);
      } catch {
        pushEnvelope({
          at_ms: fallbackMs,
          kind: "unknown",
          payload: { _raw: e.data },
        });
        return;
      }
      // Canonical wire shape — full envelope.
      if (
        parsed != null &&
        typeof parsed === "object" &&
        "kind" in (parsed as Record<string, unknown>)
      ) {
        const env = parsed as StreamEventEnvelope;
        if (!Number.isFinite(env.at_ms) || env.at_ms <= 0) {
          env.at_ms = fallbackMs;
        }
        pushEnvelope(env);
        return;
      }
      // Defensive fallback: a kernel version that still emits
      // the old payload-only wire would land here. We synthesize
      // an envelope so the surface still renders rather than
      // dropping the frame on the floor.
      pushEnvelope({
        at_ms: fallbackMs,
        kind: e.type === "message" ? "unknown" : e.type,
        payload: parsed,
      });
    };

    // Control frames — never carry a renderable payload, but
    // they drive the status pill / lag counter.
    es.addEventListener("tail-complete", () => {
      if (!stopped) setStatus("live");
    });
    es.addEventListener("lagged", (e: MessageEvent) => {
      const n = Number(e.data);
      if (Number.isFinite(n)) {
        setLagged((prev) => prev + n);
      }
    });
    es.addEventListener("closed", () => {
      if (!stopped) {
        setStatus("ended");
      }
    });
    es.addEventListener("kernel-shutdown", () => {
      // Kernel orderly shutdown — stop reconnecting so the
      // browser doesn't keep hammering a listener that is
      // actively draining.
      stopped = true;
      setStatus("ended");
      es.close();
    });
    // keep-alive is intentionally ignored — its only job is to
    // keep idle connections from being culled by intermediaries.

    es.onerror = () => {
      if (stopped) return;
      // EventSource transitions: CONNECTING (0) → OPEN (1) →
      // CLOSED (2). CLOSED means the browser gave up; we layer
      // our own backoff on top.
      if (es.readyState === EventSource.CLOSED) {
        flush();
        es.close();
        // 500 ms · 2^attempt, capped at 15 s.
        const delay = Math.min(15_000, 500 * 2 ** reconnectAttempt);
        setStatus("reconnecting");
        backoffTimer = window.setTimeout(() => {
          setReconnectAttempt((n) => n + 1);
        }, delay);
      } else {
        setStatus("reconnecting");
      }
    };

    return () => {
      stopped = true;
      es.close();
      window.clearInterval(flushTimer);
      if (backoffTimer !== undefined) window.clearTimeout(backoffTimer);
      flush();
    };
    // `reconnectAttempt` and `manualReset` participate so that
    // either a backoff-triggered or operator-triggered reconnect
    // tears the old EventSource down and opens a fresh one.
  }, [sessionId, bufferSize, flushIntervalMs, reconnectAttempt, manualReset]);

  // Auto-scroll if the user is pinned to the bottom.
  useEffect(() => {
    if (!pinned) return;
    const el = containerRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [events, pinned]);

  const onScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    const el = e.currentTarget;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    setPinned(atBottom);
  }, []);

  const onReconnect = useCallback(() => {
    setEvents([]);
    setLagged(0);
    setReconnectAttempt(0);
    setManualReset((n) => n + 1);
  }, []);

  const onClear = useCallback(() => {
    setEvents([]);
    setLagged(0);
  }, []);

  const visibleEvents = useMemo(
    () => events.filter((e) => !CONTROL_KINDS.has(e.kind)),
    [events],
  );

  /// Merge stream events and lifecycle annotations into a
  /// single chronologically-sorted timeline. Stream events
  /// carry `at_ms` (unix milliseconds); annotations carry
  /// `ts_unix` (unix seconds) — orchestrator-gap rows have no
  /// timestamp and pin to the top so an operator's eye finds
  /// them first.
  type Row =
    | { kind: "event"; key: string; at_ms: number; event: StreamEventEnvelope }
    | { kind: "annotation"; key: string; at_ms: number; annotation: LA };
  const merged = useMemo<Row[]>(() => {
    const rows: Row[] = visibleEvents.map((e, i) => ({
      kind: "event",
      key: `e-${e.at_ms}-${i}`,
      at_ms: e.at_ms,
      event: e,
    }));
    annotations.forEach((a, i) => {
      const at_ms =
        "ts_unix" in a && typeof a.ts_unix === "number"
          ? a.ts_unix * 1000
          : 0;
      rows.push({
        kind: "annotation",
        key: `a-${a.kind}-${i}`,
        at_ms,
        annotation: a,
      });
    });
    rows.sort((x, y) => x.at_ms - y.at_ms);
    return rows;
  }, [visibleEvents, annotations]);

  return (
    <div className="card p-0 overflow-hidden flex flex-col">
      <header className="px-3 py-2 border-b border-edge bg-panel-high flex items-center gap-2 text-xs">
        <StatusDot status={status} />
        <span className="text-ink-muted">{statusLabel(status)}</span>
        {lagged > 0 && (
          <span
            title="The backend reported the subscriber lagged behind the broadcast. Older events were dropped server-side; the live tail is intact."
            className="badge bg-warn-muted/30 border-warn text-warn text-[10px]"
          >
            lagged {lagged}
          </span>
        )}
        <span className="ml-auto text-ink-subtle flex items-center gap-3">
          <span>
            {visibleEvents.length} event{visibleEvents.length === 1 ? "" : "s"}
          </span>
          {!pinned && (
            <button
              onClick={() => setPinned(true)}
              className="text-accent hover:underline"
            >
              Resume tail ↓
            </button>
          )}
          <button
            onClick={onClear}
            className="text-ink-subtle hover:text-ink"
            title="Clear the in-page event ring (does not affect server-side capture)"
          >
            Clear
          </button>
          <button
            onClick={onReconnect}
            className="text-ink-subtle hover:text-ink"
            title="Drop the current SSE connection and reattach"
          >
            Reconnect
          </button>
        </span>
      </header>
      <div
        ref={containerRef}
        onScroll={onScroll}
        className="overflow-y-auto scroll-thin font-mono text-[12px] leading-relaxed bg-black/40 p-3 h-[60vh]"
      >
        {merged.length === 0 ? (
          <div className="text-ink-subtle italic">
            {status === "missing" ? (
              <>Not authenticated — sign in to view the live stream.</>
            ) : status === "ended" ? (
              <>
                Session has no live stream attached (the agent may not have
                started emitting output yet, or the session has terminated).
              </>
            ) : status === "reconnecting" ? (
              <>Reconnecting to the kernel stream…</>
            ) : (
              <>Waiting for stream events…</>
            )}
          </div>
        ) : (
          merged.map((row) =>
            row.kind === "annotation" ? (
              <div
                key={row.key}
                className="my-1 rounded border border-info/30 bg-info/5 p-2 font-sans text-[12px]"
                data-testid="session-stream-annotation"
              >
                <LifecycleAnnotation annotation={row.annotation} />
              </div>
            ) : (
              <StreamLine key={row.key} event={row.event} />
            ),
          )
        )}
      </div>
    </div>
  );
}

function statusLabel(status: StreamStatus): string {
  switch (status) {
    case "connecting":
      return "connecting…";
    case "tail-replay":
      return "replaying tail…";
    case "live":
      return "live";
    case "reconnecting":
      return "reconnecting…";
    case "ended":
      return "stream ended";
    case "missing":
      return "no token";
  }
}

function StatusDot({ status }: { status: StreamStatus }) {
  const cls =
    status === "live"
      ? "bg-ok animate-pulseDot"
      : status === "tail-replay" || status === "connecting"
        ? "bg-info animate-pulseDot"
        : status === "reconnecting"
          ? "bg-warn animate-pulseDot"
          : status === "ended"
            ? "bg-ink-subtle"
            : "bg-bad";
  return (
    <span
      className={`inline-block w-2 h-2 rounded-full ${cls}`}
      aria-hidden="true"
    />
  );
}

function StreamLine({ event }: { event: StreamEventEnvelope }) {
  const [expanded, setExpanded] = useState(false);
  const ts = formatTimeMs(event.at_ms);
  const tone =
    event.kind === "terminal" || event.kind === "complete"
      ? "text-info"
      : event.kind === "tool_call" || event.kind === "tool_result"
        ? "text-warn"
        : event.kind === "error"
          ? "text-bad"
          : "text-ink";
  const onClick = useCallback(() => setExpanded((v) => !v), []);
  return (
    <div
      className="grid grid-cols-[80px_110px_1fr] gap-2 hover:bg-white/5 px-1 py-0.5 cursor-pointer"
      onClick={onClick}
      data-testid="session-stream-row"
    >
      <span className="text-ink-subtle">{ts}</span>
      <span className={`uppercase text-[10px] font-bold ${tone}`}>
        {event.kind}
      </span>
      <span className="whitespace-pre-wrap break-words">
        {expanded ? (
          <pre className="text-[11px] text-ink-muted whitespace-pre-wrap">
            {safeStringifyPayload(event.payload)}
          </pre>
        ) : (
          <PayloadView payload={event.payload} />
        )}
      </span>
    </div>
  );
}

function safeStringifyPayload(p: unknown): string {
  try {
    return JSON.stringify(p, null, 2);
  } catch {
    return String(p);
  }
}

function PayloadView({ payload }: { payload: unknown }) {
  if (payload == null) return <span className="text-ink-subtle">·</span>;
  if (typeof payload === "string") {
    return (
      <span>
        {payload.length > 800 ? `${payload.slice(0, 800)}…` : payload}
      </span>
    );
  }
  if (typeof payload === "number" || typeof payload === "boolean") {
    return <span>{String(payload)}</span>;
  }
  if (typeof payload === "object") {
    const obj = payload as Record<string, unknown>;
    // Common payload shapes from the planner side (see
    // raxis/crates/planner-core stream emitters):
    //   * `{text: string, …}`    — token / model_chunk
    //   * `{message: string, …}` — error / terminal
    //   * `{tool_name, args}`     — tool_call
    //   * `{tool_name, result}`   — tool_result
    if (typeof obj.text === "string") return <span>{obj.text}</span>;
    if (typeof obj.message === "string") return <span>{obj.message}</span>;
    if (typeof obj.tool_name === "string") {
      return (
        <span>
          <span className="text-warn">{obj.tool_name}</span>
          {"args" in obj && (
            <Mono className="text-ink-muted text-[11px] ml-2">
              {clip(JSON.stringify(obj.args), 400)}
            </Mono>
          )}
          {"result" in obj && (
            <Mono className="text-ink-muted text-[11px] ml-2">
              → {clip(JSON.stringify(obj.result), 400)}
            </Mono>
          )}
        </span>
      );
    }
    return (
      <Mono className="text-ink-muted text-[11px]">
        {clip(JSON.stringify(payload), 600)}
      </Mono>
    );
  }
  return <span>{String(payload)}</span>;
}

function clip(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

/// Format a unix-milliseconds timestamp as HH:MM:SS.mmm UTC.
/// The stream is operator-tooling-grade — millisecond precision
/// matters when tool calls fire back-to-back.
function formatTimeMs(unixMs: number): string {
  if (!Number.isFinite(unixMs) || unixMs <= 0) return "—";
  const d = new Date(unixMs);
  return d.toISOString().slice(11, 23);
}
