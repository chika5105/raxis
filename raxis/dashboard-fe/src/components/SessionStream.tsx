import { useEffect, useRef, useState } from "react";

import { getStoredToken } from "@/lib/auth-store";
import type { StreamEventEnvelope } from "@/types/api";
import { Mono } from "@/components/Mono";

interface SessionStreamProps {
  sessionId: string;
  /// Maximum number of events held in the in-page ring (older
  /// events drop off the top to avoid unbounded DOM growth).
  bufferSize?: number;
}

type StreamStatus = "connecting" | "open" | "closed" | "error";

/// Live SSE viewer for `/api/sessions/:id/stream`.
///
/// The dashboard backend emits one SSE event per kernel-side
/// stream record, with `event: <kind>` (per the spec: `token`,
/// `tool_call`, `tool_result`, `terminal`, `heartbeat`) and a
/// JSON payload as `data:`. We render each event as a
/// terminal-style line and auto-scroll to the bottom unless the
/// operator scrolls back (ergonomic: never wrench the viewport
/// out from under a reader).
///
/// The plain `EventSource` API does not allow custom headers, so
/// we emit the JWT in the URL via `?token=…`. The dashboard
/// backend accepts the bearer in either the `Authorization`
/// header or the `token` query string for SSE specifically, per
/// the §4.3 stream wire spec.
export function SessionStream({ sessionId, bufferSize = 1_000 }: SessionStreamProps) {
  const [events, setEvents] = useState<StreamEventEnvelope[]>([]);
  const [status, setStatus] = useState<StreamStatus>("connecting");
  const [pinned, setPinned] = useState(true);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const token = getStoredToken();
    if (!token) {
      setStatus("error");
      return;
    }
    const url = `/api/sessions/${encodeURIComponent(sessionId)}/stream?token=${encodeURIComponent(
      token,
    )}`;

    const es = new EventSource(url);
    setStatus("connecting");

    const onEvent = (kind: string) => (e: MessageEvent) => {
      try {
        const payload = JSON.parse(e.data) as StreamEventEnvelope;
        // Some servers omit `kind` from the data payload (the
        // SSE event type carries it). Backfill if absent.
        if (!payload.kind) (payload as StreamEventEnvelope).kind = kind;
        setEvents((prev) => {
          const next = prev.concat(payload);
          if (next.length > bufferSize) next.splice(0, next.length - bufferSize);
          return next;
        });
      } catch {
        // Ignore malformed payloads — better than crashing
        // the entire stream view on a single bad chunk.
      }
    };

    es.onopen = () => setStatus("open");
    es.onmessage = onEvent("message");
    // Each kind we care about, registered as a typed listener.
    for (const k of ["token", "tool_call", "tool_result", "terminal", "heartbeat", "error"]) {
      es.addEventListener(k, onEvent(k) as EventListener);
    }
    es.onerror = () => {
      // EventSource auto-reconnects; surface the transient
      // disconnect so the operator sees the indicator change.
      setStatus(es.readyState === EventSource.CLOSED ? "closed" : "error");
    };

    return () => {
      es.close();
      setStatus("closed");
    };
  }, [sessionId, bufferSize]);

  // Auto-scroll if the user is pinned to the bottom.
  useEffect(() => {
    if (!pinned) return;
    const el = containerRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [events, pinned]);

  const onScroll = (e: React.UIEvent<HTMLDivElement>) => {
    const el = e.currentTarget;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    setPinned(atBottom);
  };

  return (
    <div className="card p-0 overflow-hidden flex flex-col">
      <header className="px-3 py-2 border-b border-edge bg-panel-high flex items-center gap-2 text-xs">
        <StatusDot status={status} />
        <span className="text-ink-muted">
          {status === "open" && "live"}
          {status === "connecting" && "connecting…"}
          {status === "error" && "reconnecting…"}
          {status === "closed" && "closed"}
        </span>
        <span className="ml-auto text-ink-subtle">
          {events.length} event{events.length === 1 ? "" : "s"}
          {!pinned && (
            <button
              onClick={() => setPinned(true)}
              className="ml-3 text-accent hover:underline"
            >
              Resume tail ↓
            </button>
          )}
        </span>
      </header>
      <div
        ref={containerRef}
        onScroll={onScroll}
        className="overflow-y-auto scroll-thin font-mono text-[12px] leading-relaxed bg-black/40 p-3 h-[60vh]"
      >
        {events.length === 0 ? (
          <div className="text-ink-subtle italic">
            Waiting for stream events…
          </div>
        ) : (
          events.map((e, i) => (
            <StreamLine key={`${e.seq}-${i}`} event={e} />
          ))
        )}
      </div>
    </div>
  );
}

function StatusDot({ status }: { status: StreamStatus }) {
  const cls =
    status === "open"
      ? "bg-ok animate-pulseDot"
      : status === "connecting" || status === "error"
      ? "bg-warn animate-pulseDot"
      : "bg-ink-subtle";
  return <span className={`inline-block w-2 h-2 rounded-full ${cls}`} aria-hidden="true" />;
}

function StreamLine({ event }: { event: StreamEventEnvelope }) {
  const ts = formatTime(event.at);
  const tone =
    event.kind === "terminal"
      ? "text-info"
      : event.kind === "tool_call" || event.kind === "tool_result"
      ? "text-warn"
      : event.kind === "error"
      ? "text-bad"
      : event.kind === "heartbeat"
      ? "text-ink-subtle"
      : "text-ink";
  return (
    <div className="grid grid-cols-[80px_90px_1fr] gap-2 hover:bg-white/5 px-1 py-0.5">
      <span className="text-ink-subtle">{ts}</span>
      <span className={`uppercase text-[10px] font-bold ${tone}`}>
        {event.kind}
      </span>
      <span className="whitespace-pre-wrap break-words">
        <PayloadView payload={event.payload} />
      </span>
    </div>
  );
}

function PayloadView({ payload }: { payload: unknown }) {
  if (payload == null) return <span className="text-ink-subtle">·</span>;
  if (typeof payload === "string") return <span>{payload}</span>;
  if (typeof payload === "object") {
    // Common shape: `{text: string, …}` for token streaming.
    const obj = payload as Record<string, unknown>;
    if (typeof obj.text === "string") return <span>{obj.text}</span>;
    if (typeof obj.message === "string") return <span>{obj.message}</span>;
    return (
      <Mono className="text-ink-muted text-[11px]">
        {JSON.stringify(payload).slice(0, 600)}
      </Mono>
    );
  }
  return <span>{String(payload)}</span>;
}

function formatTime(unixSeconds: number): string {
  if (!Number.isFinite(unixSeconds) || unixSeconds <= 0) return "—";
  const d = new Date(unixSeconds * 1000);
  return d.toISOString().slice(11, 23);
}
