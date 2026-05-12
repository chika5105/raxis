import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import Editor from "@monaco-editor/react";

import { ApiError, dashboardApi, sha256Hex } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner, Spinner } from "@/components/Spinner";
import { fmtAbsolute, shortFingerprint, shortSha } from "@/lib/format";
import { getStoredProfile } from "@/lib/auth-store";
import type { PolicyAdvancement } from "@/types/api";

/// Policy page. Shows the parsed snapshot in a read-friendly
/// layout, then renders a Monaco editor wrapped around the raw
/// `policy.toml` for operators with the `write_policy` role.
///
/// Editing flow (matches §4.5 wire shape):
///   1. Operator pastes new TOML in the editor (or starts from
///      the current bytes).
///   2. Operator pastes the detached Ed25519 signature
///      (base64; spec accepts padded or unpadded). The signature
///      is computed offline by the authority key holder — the
///      dashboard NEVER holds the authority private key.
///   3. The "Apply" button POSTs `{toml, signature_b64}` to
///      `PUT /api/policy/toml`. On success the kernel emits
///      `PolicyEpochAdvanced` + `PolicyUpdatedViaDashboard`
///      and the new snapshot becomes the active bundle.
export function PolicyPage() {
  const profile = getStoredProfile();
  const canWrite =
    !!profile && (profile.roles.includes("write_policy") || profile.roles.includes("admin"));

  const snap = useQuery({
    queryKey: ["policy"],
    queryFn: ({ signal }) => dashboardApi.policy.snapshot(signal),
    refetchInterval: 10_000,
  });

  const toml = useQuery({
    queryKey: ["policy-toml"],
    queryFn: ({ signal }) => dashboardApi.policy.rawToml(signal),
    enabled: canWrite,
  });

  const [draft, setDraft] = useState<string | null>(null);
  const [sig, setSig] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [advancement, setAdvancement] = useState<PolicyAdvancement | null>(null);
  const [draftHash, setDraftHash] = useState<string>("");

  // Initialize the draft once the raw TOML is fetched.
  useEffect(() => {
    if (toml.data && draft === null) setDraft(toml.data);
  }, [toml.data, draft]);

  // Keep the SHA-256 indicator current so the operator can
  // cross-check the value the kernel will compute on advance
  // (and the value the authority signed over).
  useEffect(() => {
    if (draft != null) sha256Hex(draft).then(setDraftHash);
  }, [draft]);

  const onApply = async () => {
    if (!draft) return;
    setBusy(true);
    setError(null);
    setAdvancement(null);
    try {
      const adv = await dashboardApi.policy.update({
        toml: draft,
        signature_b64: sig.trim(),
      });
      setAdvancement(adv);
      await snap.refetch();
      await toml.refetch();
    } catch (e) {
      if (e instanceof ApiError) setError(`${e.code}: ${e.detail}`);
      else if (e instanceof Error) setError(e.message);
      else setError("update failed");
    } finally {
      setBusy(false);
    }
  };

  if (snap.isPending) return <PageSpinner />;
  if (snap.error) return <ErrorBox error={snap.error} onRetry={() => snap.refetch()} />;
  const s = snap.data;

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold text-ink">Policy</h1>
        <p className="text-sm text-ink-muted">
          Active policy bundle. Editing requires the{" "}
          <code className="font-mono">write_policy</code> role.
        </p>
      </header>

      <section className="card p-4">
        <h2 className="text-sm font-semibold text-ink mb-3">Snapshot</h2>
        <dl className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Stat label="Epoch" value={`#${s.epoch}`} mono />
          <Stat label="SHA-256" value={shortSha(s.policy_sha256)} mono />
          <Stat label="Signed by" value={shortFingerprint(s.signed_by)} mono />
          <Stat label="Signed at" value={fmtAbsolute(Number(s.signed_at))} />
        </dl>
        <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <h3 className="text-xs text-ink-subtle uppercase tracking-wider mb-2">
              Operators ({s.operators.length})
            </h3>
            <ul className="space-y-1 text-xs">
              {s.operators.map((o) => (
                <li key={o.fingerprint} className="flex items-center gap-2">
                  <Mono pill>{shortFingerprint(o.fingerprint)}</Mono>
                  <span className="text-ink">{o.display_name}</span>
                  <span className="ml-auto text-ink-subtle font-mono text-[10px]">
                    {o.permitted_ops.join(", ")}
                  </span>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="text-xs text-ink-subtle uppercase tracking-wider mb-2">
              Notification routes
            </h3>
            <ul className="space-y-1 text-xs">
              {Object.entries(s.notification_routes).map(([kind, ids]) => (
                <li key={kind} className="flex items-center gap-2">
                  <span className="text-ink">{kind}</span>
                  <span className="text-ink-subtle font-mono">→ {ids.join(", ")}</span>
                </li>
              ))}
              {Object.keys(s.notification_routes).length === 0 && (
                <li className="text-ink-subtle">(none)</li>
              )}
            </ul>
          </div>
        </div>
      </section>

      {!canWrite ? (
        <section className="card p-4 text-sm text-ink-muted">
          You are signed in with read-only roles. To edit policy, your
          operator certificate needs the{" "}
          <code className="font-mono">RotateEpoch</code> permission, which
          maps to the <code className="font-mono">write_policy</code>{" "}
          dashboard role.
        </section>
      ) : toml.isPending ? (
        <PageSpinner />
      ) : toml.error ? (
        <ErrorBox error={toml.error} onRetry={() => toml.refetch()} />
      ) : (
        <>
          <section className="card p-0 overflow-hidden">
            <header className="px-4 py-3 border-b border-edge flex items-center justify-between">
              <h2 className="text-sm font-semibold text-ink">policy.toml</h2>
              <div className="text-[11px] text-ink-subtle font-mono flex items-center gap-2">
                draft sha256: <Mono>{draftHash ? `${draftHash.slice(0, 12)}…` : "computing…"}</Mono>
                {draftHash && <CopyButton value={draftHash} />}
              </div>
            </header>
            <div className="h-[60vh]">
              <Editor
                height="100%"
                defaultLanguage="toml"
                theme="vs-dark"
                value={draft ?? ""}
                onChange={(v) => setDraft(v ?? "")}
                options={{
                  fontSize: 13,
                  minimap: { enabled: false },
                  scrollBeyondLastLine: false,
                  automaticLayout: true,
                  tabSize: 2,
                  wordWrap: "on",
                }}
              />
            </div>
          </section>

          <section className="card p-4">
            <h2 className="text-sm font-semibold text-ink">Apply update</h2>
            <p className="mt-1 text-xs text-ink-muted">
              Paste the detached Ed25519 signature (base64) the policy
              authority computed over these exact TOML bytes. The dashboard
              never touches the authority private key — this signature is
              the only proof of authorization.
            </p>
            <textarea
              rows={3}
              spellCheck={false}
              className="input w-full mt-3 font-mono text-xs"
              placeholder="base64 signature (64 raw bytes ⇒ 88 chars padded / 86 unpadded)"
              value={sig}
              onChange={(e) => setSig(e.target.value)}
            />
            <div className="mt-3 flex items-center gap-3">
              <button
                type="button"
                className="btn-primary"
                disabled={busy || !draft || sig.trim().length === 0}
                onClick={onApply}
              >
                {busy ? <><Spinner className="w-4 h-4" /> Applying…</> : "Apply policy"}
              </button>
              <button
                type="button"
                className="btn"
                disabled={busy}
                onClick={() => {
                  if (toml.data) setDraft(toml.data);
                  setSig("");
                  setError(null);
                  setAdvancement(null);
                }}
              >
                Reset to current
              </button>
              {advancement && (
                <span className="text-xs text-ok">
                  ✓ advanced epoch #{advancement.previous_epoch} → #{advancement.new_epoch}
                </span>
              )}
            </div>
            {error && (
              <div className="card border-bad/40 p-3 mt-3 text-sm text-bad">{error}</div>
            )}
            {advancement && (
              <div className="card mt-3 p-3 text-xs space-y-1">
                <Stat label="New epoch" value={`#${advancement.new_epoch}`} mono />
                <Stat label="SHA-256" value={advancement.policy_sha256} mono />
                <Stat label="Sessions invalidated" value={String(advancement.n_sessions_invalidated)} />
                <Stat label="Delegations marked stale" value={String(advancement.n_delegations_marked_stale)} />
                <Stat label="At" value={fmtAbsolute(advancement.advanced_at)} />
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}

function Stat({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-ink-subtle">{label}</div>
      <div className={`mt-0.5 ${mono ? "font-mono text-ink" : "text-ink"} text-sm break-all`}>
        {value}
      </div>
    </div>
  );
}
