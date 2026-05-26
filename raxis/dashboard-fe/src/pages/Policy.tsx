import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import Editor from "@monaco-editor/react";

import { ApiError, dashboardApi, sha256Hex } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner, Spinner } from "@/components/Spinner";
import { fmtAbsolute, shortFingerprint, shortSha } from "@/lib/format";
import { getStoredProfile } from "@/lib/auth-store";
import { ensureTomlLanguage } from "@/lib/monaco-toml";
import { useTheme } from "@/lib/theme-context";
import type {
  BuilderValidationResponse,
  BuilderValidationSeverity,
  PolicyAdvancement,
} from "@/types/api";

type PolicyFeatureCategory =
  | "Authority"
  | "Execution"
  | "Network"
  | "Providers"
  | "Safety"
  | "Operations";

interface PolicyFeature {
  title: string;
  category: PolicyFeatureCategory;
  purpose: string;
  fields: string[];
  snippet?: string;
}

const POLICY_FEATURES: PolicyFeature[] = [
  {
    title: "Admin operator permissions",
    category: "Authority",
    purpose:
      "Grant the operator abilities needed for dashboard admin actions such as credential reveal and epoch advance.",
    fields: ["[[operators.entries]]", "permitted_ops", "OperatorCertInstall", "RotateEpoch"],
  },
  {
    title: "Managed lane",
    category: "Execution",
    purpose:
      "Register the lane that plan.toml references in [workspace].lane_id and cap concurrent tasks.",
    fields: ["[[lanes]]", "lane_id", "max_concurrent_tasks", "max_cost_per_epoch"],
    snippet: `[[lanes]]
lane_id              = "default"
max_concurrent_tasks = 4
max_cost_per_epoch   = 10000
priority             = 100`,
  },
  {
    title: "Gateway and turn budgets",
    category: "Providers",
    purpose:
      "Configure the kernel-spawned gateway and default planner turn scaling for retries.",
    fields: ["[gateway]", "binary_path", "planner_max_turns_default", "planner_max_turns_step_default"],
    snippet: `[gateway]
binary_path                    = "/opt/homebrew/bin/raxis-gateway"
spawn_timeout_secs             = 30
respawn_backoff_ms             = 1000
max_consecutive_respawns       = 5
planner_max_turns_default      = 60
planner_max_turns_step_default = 30`,
  },
  {
    title: "Anthropic provider",
    category: "Providers",
    purpose:
      "Permit inference through the gateway. Credentials stay in providers/anthropic-prod.toml, never policy.toml.",
    fields: ["[[providers]]", "credentials_file", "pricing.*", "timeouts"],
    snippet: `[[providers]]
provider_id           = "anthropic-prod"
kind                  = "Anthropic"
credentials_file      = "anthropic-prod.toml"
inference_timeout_ms  = 120000
data_fetch_timeout_ms = 30000
pricing.input_tokens_per_dollar      = 200000
pricing.output_tokens_per_dollar     = 50000
pricing.cache_read_tokens_per_dollar = 2000000`,
  },
  {
    title: "Egress allowlist",
    category: "Network",
    purpose:
      "Declare policy-wide domains the transparent proxy may admit. Provider hosts are auto-granted from providers.",
    fields: ["[egress]", "domains", "patterns"],
    snippet: `[egress]
domains = ["api.anthropic.com", "example.com"]
patterns = []`,
  },
  {
    title: "Witness gate",
    category: "Safety",
    purpose:
      "Attach a verifier that must pass before integration merge can advance.",
    fields: ["[[gates]]", "gate_type", "verifier_command", "network_allowed"],
    snippet: `[[gates]]
gate_type        = "NoSecretStrings"
verifier_command = "/opt/homebrew/bin/raxis-verifier-no-secrets"
max_wall_seconds = 30
max_memory_bytes = 268435456
network_allowed  = false
agent_hint_default = "A verifier found secret-shaped material. Remove literal credentials and resubmit."`,
  },
  {
    title: "Host capacity",
    category: "Operations",
    purpose:
      "Set VM concurrency and the file-descriptor floor doctor should enforce before busy sessions run.",
    fields: ["[host_capacity]", "max_concurrent_vms", "required_min_fd_limit"],
    snippet: `[host_capacity]
max_concurrent_vms    = 8
required_min_fd_limit = 4096
disk_full_behavior    = "halt_admit"`,
  },
  {
    title: "Plan replay protection",
    category: "Safety",
    purpose:
      "Bound signed-plan freshness and nonce retention windows.",
    fields: ["[plan_signing]", "max_plan_bundle_age_secs", "nonce_sweep_interval_secs"],
    snippet: `[plan_signing]
max_plan_bundle_age_secs   = 86400
max_clock_skew_secs        = 300
nonce_retention_grace_secs = 3600
nonce_sweep_interval_secs  = 3600`,
  },
  {
    title: "Bundle size limits",
    category: "Safety",
    purpose:
      "Keep signed plan artifacts bounded so operators cannot accidentally submit huge bundles.",
    fields: ["[plan_bundle_limits]", "max_artifact_bytes", "max_bundle_bytes"],
    snippet: `[plan_bundle_limits]
max_artifact_bytes = 1048576
max_bundle_bytes   = 10485760
max_artifact_count = 200`,
  },
  {
    title: "Observability pusher",
    category: "Operations",
    purpose:
      "Export kernel metrics and spans to local OTel/Grafana during live operations.",
    fields: ["[observability]", "metrics", "pusher", "resource"],
    snippet: `[observability]
enabled = true

[observability.metrics]
enabled         = true
export_interval = "5s"

[observability.pusher]
otlp_endpoint       = "http://127.0.0.1:4318"
otlp_protocol       = "http"
otlp_compression    = "gzip"
otlp_export_timeout = "10s"`,
  },
  {
    title: "Git defaults",
    category: "Execution",
    purpose:
      "Set default target ref behavior for plans that do not override it.",
    fields: ["[git]", "default_target_ref", "target_ref_locked"],
    snippet: `[git]
default_target_ref = "refs/heads/main"
target_ref_locked  = false`,
  },
  {
    title: "Environment-bound credentials",
    category: "Safety",
    purpose:
      "Make credentials discoverable and bind them to environment labels used by egress checks.",
    fields: ["[environments.<label>]", "[[permitted_credentials]]", "environment"],
    snippet: `[environments.staging]
description = "Staging services"

[[permitted_credentials]]
name        = "staging-api"
environment = "staging"`,
  },
  {
    title: "Executor image registry",
    category: "Execution",
    purpose:
      "Publish operator-approved VM images and choose the default executor image.",
    fields: ["[[vm_images]]", "[default_executor_image]", "role_restriction"],
  },
];

const ENVIRONMENT_RECOMMENDATION_KEY =
  "raxis.policy.environmentRecommendationDismissed.v1";

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
  // Mirror Monaco's chrome to the dashboard theme so an operator
  // who switched to light mode doesn't get a dark TOML editor
  // dropped in the middle of an otherwise light page. `vs` and
  // `vs-dark` are Monaco's two built-in themes; we use the same
  // `useTheme` hook the rest of the chrome reads from.
  const { theme } = useTheme();
  const monacoTheme = theme === "dark" ? "vs-dark" : "vs";

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
  const [featureCategory, setFeatureCategory] = useState<PolicyFeatureCategory | "All">("All");
  const [validation, setValidation] = useState<BuilderValidationResponse | null>(null);
  const [validationBusy, setValidationBusy] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [environmentRecommendationDismissed, setEnvironmentRecommendationDismissed] =
    useState(() => {
      if (typeof window === "undefined" || !window.localStorage) return false;
      return window.localStorage.getItem(ENVIRONMENT_RECOMMENDATION_KEY) === "1";
    });

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

  const visibleFeatures = useMemo(
    () =>
      featureCategory === "All"
        ? POLICY_FEATURES
        : POLICY_FEATURES.filter((feature) => feature.category === featureCategory),
    [featureCategory],
  );

  const appendSnippet = (snippet: string) => {
    setDraft((prev) => {
      const base = (prev ?? toml.data ?? "").trimEnd();
      return `${base}\n\n${snippet.trim()}\n`;
    });
    setValidation(null);
  };

  const dismissEnvironmentRecommendation = () => {
    setEnvironmentRecommendationDismissed(true);
    if (typeof window !== "undefined" && window.localStorage) {
      window.localStorage.setItem(ENVIRONMENT_RECOMMENDATION_KEY, "1");
    }
  };

  const onValidate = async () => {
    if (!draft) return;
    setValidationBusy(true);
    setValidationError(null);
    try {
      setValidation(await dashboardApi.builders.validatePolicy(draft));
    } catch (e) {
      if (e instanceof ApiError) setValidationError(`${e.code}: ${e.detail}`);
      else if (e instanceof Error) setValidationError(e.message);
      else setValidationError("validation failed");
    } finally {
      setValidationBusy(false);
    }
  };

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
        <h1 className="text-xl font-semibold text-ink">Policy Builder</h1>
        <p className="text-sm text-ink-muted">
          Inspect the active policy, discover policy features, validate draft
          policy.toml, then advance through the signed kernel path. Editing
          requires the <code className="font-mono">write_policy</code> role.
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

      {!environmentRecommendationDismissed && (
        <section className="card border-info/40 bg-info-muted/20 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="max-w-4xl">
              <h2 className="text-sm font-semibold text-ink">
                Environment recommendation
              </h2>
              <p className="mt-1 text-xs leading-relaxed text-ink-muted">
                Raxis supports multiple environments in one policy and one
                kernel, which is useful for controlled staging workflows. For
                production/staging separation, prefer one Homebrew service data
                dir per environment so policy, provider files, audit logs, and
                operator keys cannot be mixed accidentally. The default
                Homebrew service uses <code className="font-mono">RAXIS_ENV=default</code>{" "}
                and <code className="font-mono">$(brew --prefix)/var/lib/raxis</code>.
              </p>
            </div>
            <button
              type="button"
              className="btn"
              onClick={dismissEnvironmentRecommendation}
            >
              Dismiss
            </button>
          </div>
        </section>
      )}

      <section className="card p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-ink">Policy feature library</h2>
            <p className="mt-1 text-xs text-ink-muted">
              Discover the policy sections Raxis understands, copy known-good
              snippets, and keep the authority signature boundary explicit.
              The kernel remains the source of truth for accepted policy.
            </p>
          </div>
          <div className="flex flex-wrap gap-1">
            {(["All", "Authority", "Execution", "Network", "Providers", "Safety", "Operations"] as const).map((cat) => (
              <button
                key={cat}
                type="button"
                className={
                  featureCategory === cat
                    ? "badge border-accent bg-accent/20 text-accent"
                    : "badge border-edge bg-panel text-ink-muted hover:border-accent"
                }
                onClick={() => setFeatureCategory(cat)}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>
        <div className="mt-4 grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
          {visibleFeatures.map((feature) => (
            <PolicyFeatureCard
              key={feature.title}
              feature={feature}
              canInsert={canWrite && draft !== null && feature.snippet !== undefined}
              onInsert={() => {
                if (feature.snippet) appendSnippet(feature.snippet);
              }}
            />
          ))}
        </div>
      </section>

      {canWrite && (
        <section className="card p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-ink">Kernel validation</h2>
              <p className="mt-1 text-xs text-ink-muted">
                Read-only validation of the draft through the policy loader and
                active epoch checks. This does not advance policy or store bytes.
              </p>
            </div>
            <button
              type="button"
              className="btn"
              disabled={validationBusy || !draft}
              onClick={onValidate}
            >
              {validationBusy ? (
                <>
                  <Spinner className="h-4 w-4" /> Validating
                </>
              ) : (
                "Validate with kernel"
              )}
            </button>
          </div>
          {validationError && (
            <div className="mt-3 rounded border border-bad/40 bg-bad/10 p-2 text-xs text-bad">
              {validationError}
            </div>
          )}
          {validation ? (
            <BuilderValidationPanel response={validation} />
          ) : (
            <p className="mt-3 text-xs text-ink-muted">
              Validate before signing so TOML, cert, epoch, and policy-loader
              errors are visible while the draft is still easy to edit.
            </p>
          )}
        </section>
      )}

      <section className="card p-4">
        <h2 className="text-sm font-semibold text-ink">When something is stuck</h2>
        <p className="mt-1 text-xs text-ink-muted">
          Start with the smallest command that tells you which layer is failing.
          The dashboard shows the same recovery loop so operators do not have to
          remember it under pressure.
        </p>
        <div className="mt-3 grid gap-2 lg:grid-cols-4">
          {[
            {
              label: "Doctor",
              command: "raxis doctor",
              hint: "Data dir, policy, DB, audit, certs.",
            },
            {
              label: "Supervisor",
              command: 'raxis-supervisor status --data-dir "$RAXIS_DATA_DIR"',
              hint: "Healthy, Restarting, Halted, or CircuitOpen.",
            },
            {
              label: "Kernel log",
              command: 'tail -n 80 "$(brew --prefix)/var/log/raxis/kernel.err.log"',
              hint: "Boot, gateway, policy, and VM errors.",
            },
            {
              label: "Plan validation",
              command: "raxis plan validate plan.toml",
              hint: "Catch TOML and DAG mistakes before submit.",
            },
          ].map((item) => (
            <div key={item.label} className="rounded border border-edge bg-panel p-3">
              <div className="flex items-center justify-between gap-2">
                <h3 className="text-xs font-semibold text-ink">{item.label}</h3>
                <CopyButton value={item.command} label={`Copy ${item.label} command`} />
              </div>
              <code className="mt-2 block truncate font-mono text-[11px] text-ink-muted">
                {item.command}
              </code>
              <p className="mt-2 text-xs text-ink-subtle">{item.hint}</p>
            </div>
          ))}
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
                beforeMount={ensureTomlLanguage}
                theme={monacoTheme}
                value={draft ?? ""}
                onChange={(v) => {
                  setDraft(v ?? "");
                  setValidation(null);
                }}
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
                  setValidation(null);
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

function BuilderValidationPanel({ response }: { response: BuilderValidationResponse }) {
  return (
    <div className="mt-3 space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className={response.ok ? "badge border-ok bg-ok-muted text-ok" : "badge border-bad bg-bad/10 text-bad"}>
          {response.ok ? "Kernel check passed" : "Kernel check found errors"}
        </span>
        <span className="text-ink-subtle">policy epoch #{response.policy_epoch}</span>
      </div>
      {response.issues.length === 0 ? (
        <div className="rounded border border-ok/40 bg-ok-muted px-2.5 py-2 text-xs text-ok">
          No issues reported by kernel validation.
        </div>
      ) : (
        <ul className="space-y-2">
          {response.issues.map((issue) => (
            <li
              key={`${issue.code}-${issue.message}`}
              className={`rounded border px-2.5 py-2 text-xs ${issueClass(issue.severity)}`}
            >
              <div className="font-semibold">{issue.message}</div>
              <div className="mt-1 text-ink-muted">{issue.remediation}</div>
              <code className="mt-1 inline-block font-mono text-[10px] text-ink-subtle">
                {issue.code}
              </code>
            </li>
          ))}
        </ul>
      )}
      <div className="grid gap-2 lg:grid-cols-2">
        {response.next_steps.map((command) => (
          <div key={command} className="flex items-center gap-2 rounded border border-edge bg-panel px-2.5 py-2">
            <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-ink-muted">
              {command}
            </code>
            <CopyButton value={command} label="Copy command" />
          </div>
        ))}
      </div>
    </div>
  );
}

function issueClass(severity: BuilderValidationSeverity) {
  if (severity === "error") return "border-bad/40 bg-bad/10 text-bad";
  if (severity === "warning") return "border-warn/40 bg-warn-muted text-warn";
  return "border-info/40 bg-info-muted text-info";
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

function PolicyFeatureCard({
  feature,
  canInsert,
  onInsert,
}: {
  feature: PolicyFeature;
  canInsert: boolean;
  onInsert: () => void;
}) {
  return (
    <article className="flex min-h-[13rem] flex-col rounded-md border border-edge bg-panel p-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-ink">{feature.title}</h3>
          <span className="mt-1 inline-flex text-[10px] font-semibold uppercase tracking-wider text-ink-subtle">
            {feature.category}
          </span>
        </div>
        {feature.snippet && (
          <CopyButton value={feature.snippet} label={`Copy ${feature.title} snippet`} />
        )}
      </div>
      <p className="mt-2 text-xs leading-relaxed text-ink-muted">{feature.purpose}</p>
      <div className="mt-3 flex flex-wrap gap-1">
        {feature.fields.map((field) => (
          <code
            key={field}
            className="rounded border border-edge bg-panel-raised px-1.5 py-0.5 font-mono text-[10px] text-ink-muted"
          >
            {field}
          </code>
        ))}
      </div>
      <div className="mt-auto pt-3">
        {feature.snippet ? (
          <button
            type="button"
            className="btn w-full justify-center"
            disabled={!canInsert}
            onClick={onInsert}
            title={canInsert ? "Append snippet to policy.toml draft" : "Load editable policy TOML first"}
          >
            Append snippet
          </button>
        ) : (
          <div className="rounded border border-edge bg-panel-raised px-2 py-1.5 text-xs text-ink-subtle">
            No inline snippet: this section needs image digests or generated
            cert material.
          </div>
        )}
      </div>
    </article>
  );
}
