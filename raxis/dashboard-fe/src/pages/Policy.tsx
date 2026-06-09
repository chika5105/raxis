/**
 * Policy.tsx
 *
 * Two surfaces:
 *   PolicyPage        — read-only viewer of the active policy state.
 *                       Unchanged from the original — not a builder.
 *
 *   PolicyBuilderPage — canvas redesign: 3-pane layout.
 *     ┌────────────────┬──────────────────────┬───────────────────┐
 *     │  LEFT PANE     │  Monaco editor        │  RIGHT PANE       │
 *     │  Feature lib   │  (full-height draft)  │  Validation       │
 *     │  [collapsible] │                       │  Apply / epoch    │
 *     │                │                       │  Recovery cmds    │
 *     └────────────────┴──────────────────────┴───────────────────┘
 *
 * All existing logic is preserved. Only the layout changes.
 */

import { useEffect, useMemo, useRef, useState, type ComponentProps } from "react";
import { useQuery } from "@tanstack/react-query";
import Editor from "@monaco-editor/react";
import { Link } from "react-router-dom";

import { ApiError, dashboardApi, sha256Hex } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner, Spinner } from "@/components/Spinner";
import { InfoTooltip, Tooltip } from "@/components/Tooltip";
import { fmtAbsolute, shortFingerprint, shortSha } from "@/lib/format";
import { getStoredProfile } from "@/lib/auth-store";
import { ensureTomlLanguage, raxisMonacoTheme } from "@/lib/monaco-toml";
import { mergePolicySnippet, readPolicyDraft, writePolicyDraft } from "@/lib/policy-draft";
import { useTheme } from "@/lib/theme-context";
import {
  CanvasLayout,
  CanvasHeaderBar,
  PaneDivider,
  InspectorTabBar,
  CollapsibleSection,
  type InspectorTab,
} from "@/components/builder/CanvasLayout";
import type {
  BuilderValidationResponse,
  BuilderValidationSeverity,
  PolicyAdvancement,
  PolicySnapshotView,
} from "@/types/api";

// ---------------------------------------------------------------------------
// Types (unchanged)
// ---------------------------------------------------------------------------

type PolicyFeatureCategory =
  | "Authority"
  | "Execution"
  | "Network"
  | "Models"
  | "Safety"
  | "Operations";

interface PolicyFeature {
  title: string;
  category: PolicyFeatureCategory;
  purpose: string;
  info?: string;
  fields: string[];
  snippet?: string;
}

// ---------------------------------------------------------------------------
// Feature definitions (unchanged)
// ---------------------------------------------------------------------------

const POLICY_FEATURES: PolicyFeature[] = [
  {
    title: "Admin operator permissions",
    category: "Authority",
    purpose: "Grant the operator abilities needed for dashboard admin actions such as credential reveal and epoch advance.",
    info: "Operator permissions are authority-bearing. Grant them deliberately, then rotate the policy epoch so the kernel commits the new envelope.",
    fields: ["[[operators.entries]]", "permitted_ops", "OperatorCertInstall", "RotateEpoch"],
  },
  {
    title: "Policy / plan boundary",
    category: "Authority",
    purpose: "Make the envelope rule explicit: permissions narrow by intersection, protections accumulate by union, ceilings take the smaller value, floors take the larger value, and locked fields reject conflicting plans.",
    info: "Use this as the review rule for every control here. A plan can be more specific, but it cannot grant itself authority the policy did not publish.",
    fields: ["policy ∩ plan", "policy ∪ plan", "ceilings", "floors", "locked fields"],
  },
  {
    title: "Managed lane",
    category: "Execution",
    purpose: "Create or update an execution lane that plan.toml can reference. Lanes are the CISO-friendly way to cap concurrency, spend, and priority by work class.",
    info: "Plans must choose a lane that policy already declares. Duplicate lane IDs are rejected because they make admission ambiguous.",
    fields: ["[[lanes]]", "lane_id", "max_concurrent_tasks", "max_cost_per_epoch"],
    snippet: `[[lanes]]
lane_id              = "default"
max_concurrent_tasks = 4
max_cost_per_epoch   = 10000
priority             = 100`,
  },
  {
    title: "Approved model provider",
    category: "Models",
    purpose: "Allow one model provider identity, pricing envelope, timeout, and credential file name. The secret value stays in providers/*.toml, never in policy.toml.",
    info: "This publishes which vendors may be used. It does not store API keys, and it does not configure the gateway subprocess.",
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
    title: "Role model routing",
    category: "Models",
    purpose: "Choose the primary and fallback model order for orchestrators, executors, and reviewers. Required whenever providers are declared.",
    info: "This is business policy: which models may act in each role and in what fallback order. Gateway binary paths, sockets, and respawn behavior are Raxis runtime mechanics and are not policy.",
    fields: ["[model_routing]", "orchestrator_chain", "executor_chain", "reviewer_chain", "executor_rotate_primary"],
    snippet: `[model_routing]
orchestrator_chain = ["claude-haiku-4-5", "gemini-2.5-flash", "gpt-5.3-codex"]
executor_chain     = ["claude-haiku-4-5", "gemini-2.5-flash", "gpt-5.3-codex"]
executor_rotate_primary = true
reviewer_chain     = ["gpt-5.3-codex", "claude-haiku-4-5", "gemini-2.5-flash"]`,
  },
  {
    title: "Egress allowlist",
    category: "Network",
    purpose: "Declare non-provider domains the transparent proxy may admit. Provider hosts are inferred from approved providers, so the CISO only reviews business egress.",
    info: "Agents have no direct NIC. This allowlist controls the mediated outbound hosts the kernel may admit beyond model-provider endpoints.",
    fields: ["[egress]", "domains", "patterns"],
    snippet: `[egress]
domains = ["example.com"]
patterns = []`,
  },
  {
    title: "Witness gate",
    category: "Safety",
    purpose: "Attach an operator-mandated invariant with typed claims, selector scope, and pinned verifier identity.",
    info: "Policy gates are protections: plans cannot disable them. A plan can only add more gates or narrow where work runs.",
    fields: ["[[gates]]", "gate_type", "satisfies", "verifier_command", "verifier_sha256", "gates.selectors"],
    snippet: `[[gates]]
gate_type        = "NoSecretStrings"
verifier_command = "/opt/homebrew/bin/raxis-verifier-no-secrets"
verifier_sha256  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
max_wall_seconds = 30
max_memory_bytes = 268435456
network_allowed  = false
satisfies        = ["NoSecretStrings"]
agent_hint_default = "A verifier found secret-shaped material. Remove literal credentials and resubmit."

[gates.selectors]
workspaces       = ["checkout-api"]
lane_ids         = ["default"]
path_globs       = ["src/**", "Cargo.toml"]
task_agent_types = ["Executor"]
environments     = ["staging"]
hooks            = ["complete_task"]`,
  },
  {
    title: "Host capacity",
    category: "Operations",
    purpose: "Set VM concurrency and the file-descriptor floor doctor should enforce before busy sessions run.",
    info: "These are operational ceilings/floors. Plans cannot exceed capacity ceilings or weaken required host readiness floors.",
    fields: ["[host_capacity]", "max_concurrent_vms", "required_min_fd_limit"],
    snippet: `[host_capacity]
max_concurrent_vms    = 8
required_min_fd_limit = 4096
disk_full_behavior    = "halt_admit"`,
  },
  {
    title: "Plan replay protection",
    category: "Safety",
    purpose: "Bound signed-plan freshness and nonce retention windows.",
    info: "This prevents stale signed plans from being replayed after the operator intended the window to close.",
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
    purpose: "Keep signed plan artifacts bounded so operators cannot accidentally submit huge bundles.",
    info: "These are ceilings. The plan cannot raise them; the policy keeps validation and audit artifacts bounded.",
    fields: ["[plan_bundle_limits]", "max_artifact_bytes", "max_bundle_bytes"],
    snippet: `[plan_bundle_limits]
max_artifact_bytes = 1048576
max_bundle_bytes   = 10485760
max_artifact_count = 200`,
  },
  {
    title: "Observability pusher",
    category: "Operations",
    purpose: "Export kernel metrics and spans to local OTel/Grafana during live operations.",
    info: "Telemetry is visibility, not authority. It should be easy to turn on without changing the agent security envelope.",
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
    title: "Target branch policy",
    category: "Execution",
    purpose: "Set the default target ref and decide whether plans may override it. Locked means a conflicting plan is rejected.",
    info: "Unlocked fields are defaults: the plan can choose another ref inside policy rules. Locked fields win completely.",
    fields: ["[git]", "default_target_ref", "target_ref_locked"],
    snippet: `[git]
default_target_ref = "refs/heads/main"
target_ref_locked  = false`,
  },
  {
    title: "Environment-bound credentials",
    category: "Safety",
    purpose: "Make credentials discoverable and bind them to environment labels used by egress checks.",
    info: "Policy publishes credential names and expected shape, not secret values. Plans reference these names and cannot invent credentials.",
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
    purpose: "Publish operator-approved executor VM images and choose the default image. Reviewer and orchestrator images remain Raxis-owned.",
    info: "VM image aliases are permissions. Plans can choose from approved aliases but cannot introduce an unapproved image.",
    fields: ["[[vm_images]]", "[default_executor_image]", "role_restriction"],
  },
];

const ENVIRONMENT_RECOMMENDATION_KEY = "raxis.policy.environmentRecommendationDismissed.v1";
const POLICY_BUILDER_UI_STORAGE_KEY = "raxis.dashboard.policyBuilderUi.v1";

type PolicyBuilderRightTab = "validate" | "apply" | "recovery";

interface PolicyBuilderUiDraft {
  version: 1;
  featureCategory: PolicyFeatureCategory | "All";
  rightTab: PolicyBuilderRightTab;
}

function isPolicyFeatureCategory(value: string): value is PolicyFeatureCategory {
  return (
    value === "Authority" ||
    value === "Execution" ||
    value === "Network" ||
    value === "Models" ||
    value === "Safety" ||
    value === "Operations"
  );
}

function readPolicyBuilderUiDraft(): PolicyBuilderUiDraft | null {
  if (typeof window === "undefined" || !window.localStorage) return null;
  try {
    const raw = window.localStorage.getItem(POLICY_BUILDER_UI_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as {
      version?: unknown;
      featureCategory?: unknown;
      rightTab?: unknown;
    };
    if (parsed.version !== 1) return null;
    const rawFeatureCategory =
      typeof parsed.featureCategory === "string" ? parsed.featureCategory : "All";
    const featureCategory = isPolicyFeatureCategory(rawFeatureCategory)
      ? rawFeatureCategory
      : rawFeatureCategory === "Providers"
        ? "Models"
        : "All";
    const rightTab =
      parsed.rightTab === "apply" || parsed.rightTab === "recovery"
        ? parsed.rightTab
        : "validate";
    return { version: 1, featureCategory, rightTab };
  } catch {
    return null;
  }
}

function writePolicyBuilderUiDraft(draft: PolicyBuilderUiDraft) {
  if (typeof window === "undefined" || !window.localStorage) return;
  try {
    window.localStorage.setItem(POLICY_BUILDER_UI_STORAGE_KEY, JSON.stringify(draft));
  } catch {
    // Local builder UI persistence is convenience-only. The active
    // signed policy epoch remains the source of truth.
  }
}

// ---------------------------------------------------------------------------
// PolicyPage — read-only viewer (unchanged from original)
// ---------------------------------------------------------------------------

export function PolicyPage() {
  const profile = getStoredProfile();
  const canWrite =
    !!profile && (profile.roles.includes("write_policy") || profile.roles.includes("admin"));
  const { theme } = useTheme();
  const monacoTheme = raxisMonacoTheme(theme);

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

  if (snap.isPending) return <PageSpinner />;
  if (snap.error) return <ErrorBox error={snap.error} onRetry={() => snap.refetch()} />;
  const s = snap.data;

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-ink">Policy</h1>
          <p className="text-sm text-ink-muted">
            Inspect the active kernel policy and current policy.toml. Drafting,
            validation, snippets, and epoch-advance controls live in Policy Builder.
          </p>
        </div>
        <Link to="/policy-builder" className="btn-primary">
          Open Policy Builder
        </Link>
      </header>

      <PolicySnapshotSection snapshot={s} />

      {!canWrite ? (
        <section className="card p-4 text-sm text-ink-muted">
          Current raw policy.toml is visible to operators with the{" "}
          <code className="font-mono">write_policy</code> or{" "}
          <code className="font-mono">admin</code> dashboard role. Your read-only
          policy snapshot above is still the active kernel state.
        </section>
      ) : toml.isPending ? (
        <PageSpinner />
      ) : toml.error ? (
        <ErrorBox error={toml.error} onRetry={() => toml.refetch()} />
      ) : (
        <section className="card p-0 overflow-hidden">
          <header className="px-4 py-3 border-b border-edge flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-ink">Current policy.toml</h2>
              <p className="mt-1 text-xs text-ink-muted">
                Read-only view of the policy bytes currently loaded by the kernel.
              </p>
            </div>
            <div className="text-[11px] text-ink-subtle font-mono flex items-center gap-2">
              active sha256: <Mono>{shortSha(s.policy_sha256)}</Mono>
              <CopyButton value={s.policy_sha256} />
            </div>
          </header>
          <div className="h-[60vh]">
            <Editor
              height="100%"
              defaultLanguage="toml"
              beforeMount={ensureTomlLanguage}
              theme={monacoTheme}
              value={toml.data ?? ""}
              options={{
                readOnly: true,
                fontSize: 13,
                minimap: { enabled: false },
                scrollBeyondLastLine: true,
                smoothScrolling: true,
                padding: { top: 12, bottom: 96 },
                automaticLayout: true,
                tabSize: 2,
                wordWrap: "on",
              }}
            />
          </div>
        </section>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// PolicyBuilderPage — canvas redesign
// ---------------------------------------------------------------------------

export function PolicyBuilderPage() {
  const profile = getStoredProfile();
  const canWrite =
    !!profile && (profile.roles.includes("write_policy") || profile.roles.includes("admin"));
  const { theme } = useTheme();
  const monacoTheme = raxisMonacoTheme(theme);

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

  const [draft, setDraft] = useState<string | null>(() => readPolicyDraft());
  type PolicyEditorInstance = Parameters<NonNullable<ComponentProps<typeof Editor>["onMount"]>>[0];
  const editorRef = useRef<PolicyEditorInstance | null>(null);
  const [sig, setSig] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [advancement, setAdvancement] = useState<PolicyAdvancement | null>(null);
  const [draftHash, setDraftHash] = useState<string>("");
  const persistedUi = useMemo(() => readPolicyBuilderUiDraft(), []);
  const [featureCategory, setFeatureCategory] = useState<PolicyFeatureCategory | "All">(
    persistedUi?.featureCategory ?? "All",
  );
  const [validation, setValidation] = useState<BuilderValidationResponse | null>(null);
  const [validationBusy, setValidationBusy] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [rightTab, setRightTab] = useState<PolicyBuilderRightTab>(
    persistedUi?.rightTab ?? "validate",
  );
  const [environmentRecommendationDismissed, setEnvironmentRecommendationDismissed] =
    useState(() => {
      if (typeof window === "undefined" || !window.localStorage) return false;
      return window.localStorage.getItem(ENVIRONMENT_RECOMMENDATION_KEY) === "1";
    });

  useEffect(() => {
    if (toml.data && draft === null) setDraft(toml.data);
  }, [toml.data, draft]);

  useEffect(() => {
    writePolicyDraft(draft);
  }, [draft]);

  useEffect(() => {
    if (draft != null) void sha256Hex(draft).then(setDraftHash);
  }, [draft]);

  useEffect(() => {
    writePolicyBuilderUiDraft({
      version: 1,
      featureCategory,
      rightTab,
    });
  }, [featureCategory, rightTab]);

  const visibleFeatures = useMemo(
    () =>
      featureCategory === "All"
        ? POLICY_FEATURES
        : POLICY_FEATURES.filter((f) => f.category === featureCategory),
    [featureCategory],
  );

  const revealPolicyAnchor = (anchor: string) => {
    if (!anchor) return;
    window.setTimeout(() => {
      const editor = editorRef.current;
      const model = editor?.getModel?.();
      if (!editor || !model) return;
      const lineCount = model.getLineCount();
      for (let lineNumber = 1; lineNumber <= lineCount; lineNumber += 1) {
        if (model.getLineContent(lineNumber).includes(anchor)) {
          editor.revealLineInCenter(lineNumber);
          editor.setPosition({ lineNumber, column: 1 });
          editor.focus();
          return;
        }
      }
    }, 0);
  };

  const mergeSnippet = (snippet: string) => {
    const merged = mergePolicySnippet(draft ?? toml.data ?? "", snippet);
    setDraft(merged.toml);
    setValidation(null);
    revealPolicyAnchor(merged.anchor);
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
    setRightTab("validate");
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
      const adv = await dashboardApi.policy.update({ toml: draft, signature_b64: sig.trim() });
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

  const validationIssueCount = validation ? (validation.ok ? 0 : validation.issues.length) : 0;

  const rightTabs: InspectorTab[] = [
    { id: "validate", label: "Validate", badge: validationIssueCount },
    { id: "apply",    label: "Apply" },
    { id: "recovery", label: "Recovery" },
  ];

  // Editor is the canvas for policy builder. If not writable, show read-only note.
  const editorArea = !canWrite ? (
    <div className="flex-1 flex items-center justify-center p-8">
      <div className="card p-6 text-sm text-ink-muted max-w-md text-center space-y-2">
        <p>You are signed in with read-only roles.</p>
        <p>
          To edit policy, your operator certificate needs the{" "}
          <code className="font-mono">RotateEpoch</code> permission, which maps to the{" "}
          <code className="font-mono">write_policy</code> dashboard role.
        </p>
        <Link to="/policy" className="btn block mt-2 justify-center">
          View active policy
        </Link>
      </div>
    </div>
  ) : toml.isPending ? (
    <div className="flex-1 flex items-center justify-center">
      <PageSpinner />
    </div>
  ) : toml.error ? (
    <div className="p-4">
      <ErrorBox error={toml.error} onRetry={() => toml.refetch()} />
    </div>
  ) : (
    <div className="flex-1 h-full min-h-0 overflow-hidden">
      <Editor
        height="100%"
        defaultLanguage="toml"
        beforeMount={ensureTomlLanguage}
        theme={monacoTheme}
        onMount={(editor) => {
          editorRef.current = editor;
        }}
        value={draft ?? ""}
        onChange={(v) => {
          setDraft(v ?? "");
          setValidation(null);
        }}
        options={{
          fontSize: 13,
          minimap: { enabled: false },
          scrollBeyondLastLine: true,
          smoothScrolling: true,
          padding: { top: 12, bottom: 96 },
          automaticLayout: true,
          tabSize: 2,
          wordWrap: "on",
        }}
      />
    </div>
  );

  return (
    <CanvasLayout
      leftPaneTitle="Feature Library"
      leftPaneStorageKey="raxis.builder.policy.leftOpen"
      leftPaneWidth={272}
      leftPaneOwnsScroll
      rightPaneTitle="Policy Actions"
      rightPaneStorageKey="raxis.builder.policy.rightOpen"
      rightPaneWidth={340}
      rightPaneOwnsScroll
      headerBar={
        <CanvasHeaderBar>
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-subtle shrink-0">
              Policy Builder
            </span>
            {snap.data && (
              <>
                <span className="text-ink-subtle text-xs">/</span>
                <span className="text-xs text-ink-muted">
                  epoch #{snap.data.epoch}
                </span>
              </>
            )}
          </div>

          {draftHash && (
            <div className="text-[10px] text-ink-subtle font-mono flex items-center gap-1 hidden sm:flex">
              draft:
              <Mono>{draftHash.slice(0, 12)}…</Mono>
              <CopyButton value={draftHash} />
            </div>
          )}

          <div className="ml-auto flex items-center gap-2">
            {!environmentRecommendationDismissed && (
              <Tooltip
                content="One kernel service per environment is recommended. Click to dismiss."
                side="bottom"
                align="end"
              >
                <button
                  type="button"
                  className="text-[10px] text-info hover:underline"
                  onClick={dismissEnvironmentRecommendation}
                >
                  ⓘ Env recommendation
                </button>
              </Tooltip>
            )}
            <Link to="/policy" className="btn text-xs py-1">
              View active
            </Link>
            <button
              type="button"
              className="btn text-xs py-1"
              disabled={validationBusy || !draft}
              onClick={() => void onValidate()}
            >
              {validationBusy ? <><Spinner className="h-3.5 w-3.5" /> Validating…</> : "Validate"}
            </button>
          </div>
        </CanvasHeaderBar>
      }
      leftPane={
        <PolicyFeatureLibrary
          featureCategory={featureCategory}
          visibleFeatures={visibleFeatures}
          canInsert={canWrite && draft !== null}
          onSetCategory={setFeatureCategory}
          onAppendSnippet={mergeSnippet}
        />
      }
      canvasClassName="border-l border-r border-edge"
      rightPane={
        <PolicyInspector
          tabs={rightTabs}
          activeTab={rightTab}
          onTabChange={(id) => setRightTab(id as typeof rightTab)}
          // Validate tab
          validation={validation}
          validationError={validationError}
          validationBusy={validationBusy}
          onValidate={() => void onValidate()}
          // Apply tab
          sig={sig}
          onSetSig={setSig}
          busy={busy}
          error={error}
          advancement={advancement}
          canWrite={canWrite}
          hasDraft={draft !== null && draft.length > 0}
          onApply={() => void onApply()}
          onResetToActive={() => {
            if (toml.data) setDraft(toml.data);
            setSig("");
            setError(null);
            setAdvancement(null);
            setValidation(null);
          }}
        />
      }
    >
      {editorArea}
    </CanvasLayout>
  );
}

// ---------------------------------------------------------------------------
// PolicyFeatureLibrary (left pane)
// ---------------------------------------------------------------------------

function PolicyFeatureLibrary({
  featureCategory,
  visibleFeatures,
  canInsert,
  onSetCategory,
  onAppendSnippet,
}: {
  featureCategory: PolicyFeatureCategory | "All";
  visibleFeatures: PolicyFeature[];
  canInsert: boolean;
  onSetCategory: (cat: PolicyFeatureCategory | "All") => void;
  onAppendSnippet: (snippet: string) => void;
}) {
  return (
    <div className="h-full min-h-0 overflow-y-auto overscroll-y-auto scroll-thin pb-4">
      <div className="px-3 pt-3 pb-2">
        <div className="rounded border border-info/30 bg-info-muted p-2 text-xs">
          <div className="font-semibold text-ink">Org security policy</div>
          <p className="mt-1 leading-relaxed text-ink-muted">
            Choose the controls a CISO owns: operators, lanes, approved model
            providers, egress, gates, credentials, images, and observability.
            Raxis runtime wiring is managed by the install and supervisor.
          </p>
        </div>
        <div className="mt-2 rounded border border-edge bg-panel-raised p-2 text-[11px] leading-relaxed text-ink-muted">
          <span className="font-semibold text-ink">Policy is the envelope.</span>{" "}
          Plans fit inside it: permissions narrow by intersection, protections
          accumulate by union, ceilings cannot be exceeded, floors cannot be
          weakened, and locked fields reject conflicting plans.
        </div>
      </div>

      <div>
        <CollapsibleSection title="Browse by category" defaultOpen>
          <div className="flex flex-wrap gap-1 pt-1">
            {(["All", "Authority", "Execution", "Network", "Models", "Safety", "Operations"] as const).map((cat) => (
              <button
                key={cat}
                type="button"
                className={`text-[10px] font-semibold px-2 py-0.5 rounded border transition-colors ${
                  featureCategory === cat
                    ? "border-accent bg-accent/15 text-accent"
                    : "border-edge text-ink-muted hover:border-accent"
                }`}
                onClick={() => onSetCategory(cat)}
              >
                {cat}
              </button>
            ))}
          </div>
        </CollapsibleSection>
      </div>

      <PaneDivider />

      <div className="px-3 pt-1">
        <div className="flex flex-col gap-1.5">
          {visibleFeatures.map((feature) => (
            <PolicyFeatureCard
              key={feature.title}
              feature={feature}
              canInsert={canInsert && feature.snippet !== undefined}
              onInsert={() => { if (feature.snippet) onAppendSnippet(feature.snippet); }}
            />
          ))}
        </div>
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
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="rounded border border-edge bg-panel p-2 text-xs">
      <div className="flex items-start justify-between gap-1">
        <button type="button" onClick={() => setExpanded((v) => !v)} className="flex-1 text-left">
          <div className="font-semibold text-ink leading-tight">{feature.title}</div>
          <div className="text-[10px] font-semibold uppercase tracking-wider text-ink-subtle mt-0.5">
            {feature.category}
          </div>
        </button>
        {feature.info && <InfoTooltip content={feature.info} />}
        {feature.snippet && (
          <CopyButton value={feature.snippet} label={`Copy ${feature.title} snippet`} />
        )}
      </div>

      {expanded && (
        <>
          <p className="text-ink-muted mt-1.5 leading-relaxed">{feature.purpose}</p>
          <div className="flex flex-wrap gap-0.5 mt-1.5">
            {feature.fields.map((field) => (
              <code key={field} className="rounded border border-edge bg-panel-raised px-1 py-px font-mono text-[9px] text-ink-muted">
                {field}
              </code>
            ))}
          </div>
        </>
      )}

      {feature.snippet ? (
        <Tooltip
          content={canInsert ? "Add or update this policy block" : "Load editable policy TOML first"}
          side="bottom"
          className="mt-1.5 w-full"
        >
          <button
            type="button"
            className="btn w-full justify-center py-0.5 text-[10px]"
            disabled={!canInsert}
            onClick={onInsert}
          >
            Add / update
          </button>
        </Tooltip>
      ) : (
        <div className="rounded border border-edge bg-panel-raised px-2 py-1 text-[10px] text-ink-subtle mt-1.5">
          No inline snippet — needs image digests or cert material.
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// PolicyInspector (right pane)
// ---------------------------------------------------------------------------

interface PolicyInspectorProps {
  tabs: InspectorTab[];
  activeTab: string;
  onTabChange: (id: string) => void;
  // Validate
  validation: BuilderValidationResponse | null;
  validationError: string | null;
  validationBusy: boolean;
  onValidate: () => void;
  // Apply
  sig: string;
  onSetSig: (v: string) => void;
  busy: boolean;
  error: string | null;
  advancement: PolicyAdvancement | null;
  canWrite: boolean;
  hasDraft: boolean;
  onApply: () => void;
  onResetToActive: () => void;
}

function PolicyInspector(props: PolicyInspectorProps) {
  const { tabs, activeTab, onTabChange } = props;

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden">
      <InspectorTabBar tabs={tabs} active={activeTab} onChange={onTabChange} />

      <div className="flex-1 min-h-0 overflow-y-auto overscroll-y-auto scroll-thin pb-4">

        {/* VALIDATE TAB */}
        {activeTab === "validate" && (
          <div className="p-3 space-y-3">
            <div className="flex items-start justify-between gap-2">
              <p className="text-xs text-ink-muted leading-relaxed flex-1">
                Read-only validation through the policy loader and active epoch checks.
                Does not advance policy or store bytes.
              </p>
              <button
                type="button"
                className="btn text-xs py-1 shrink-0"
                disabled={props.validationBusy || !props.hasDraft}
                onClick={props.onValidate}
              >
                {props.validationBusy ? <><Spinner className="h-3 w-3" /> Running</> : "Run"}
              </button>
            </div>
            {props.validationError && (
              <div className="rounded border border-bad/40 bg-bad/10 p-2 text-xs text-bad">
                {props.validationError}
              </div>
            )}
            {props.validation ? (
              <BuilderValidationPanel response={props.validation} />
            ) : (
              <p className="text-xs text-ink-subtle leading-relaxed">
                Validate before signing so TOML, cert, epoch, and policy-loader errors are visible while the draft is still easy to edit.
              </p>
            )}
          </div>
        )}

        {/* APPLY TAB */}
        {activeTab === "apply" && (
          <div className="p-3 space-y-3">
            {!props.canWrite ? (
              <div className="rounded border border-edge p-3 text-xs text-ink-muted">
                You are signed in with read-only roles. Policy updates require{" "}
                <code className="font-mono">write_policy</code> or{" "}
                <code className="font-mono">admin</code> role.
              </div>
            ) : (
              <>
                <div>
                  <p className="text-xs text-ink-muted leading-relaxed">
                    Paste the detached Ed25519 signature (base64) computed over the exact draft TOML bytes. The dashboard never touches the authority private key.
                  </p>
                  <textarea
                    rows={3}
                    spellCheck={false}
                    className="input w-full mt-2 font-mono text-xs"
                    placeholder="base64 signature (88 chars padded / 86 unpadded)"
                    value={props.sig}
                    onChange={(e) => props.onSetSig(e.target.value)}
                  />
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <button
                    type="button"
                    className="btn-primary text-xs py-1"
                    disabled={props.busy || !props.hasDraft || props.sig.trim().length === 0}
                    onClick={props.onApply}
                  >
                    {props.busy ? <><Spinner className="w-3.5 h-3.5" /> Applying…</> : "Apply policy"}
                  </button>
                  <button
                    type="button"
                    className="btn text-xs py-1"
                    disabled={props.busy}
                    onClick={props.onResetToActive}
                  >
                    Reset to current
                  </button>
                  {props.advancement && (
                    <span className="text-xs text-ok">
                      ✓ epoch #{props.advancement.previous_epoch} → #{props.advancement.new_epoch}
                    </span>
                  )}
                </div>
                {props.error && (
                  <div className="rounded border border-bad/40 bg-bad/10 p-2 text-xs text-bad">
                    {props.error}
                  </div>
                )}
                {props.advancement && (
                  <div className="rounded border border-edge bg-panel p-3 text-xs space-y-1.5">
                    <StatRow label="New epoch" value={`#${props.advancement.new_epoch}`} mono />
                    <StatRow label="SHA-256" value={props.advancement.policy_sha256} mono />
                    <StatRow label="Sessions invalidated" value={String(props.advancement.n_sessions_invalidated)} />
                    <StatRow label="Delegations stale" value={String(props.advancement.n_delegations_marked_stale)} />
                    <StatRow label="At" value={fmtAbsolute(props.advancement.advanced_at)} />
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* RECOVERY TAB */}
        {activeTab === "recovery" && (
          <div className="p-3 space-y-2">
            <p className="text-xs text-ink-muted leading-relaxed">
              Start with the smallest command that tells you which layer is failing.
            </p>
            {[
              { label: "Doctor", command: "raxis doctor", hint: "Data dir, policy, DB, audit, certs." },
              { label: "Supervisor", command: 'raxis-supervisor status --data-dir "$RAXIS_DATA_DIR"', hint: "Healthy, Restarting, Halted, or CircuitOpen." },
              { label: "Kernel log", command: 'tail -n 80 "$(brew --prefix)/var/log/raxis/kernel.err.log"', hint: "Boot, gateway, policy, and VM errors." },
              { label: "Plan validation", command: "raxis plan validate plan.toml", hint: "Catch TOML and DAG mistakes before submit." },
            ].map((item) => (
              <div key={item.label} className="rounded border border-edge bg-panel p-2.5">
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-xs font-semibold text-ink">{item.label}</span>
                  <CopyButton value={item.command} label={`Copy ${item.label} command`} />
                </div>
                <code className="block truncate font-mono text-[10px] text-ink-muted">{item.command}</code>
                <p className="text-[10px] text-ink-subtle mt-1">{item.hint}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function BuilderValidationPanel({ response }: { response: BuilderValidationResponse }) {
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className={response.ok ? "badge border-ok bg-ok-muted text-ok" : "badge border-bad bg-bad/10 text-bad"}>
          {response.ok ? "Kernel check passed" : "Kernel check found errors"}
        </span>
        <span className="text-ink-subtle">epoch #{response.policy_epoch}</span>
      </div>
      {response.issues.length === 0 ? (
        <div className="rounded border border-ok/40 bg-ok-muted px-2.5 py-1.5 text-xs text-ok">
          No issues reported by kernel validation.
        </div>
      ) : (
        <ul className="space-y-1.5">
          {response.issues.map((issue) => (
            <li key={`${issue.code}-${issue.message}`} className={`rounded border px-2.5 py-1.5 text-xs ${issueClass(issue.severity)}`}>
              <div className="font-semibold">{issue.message}</div>
              <div className="mt-0.5 text-ink-muted">{issue.remediation}</div>
              <code className="mt-0.5 inline-block font-mono text-[9px] text-ink-subtle">{issue.code}</code>
            </li>
          ))}
        </ul>
      )}
      {response.next_steps.length > 0 && (
        <div className="grid gap-1.5">
          {response.next_steps.map((cmd) => (
            <div key={cmd} className="flex items-center gap-2 rounded border border-edge bg-panel px-2.5 py-1.5">
              <code className="min-w-0 flex-1 truncate font-mono text-[10px] text-ink-muted">{cmd}</code>
              <CopyButton value={cmd} label="Copy command" />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function issueClass(severity: BuilderValidationSeverity) {
  if (severity === "error") return "border-bad/40 bg-bad/10 text-bad";
  if (severity === "warning") return "border-warn/40 bg-warn-muted text-warn";
  return "border-info/40 bg-info-muted text-info";
}

function StatRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-ink-subtle shrink-0">{label}</span>
      <span className={`${mono ? "font-mono" : ""} text-ink truncate`}>{value}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// PolicySnapshotSection (unchanged, used by PolicyPage)
// ---------------------------------------------------------------------------

function PolicySnapshotSection({ snapshot: s }: { snapshot: PolicySnapshotView }) {
  return (
    <section className="card p-4">
      <h2 className="text-sm font-semibold text-ink mb-3">Active snapshot</h2>
      <dl className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatDl label="Epoch" value={`#${s.epoch}`} mono />
        <StatDl label="SHA-256" value={shortSha(s.policy_sha256)} mono />
        <StatDl label="Signed by" value={shortFingerprint(s.signed_by)} mono />
        <StatDl label="Signed at" value={fmtAbsolute(Number(s.signed_at))} />
      </dl>
      <div className="mt-4 rounded border border-edge bg-panel-raised p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="text-[10px] uppercase tracking-wider text-ink-subtle">
              Target ref policy
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-2 text-sm">
              <Mono>{s.git_default_target_ref}</Mono>
              <Tooltip
                content={
                  s.git_target_ref_locked
                    ? "Locked policy field: conflicting plan target_ref values are rejected."
                    : "Unlocked default: plans may request another target ref inside the policy envelope."
                }
              >
                <span
                  className={
                    s.git_target_ref_locked
                      ? "badge border-bad/40 bg-bad/10 text-bad"
                      : "badge border-ok/40 bg-ok-muted text-ok"
                  }
                >
                  {s.git_target_ref_locked ? "Locked" : "Unlocked"}
                </span>
              </Tooltip>
            </div>
          </div>
          <p className="max-w-xl text-xs leading-relaxed text-ink-muted">
            Locked fields win completely. Unlocked fields act as defaults: the plan can
            narrow or choose inside the policy envelope, but it cannot expand authority.
          </p>
        </div>
      </div>
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
  );
}

function StatDl({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-ink-subtle">{label}</div>
      <div className={`mt-0.5 ${mono ? "font-mono text-ink" : "text-ink"} text-sm break-all`}>
        {value}
      </div>
    </div>
  );
}
