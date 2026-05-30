//! provider model selection (MVP).
//!
//! Closes the operator-grade leg of `provider-model-selection.md` so
//! a planner-role binary can:
//!
//! 1. Read a model id from the kernel-stamped `RAXIS_MODEL_ID` env
//!    var, or read an ordered `RAXIS_MODEL_CHAIN` fallback list
//!    (or fall back to a role-canonical default).
//! 2. Validate the id against the V2 known-model registry.
//! 3. Surface deprecation warnings to stderr at planner-boot so the
//!    operator sees them in `initiative watch`.
//!
//! The full spec covers per-role alias chains
//! (`[provider_aliases_defaults]`), `raxis plan prepare`
//! defaulting, and policy-level chain validation. V2 lands the
//! wire-shape leg (registry + env-var contract); the alias-chain
//! resolution and `setup wizard` auto-generation stay deferred to
//! V3.
//!
//! ## Why a registry instead of a free-form string
//!
//! The Anthropic Messages API will accept any string for the
//! `model` field and silently route to a default if the id is
//! unrecognised. That's a footgun: a typo in `RAXIS_MODEL_ID`
//! degrades silently to a different model than the operator
//! configured. The registry is the operator-visible mismatch
//! check — an unknown model id surfaces as a typed
//! [`ProviderModelError::UnknownModel`] at planner-boot, BEFORE
//! the dispatch loop spends any tokens against the wrong model.
//!
//! The registry is intentionally append-only: when a new Anthropic
//! / OpenAI / Bedrock model lands, the spec adds a row, the model
//! id is recognised by `validate_model_id(...)`, and operators
//! consume it via `RAXIS_MODEL_ID=<new-id>`. Removing a row
//! requires a deprecation cycle (mark deprecated → emit warning
//! → eventual removal in a major release) so existing plans don't
//! break silently.

use std::env;

use thiserror::Error;

/// Env var for a single planner model id. Used when no fallback
/// chain is declared.
pub const MODEL_ID_ENV: &str = "RAXIS_MODEL_ID";
/// Env var for a comma-separated planner model fallback chain.
/// First entry is primary; later entries are attempted only for
/// retryable provider failures.
pub const MODEL_CHAIN_ENV: &str = "RAXIS_MODEL_CHAIN";

// ---------------------------------------------------------------------------
// ProviderId + KnownModel
// ---------------------------------------------------------------------------

/// V2 known providers. Matches the gateway's `[providers]` table
/// vocabulary one-for-one. Adding a provider here also requires a
/// matching gateway-side `[providers.X]` config + a
/// `crate::model::ModelClient` impl.
///
/// The driver in `crate::driver` dispatches model construction on
/// this enum: each variant maps to one of `AnthropicClient`,
/// `OpenAiClient`, `GeminiClient`, `BedrockClient`,
/// `SidecarModelClient`. All five accept an
/// `Arc<dyn crate::http_fetch::HttpFetch>` so the kernel-mediated
/// transport (`EgressTier::None` guests) and the direct transport
/// (subprocess substrate) share the same construction codepath.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderId {
    /// Anthropic Messages API → [`crate::model::AnthropicClient`].
    Anthropic,
    /// OpenAI-compatible APIs →
    /// [`crate::openai_client::OpenAiClient`].
    OpenAi,
    /// Google Gemini Generative Language API →
    /// [`crate::gemini_client::GeminiClient`].
    Gemini,
    /// AWS Bedrock InvokeModel API →
    /// [`crate::bedrock_client::BedrockClient`]. Wraps the SigV4
    /// signing leg through the gateway in production.
    Bedrock,
    /// Operator-run HTTP sidecar implementing the
    /// `extensibility-traits.md §9A` request / response contract →
    /// [`crate::sidecar_client::SidecarModelClient`].
    Sidecar,
}

impl ProviderId {
    /// Stable wire string used in policy `[providers]` entries and
    /// in alias chain elements (`anthropic:claude-…`, `openai:gpt-5…`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
            Self::Gemini => "gemini",
            Self::Bedrock => "bedrock",
            Self::Sidecar => "sidecar",
        }
    }

    /// Default base URL for the provider when
    /// `RAXIS_PLANNER_BASE_URL` is unset.
    ///
    /// * **Anthropic** — `https://api.anthropic.com`. Stable.
    /// * **OpenAI** — `https://api.openai.com`. Stable.
    /// * **Gemini** — `https://generativelanguage.googleapis.com`.
    ///   Stable.
    /// * **Bedrock** — `https://bedrock-runtime.us-east-1.amazonaws.com`
    ///   as a production-shaped placeholder; multi-region operators
    ///   override via `RAXIS_PLANNER_BASE_URL`. We deliberately do NOT
    ///   accept an env-driven region here because the planner has no
    ///   business choosing the region — that's the gateway's job
    ///   (it knows the operator's deployment topology). Once the
    ///   gateway is ready to override the URL upstream of the planner
    ///   the env var becomes unnecessary.
    /// * **Sidecar** — returns `""`. The sidecar endpoint is
    ///   operator-supplied per-deployment via the
    ///   `RAXIS_PLANNER_SIDECAR_ENDPOINT` env var; there is no
    ///   well-known default, and the driver MUST refuse to boot when
    ///   the env var is missing for a sidecar-backed model.
    pub const fn default_base_url(self) -> &'static str {
        match self {
            Self::Anthropic => "https://api.anthropic.com",
            Self::OpenAi => "https://api.openai.com",
            Self::Gemini => "https://generativelanguage.googleapis.com",
            Self::Bedrock => "https://bedrock-runtime.us-east-1.amazonaws.com",
            Self::Sidecar => "",
        }
    }
}

/// OpenAI-family API surface required by a known model.
///
/// Chat-capable models keep native tool-call support through
/// `/v1/chat/completions`. Completion-only models must be routed to
/// `/v1/completions`; routing them to the chat endpoint returns the
/// upstream `This is not a chat model` error and burns a failed turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenAiModelApiSurface {
    /// Native OpenAI chat messages and function/tool-call envelopes.
    ChatCompletions,
    /// Legacy/plain completion prompt surface.
    Completions,
}

/// One row in the V2 known-model registry. Both `name` and
/// `provider` are stable wire shapes — operators reference them in
/// `policy.toml` and `plan.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownModel {
    /// The provider's model id. Forwarded verbatim into
    /// [`crate::model::MessageRequest::model`].
    pub name: &'static str,
    /// Provider this model belongs to.
    pub provider: ProviderId,
    /// `Some(replacement)` ⇒ deprecated; `None` ⇒ supported.
    /// Deprecated models still admit traffic but emit
    /// [`emit_model_deprecation_warning`] at planner-boot so the
    /// operator sees the upcoming-removal hint in
    /// `initiative watch`.
    pub deprecated: Option<&'static str>,
    /// Approximate context window size in tokens. Used by
    /// upstream code to bound the per-request prompt size; `None`
    /// when the provider has not committed to a fixed value.
    pub context_window: Option<u32>,
}

impl KnownModel {
    /// OpenAI-family endpoint selector. `None` for non-OpenAI
    /// providers.
    pub fn openai_api_surface(self) -> Option<OpenAiModelApiSurface> {
        match self.provider {
            ProviderId::OpenAi => match self.name {
                "gpt-5.3-codex" => Some(OpenAiModelApiSurface::Completions),
                _ => Some(OpenAiModelApiSurface::ChatCompletions),
            },
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// V2 known-model registry
// ---------------------------------------------------------------------------

/// V2 known-model registry. Append-only — see module docs.
///
/// Sourcing rule: every model id here MUST be referenced by at
/// least one V2 example or `setup wizard` default. Entries that
/// fall out of those references should be marked deprecated, NOT
/// silently removed.
pub const KNOWN_MODELS: &[KnownModel] = &[
    // --- Anthropic ---
    KnownModel {
        name: "claude-sonnet-4-5-20250929",
        provider: ProviderId::Anthropic,
        deprecated: None,
        context_window: Some(200_000),
    },
    KnownModel {
        name: "claude-sonnet-4-20250514",
        provider: ProviderId::Anthropic,
        deprecated: None,
        context_window: Some(200_000),
    },
    KnownModel {
        name: "claude-4.6-sonnet-medium-thinking",
        provider: ProviderId::Anthropic,
        deprecated: None,
        context_window: Some(200_000),
    },
    KnownModel {
        name: "claude-opus-4-7-thinking-xhigh",
        provider: ProviderId::Anthropic,
        deprecated: None,
        context_window: Some(200_000),
    },
    KnownModel {
        name: "claude-opus-4.7-thinking-medium",
        provider: ProviderId::Anthropic,
        deprecated: None,
        context_window: Some(200_000),
    },
    KnownModel {
        name: "claude-3-5-sonnet-20241022",
        provider: ProviderId::Anthropic,
        deprecated: Some("claude-sonnet-4-5-20250929"),
        context_window: Some(200_000),
    },
    KnownModel {
        name: "claude-haiku-4-5",
        provider: ProviderId::Anthropic,
        deprecated: None,
        context_window: Some(200_000),
    },
    // --- OpenAI ---
    KnownModel {
        name: "gpt-5.5-medium",
        provider: ProviderId::OpenAi,
        deprecated: None,
        context_window: Some(200_000),
    },
    KnownModel {
        name: "gpt-5.3-codex",
        provider: ProviderId::OpenAi,
        deprecated: None,
        context_window: Some(200_000),
    },
    // --- Google Gemini ---
    KnownModel {
        name: "gemini-2.5-pro",
        provider: ProviderId::Gemini,
        deprecated: None,
        context_window: Some(2_000_000),
    },
    KnownModel {
        name: "gemini-2.5-flash",
        provider: ProviderId::Gemini,
        deprecated: None,
        context_window: Some(1_000_000),
    },
    // --- AWS Bedrock (Anthropic-on-Bedrock; BedrockClient) ---
    KnownModel {
        name: "anthropic.claude-3-5-sonnet-20241022-v2:0",
        provider: ProviderId::Bedrock,
        deprecated: None,
        context_window: Some(200_000),
    },
    KnownModel {
        name: "anthropic.claude-3-5-haiku-20241022-v1:0",
        provider: ProviderId::Bedrock,
        deprecated: None,
        context_window: Some(200_000),
    },
];

/// Default model the planner uses when `RAXIS_MODEL_ID` is unset.
/// Tracks `provider-model-selection.md §4.1` (single-provider
/// Anthropic-only deployment); operators with a multi-provider
/// deployment override via the env var.
pub const DEFAULT_MODEL: &str = "claude-sonnet-4-5-20250929";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors specific to provider/model resolution at planner-boot.
#[derive(Debug, Error)]
pub enum ProviderModelError {
    /// `RAXIS_MODEL_ID` was set but contains a model id not in
    /// [`KNOWN_MODELS`]. The planner refuses to silently route to
    /// the wrong model — V2 wants the operator to add the model to
    /// the registry first (a one-line PR in `provider_model.rs`).
    #[error("unknown model id: {0:?}")]
    UnknownModel(String),
    /// `RAXIS_MODEL_ID` was set to the empty string. Treated the
    /// same as "unset" would be (use [`DEFAULT_MODEL`]) is
    /// tempting but ambiguous; we surface it explicitly so the
    /// operator-side typo is visible.
    #[error("RAXIS_MODEL_ID is set but empty")]
    EmptyModelEnv,
    /// `RAXIS_MODEL_CHAIN` was present but empty.
    #[error("RAXIS_MODEL_CHAIN is set but empty")]
    EmptyModelChainEnv,
    /// `RAXIS_MODEL_CHAIN` contained an empty comma-separated entry.
    #[error("RAXIS_MODEL_CHAIN contains an empty entry")]
    EmptyModelChainEntry,
}

// ---------------------------------------------------------------------------
// Lookup helpers
// ---------------------------------------------------------------------------

/// Find a known model by id. Linear scan — the registry is small
/// (≈12 rows) and the cost is paid once at planner-boot.
pub fn find_known_model(name: &str) -> Option<&'static KnownModel> {
    KNOWN_MODELS.iter().find(|m| m.name == name)
}

/// Validate that `name` is a known model id. Returns the matching
/// [`KnownModel`] entry on success.
pub fn validate_model_id(name: &str) -> Result<&'static KnownModel, ProviderModelError> {
    find_known_model(name).ok_or_else(|| ProviderModelError::UnknownModel(name.to_owned()))
}

/// Resolve the planner-binary's model id from the kernel-stamped
/// environment, with deprecation warnings emitted to stderr.
///
/// Returns the resolved model id and provider on success.
///
/// Error cases:
/// * Empty `RAXIS_MODEL_ID` ⇒ [`ProviderModelError::EmptyModelEnv`].
/// * Unknown id ⇒ [`ProviderModelError::UnknownModel`].
pub fn resolve_model_from_env() -> Result<&'static KnownModel, ProviderModelError> {
    resolve_model_from_env_fn(|k| env::var(k).ok())
}

/// Resolve an ordered model fallback chain from the kernel-stamped
/// environment. `RAXIS_MODEL_CHAIN` is comma-separated and takes
/// precedence over `RAXIS_MODEL_ID`; absence falls back to the
/// single-model resolver for backward compatibility.
pub fn resolve_model_chain_from_env_fn<F>(
    env: F,
) -> Result<Vec<&'static KnownModel>, ProviderModelError>
where
    F: Fn(&str) -> Option<String>,
{
    match env(MODEL_CHAIN_ENV) {
        Some(raw) if raw.trim().is_empty() => Err(ProviderModelError::EmptyModelChainEnv),
        Some(raw) => {
            let mut out = Vec::new();
            for part in raw.split(',') {
                let model_id = part.trim();
                if model_id.is_empty() {
                    return Err(ProviderModelError::EmptyModelChainEntry);
                }
                out.push(validate_model_id(model_id)?);
            }
            Ok(out)
        }
        None => resolve_model_from_env_fn(env).map(|model| vec![model]),
    }
}

/// Test-friendly variant of [`resolve_model_from_env`] that takes
/// a closure `&str -> Option<String>` instead of the live process
/// environment.
pub fn resolve_model_from_env_fn<F>(env: F) -> Result<&'static KnownModel, ProviderModelError>
where
    F: Fn(&str) -> Option<String>,
{
    let raw = env(MODEL_ID_ENV);
    let id = match raw {
        Some(s) if s.is_empty() => return Err(ProviderModelError::EmptyModelEnv),
        Some(s) => s,
        None => DEFAULT_MODEL.to_owned(),
    };
    let model = validate_model_id(&id)?;
    if let Some(replacement) = model.deprecated {
        emit_model_deprecation_warning(model.name, replacement);
    }
    Ok(model)
}

/// Render the standard deprecation-warning JSON line to stderr.
/// The kernel-side log scraper treats `level=warn` + `event=ModelDeprecated`
/// as an operator-attention signal.
pub fn emit_model_deprecation_warning(model: &str, replacement: &str) {
    eprintln!(
        "{{\"level\":\"warn\",\"event\":\"ModelDeprecated\",\
         \"model\":\"{model}\",\"replacement\":\"{replacement}\"}}",
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time guard: deleting every entry from `KNOWN_MODELS`
    // would otherwise silently pass `each_entry_unique` (vacuously
    // true) and leave the registry empty.
    const _: () = assert!(!KNOWN_MODELS.is_empty());

    #[test]
    fn each_entry_unique() {
        for (i, m) in KNOWN_MODELS.iter().enumerate() {
            for n in &KNOWN_MODELS[(i + 1)..] {
                assert_ne!(m.name, n.name, "duplicate registry row for {:?}", m.name);
            }
        }
    }

    #[test]
    fn default_model_is_in_registry() {
        let m = find_known_model(DEFAULT_MODEL).expect("DEFAULT_MODEL must be in KNOWN_MODELS");
        assert_eq!(m.provider, ProviderId::Anthropic);
        assert!(
            m.deprecated.is_none(),
            "DEFAULT_MODEL must NOT be deprecated"
        );
    }

    #[test]
    fn validate_known_id_returns_entry() {
        let m = validate_model_id(DEFAULT_MODEL).unwrap();
        assert_eq!(m.name, DEFAULT_MODEL);
    }

    #[test]
    fn validate_unknown_id_rejects() {
        let err = validate_model_id("totally-made-up-model").unwrap_err();
        match err {
            ProviderModelError::UnknownModel(s) => {
                assert_eq!(s, "totally-made-up-model");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn empty_env_value_is_typed_error() {
        let err = resolve_model_from_env_fn(|k| match k {
            "RAXIS_MODEL_ID" => Some(String::new()),
            _ => None,
        })
        .unwrap_err();
        assert!(matches!(err, ProviderModelError::EmptyModelEnv));
    }

    #[test]
    fn unset_env_falls_back_to_default_model() {
        let m = resolve_model_from_env_fn(|_| None).unwrap();
        assert_eq!(m.name, DEFAULT_MODEL);
    }

    #[test]
    fn resolves_explicit_model_from_env() {
        let m = resolve_model_from_env_fn(|k| match k {
            "RAXIS_MODEL_ID" => Some("claude-opus-4.7-thinking-medium".to_owned()),
            _ => None,
        })
        .unwrap();
        assert_eq!(m.name, "claude-opus-4.7-thinking-medium");
        assert_eq!(m.provider, ProviderId::Anthropic);
    }

    #[test]
    fn openai_registry_marks_completion_only_models() {
        let chat = validate_model_id("gpt-5.5-medium").unwrap();
        assert_eq!(
            chat.openai_api_surface(),
            Some(OpenAiModelApiSurface::ChatCompletions)
        );

        let completions = validate_model_id("gpt-5.3-codex").unwrap();
        assert_eq!(
            completions.openai_api_surface(),
            Some(OpenAiModelApiSurface::Completions)
        );

        let non_openai = validate_model_id("claude-haiku-4-5").unwrap();
        assert_eq!(non_openai.openai_api_surface(), None);
    }

    #[test]
    fn deprecated_model_resolves_but_warning_path_runs() {
        // Just ensure the deprecated model is admitted with the
        // deprecation flag set; the actual stderr emission isn't
        // asserted (cargo test isolates stderr capture per-test
        // and we don't want a snapshot dependency here).
        let m = resolve_model_from_env_fn(|k| match k {
            "RAXIS_MODEL_ID" => Some("claude-3-5-sonnet-20241022".to_owned()),
            _ => None,
        })
        .unwrap();
        assert_eq!(m.name, "claude-3-5-sonnet-20241022");
        assert!(m.deprecated.is_some());
    }

    #[test]
    fn resolves_model_chain_from_env() {
        let models = resolve_model_chain_from_env_fn(|k| match k {
            MODEL_CHAIN_ENV => Some("gemini-2.5-flash, gpt-5.3-codex, claude-haiku-4-5".to_owned()),
            _ => None,
        })
        .unwrap();
        let names: Vec<&str> = models.iter().map(|m| m.name).collect();
        assert_eq!(
            names,
            vec!["gemini-2.5-flash", "gpt-5.3-codex", "claude-haiku-4-5",]
        );
    }

    #[test]
    fn model_chain_rejects_empty_entries() {
        let err = resolve_model_chain_from_env_fn(|k| match k {
            MODEL_CHAIN_ENV => Some("gemini-2.5-flash,,gpt-5.3-codex".to_owned()),
            _ => None,
        })
        .unwrap_err();
        assert!(matches!(err, ProviderModelError::EmptyModelChainEntry));
    }

    #[test]
    fn provider_id_str_matches_policy_wire_shape() {
        assert_eq!(ProviderId::Anthropic.as_str(), "anthropic");
        assert_eq!(ProviderId::OpenAi.as_str(), "openai");
        assert_eq!(ProviderId::Gemini.as_str(), "gemini");
        assert_eq!(ProviderId::Bedrock.as_str(), "bedrock");
        assert_eq!(ProviderId::Sidecar.as_str(), "sidecar");
    }

    #[test]
    fn default_base_url_is_https_for_known_providers() {
        for (id, expected_prefix) in [
            (ProviderId::Anthropic, "https://"),
            (ProviderId::OpenAi, "https://"),
            (ProviderId::Gemini, "https://"),
            (ProviderId::Bedrock, "https://"),
        ] {
            let url = id.default_base_url();
            assert!(
                url.starts_with(expected_prefix),
                "{:?}: default_base_url {url:?} must start with {expected_prefix}",
                id,
            );
        }
    }

    #[test]
    fn default_base_url_for_sidecar_is_empty() {
        assert_eq!(ProviderId::Sidecar.default_base_url(), "");
    }
}
