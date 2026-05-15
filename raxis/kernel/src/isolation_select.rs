//! Boot-time selection of the agent-runtime isolation substrate.
//!
//! Implements `extensibility-traits.md §3.8` —
//! `select_isolation_backend(&policy) -> Arc<dyn Backend>`.
//!
//! The kernel binary depends on two concrete substrate crates:
//!
//! * `raxis-isolation-firecracker` — `[target.'cfg(target_os = "linux")']`
//! * `raxis-isolation-apple-vz`    — `[target.'cfg(target_os = "macos")']`
//!
//! At boot the kernel invokes [`select_isolation_backend`] which
//! picks the platform-default substrate (`firecracker` on Linux,
//! `apple-vz` on macOS), then runs
//! [`raxis_isolation::verify_admission_tier`] on the substrate's
//! self-reported [`raxis_isolation::IsolationLevel`]. The policy
//! decides whether `WasmSandbox` is admissible (ignored in V2 since
//! no Wasm substrate ships) and whether `FallbackOnly` is admissible
//! (only with the operator-supplied `--unsafe-fallback-isolation`
//! flag, which records an audit event before continuing).
//!
//! ## What this module is NOT responsible for
//!
//! * Configuring the substrate's runtime directory — that's
//!   `bootstrap.rs`'s job (it provisions `<data_dir>/runtime`).
//! * Recording the substrate's `backend_id` into the audit chain —
//!   that's `kernel/src/main.rs`'s `SessionVmSpawned` emission.
//! * The actual VM spawn. The kernel-side spawn callsites live in:
//!     * `kernel/src/session_spawn_orchestrator.rs` —
//!       `LiveOrchestratorSpawn::spawn_for_initiative` for the
//!       canonical Orchestrator session (driven by
//!       `OperatorRequest::ApprovePlan` after the SQL transaction
//!       commits, per `extensibility-traits.md §3.5`); plus
//!       `spawn_executor_for_task`, the free-fn helper the
//!       `IntentKind::ActivateSubTask` handler calls to drive
//!       Executor / Reviewer spawn against the same trait surface
//!       (`extensibility-traits.md §3.5` + `v2-deep-spec.md §Step 21`).
//!     * `crates/session-spawn/src/lib.rs` — the
//!       `SessionSpawnService::spawn_session()` composer that owns
//!       the `Arc::clone(&isolation).spawn(...)` call into the
//!       `IsolationBackend`. Both kernel-side bridges flow through
//!       this single composer, so there is exactly one
//!       `Backend::spawn` invocation point in the kernel binary.

use std::path::PathBuf;
use std::sync::Arc;

use raxis_isolation::{AdmissionDecision, Backend, IsolationLevel};

/// Errors the substrate selector can surface.
///
/// Distinct from `KernelError` so this module is testable without a
/// full kernel boot. `kernel/src/main.rs` translates these into
/// `BootError::IsolationSelectFailed { reason }` before exiting.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SelectError {
    /// The host platform has no shipped substrate (e.g. Windows
    /// without the V3 Hyper-V backend).
    #[error("no isolation substrate available for this host platform: {os}")]
    NoSubstrateForPlatform {
        /// `std::env::consts::OS` value.
        os: String,
    },

    /// The substrate's self-reported tier was below the R-1
    /// conformance bar and the operator did not pass
    /// `--unsafe-fallback-isolation`.
    #[error(
        "substrate {backend_id} reported {tier:?}: production refuses this tier without \
         --unsafe-fallback-isolation"
    )]
    TierBelowR1 {
        /// Backend identifier from `Backend::backend_id`.
        backend_id: &'static str,
        /// Reported tier.
        tier: IsolationLevel,
    },

    /// The substrate self-reported `TestOnly`. Production never
    /// admits this tier.
    #[error("substrate {backend_id} reported TestOnly tier; production refuses absolutely")]
    TestOnlyInProduction {
        /// Backend identifier from `Backend::backend_id`.
        backend_id: &'static str,
    },

    /// The substrate's `verify_isolation_guarantee` itself returned
    /// an error.
    #[error("substrate {backend_id} verify_isolation_guarantee failed: {reason}")]
    VerifyFailed {
        /// Backend identifier.
        backend_id: &'static str,
        /// Substrate-reported reason.
        reason: String,
    },
}

/// What the operator gave us at boot. Plain-data so the selector
/// stays testable.
#[derive(Debug, Clone)]
pub struct SelectorInputs {
    /// Runtime directory under which the substrate stages per-session
    /// host files (UDS sockets, pipes). Always `<data_dir>/runtime`
    /// in production.
    pub runtime_dir: PathBuf,

    /// Operator passed `--unsafe-fallback-isolation` at boot. When
    /// `true`, a substrate reporting `FallbackOnly` is admitted; the
    /// kernel main loop is responsible for emitting the
    /// `IsolationFallbackBypass` audit event before proceeding.
    pub allow_fallback: bool,

    /// Operator policy says Wasm-sandboxed substrates are usable for
    /// low-stakes verifiers. V2 ships no Wasm substrate, so this
    /// only matters for V3+ — kept here so the kernel main can
    /// thread the policy bit through without per-version
    /// refactoring.
    pub allow_wasm_sandbox: bool,
}

impl SelectorInputs {
    /// Build a default-shaped input. Every field is mandatory in
    /// production; this helper exists for tests + smoke fixtures.
    pub fn new(runtime_dir: impl Into<PathBuf>) -> Self {
        Self {
            runtime_dir: runtime_dir.into(),
            allow_fallback: false,
            allow_wasm_sandbox: false,
        }
    }
}

/// Outcome of [`select_isolation_backend`].
///
/// Carrying both the boxed backend and the verified tier lets
/// `kernel/src/main.rs` emit a single `KernelStarted { isolation:
/// { backend_id, tier } }` audit event without re-querying.
pub struct SelectedBackend {
    /// The chosen backend, ready to be cloned into `HandlerContext`.
    pub backend: Arc<dyn Backend>,
    /// Verified tier from `verify_isolation_guarantee`.
    pub tier: IsolationLevel,
    /// Whether the kernel must emit `IsolationFallbackBypass` before
    /// admitting any session (true iff the substrate reported
    /// `FallbackOnly` and the operator overrode).
    pub fallback_bypass_required: bool,
}

/// Pick + admit the isolation substrate.
///
/// Selection rules per `extensibility-traits.md §3.8` "auto":
///
/// * Linux ⇒ Firecracker.
/// * macOS ⇒ Apple Virtualization Framework.
/// * Anything else ⇒ `SelectError::NoSubstrateForPlatform`.
///
/// Admission rules per `raxis_isolation::verify_admission_tier`:
///
/// * `R1Conformant{,Strong}` ⇒ admit.
/// * `WasmSandbox` ⇒ admit iff `inputs.allow_wasm_sandbox`.
/// * `FallbackOnly` ⇒ admit iff `inputs.allow_fallback` (operator
///   passed `--unsafe-fallback-isolation`); kernel main records
///   the bypass audit event.
/// * `TestOnly` ⇒ never admit (production never includes test
///   substrates per the `raxis-test-support` mock-isolation rule).
pub fn select_isolation_backend(inputs: &SelectorInputs) -> Result<SelectedBackend, SelectError> {
    let backend = build_platform_backend(inputs)?;
    admit_backend(backend, inputs)
}

/// Build the platform-default backend. Pulled out so tests can
/// stub the build step without going through the full admission
/// path.
#[cfg(target_os = "linux")]
fn build_platform_backend(inputs: &SelectorInputs) -> Result<Arc<dyn Backend>, SelectError> {
    use raxis_isolation_firecracker::FirecrackerBackend;
    let backend = FirecrackerBackend::new(&inputs.runtime_dir);
    Ok(Arc::new(backend))
}

#[cfg(target_os = "macos")]
fn build_platform_backend(inputs: &SelectorInputs) -> Result<Arc<dyn Backend>, SelectError> {
    use raxis_isolation_apple_vz::AppleVzBackend;
    let backend = AppleVzBackend::new(&inputs.runtime_dir);
    Ok(Arc::new(backend))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn build_platform_backend(_inputs: &SelectorInputs) -> Result<Arc<dyn Backend>, SelectError> {
    Err(SelectError::NoSubstrateForPlatform {
        os: std::env::consts::OS.to_owned(),
    })
}

/// Run the admission helper against the candidate backend.
///
/// Public so kernel boot can pass an already-selected `Arc<dyn Backend>`
/// (e.g. an integration test substrate that the production main
/// would never construct, but conformance tests want to drive
/// through the full admission gate).
pub fn admit_backend(
    backend: Arc<dyn Backend>,
    inputs: &SelectorInputs,
) -> Result<SelectedBackend, SelectError> {
    let backend_id = backend.backend_id();
    let tier = backend
        .verify_isolation_guarantee()
        .map_err(|e| SelectError::VerifyFailed {
            backend_id,
            reason: format!("{e}"),
        })?;
    let decision = raxis_isolation::verify_admission_tier(tier);
    match decision {
        AdmissionDecision::Admit => Ok(SelectedBackend {
            backend,
            tier,
            fallback_bypass_required: false,
        }),
        AdmissionDecision::AdmitWasmIfPolicyAllows => {
            if inputs.allow_wasm_sandbox {
                Ok(SelectedBackend {
                    backend,
                    tier,
                    fallback_bypass_required: false,
                })
            } else {
                Err(SelectError::TierBelowR1 { backend_id, tier })
            }
        }
        AdmissionDecision::AdmitFallbackIfFlagSet => {
            if inputs.allow_fallback {
                Ok(SelectedBackend {
                    backend,
                    tier,
                    fallback_bypass_required: true,
                })
            } else {
                Err(SelectError::TierBelowR1 { backend_id, tier })
            }
        }
        AdmissionDecision::Refuse(_) => Err(SelectError::TestOnlyInProduction { backend_id }),
    }
}

// ---------------------------------------------------------------------------
// Tests — exercise the admission helper against typed test backends
// without requiring real Firecracker / AVF on the host.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_isolation::{
        Backend, CapabilityKind, CapabilityValue, IsolationError, Session, VerifiedImage, VmSpec,
        WorkspaceMount,
    };

    /// Tiny in-test backend that lets us inject a tier and a
    /// backend_id. Used only to drive `admit_backend` — never wired
    /// into a production code path.
    struct TestBackend {
        id: &'static str,
        tier: IsolationLevel,
    }

    impl Backend for TestBackend {
        fn spawn(
            &self,
            _image: &VerifiedImage,
            _mounts: &[WorkspaceMount],
            _spec: &VmSpec,
        ) -> Result<Box<dyn Session>, IsolationError> {
            Err(IsolationError::BackendInternal(
                "test backend never spawns".to_owned(),
            ))
        }
        fn verify_isolation_guarantee(&self) -> Result<IsolationLevel, IsolationError> {
            Ok(self.tier)
        }
        fn capability(&self, _kind: CapabilityKind) -> CapabilityValue {
            CapabilityValue::Bool(false)
        }
        fn backend_id(&self) -> &'static str {
            self.id
        }
    }

    fn run_admit(
        tier: IsolationLevel,
        allow_fallback: bool,
        allow_wasm: bool,
    ) -> Result<SelectedBackend, SelectError> {
        let backend = Arc::new(TestBackend {
            id: "test-backend-fixture",
            tier,
        }) as Arc<dyn Backend>;
        admit_backend(
            backend,
            &SelectorInputs {
                runtime_dir: PathBuf::from("/tmp/raxis-runtime"),
                allow_fallback,
                allow_wasm_sandbox: allow_wasm,
            },
        )
    }

    #[test]
    fn r1_conformant_is_admitted_unconditionally() {
        let r = run_admit(IsolationLevel::R1Conformant, false, false)
            .unwrap_or_else(|e| panic!("R1Conformant must admit, got {e:?}"));
        assert_eq!(r.tier, IsolationLevel::R1Conformant);
        assert!(!r.fallback_bypass_required);
    }

    #[test]
    fn r1_strong_is_admitted_unconditionally() {
        let r = run_admit(IsolationLevel::R1ConformantStrong, false, false)
            .unwrap_or_else(|e| panic!("R1ConformantStrong must admit, got {e:?}"));
        assert_eq!(r.tier, IsolationLevel::R1ConformantStrong);
        assert!(!r.fallback_bypass_required);
    }

    #[test]
    fn wasm_sandbox_admitted_only_when_policy_allows() {
        match run_admit(IsolationLevel::WasmSandbox, false, false) {
            Err(SelectError::TierBelowR1 { tier, .. }) => {
                assert_eq!(tier, IsolationLevel::WasmSandbox);
            }
            Err(other) => panic!("expected TierBelowR1, got {other:?}"),
            Ok(_) => panic!("WasmSandbox must not admit without policy"),
        }
        let r = run_admit(IsolationLevel::WasmSandbox, false, true)
            .unwrap_or_else(|e| panic!("WasmSandbox with policy must admit: {e:?}"));
        assert_eq!(r.tier, IsolationLevel::WasmSandbox);
        assert!(!r.fallback_bypass_required);
    }

    #[test]
    fn fallback_only_admitted_only_with_unsafe_flag() {
        match run_admit(IsolationLevel::FallbackOnly, false, false) {
            Err(SelectError::TierBelowR1 { tier, .. }) => {
                assert_eq!(tier, IsolationLevel::FallbackOnly);
            }
            Err(other) => panic!("expected TierBelowR1, got {other:?}"),
            Ok(_) => panic!("FallbackOnly must not admit without unsafe flag"),
        }
        let r = run_admit(IsolationLevel::FallbackOnly, true, false).unwrap_or_else(|e| {
            panic!(
                "FallbackOnly with --unsafe-fallback-isolation must \
                                          admit: {e:?}"
            )
        });
        assert_eq!(r.tier, IsolationLevel::FallbackOnly);
        assert!(
            r.fallback_bypass_required,
            "fallback admission must surface the bypass requirement so kernel main \
             emits the IsolationFallbackBypass audit event before any spawn",
        );
    }

    #[test]
    fn test_only_is_refused_absolutely_even_with_unsafe_fallback() {
        match run_admit(IsolationLevel::TestOnly, true, true) {
            Err(SelectError::TestOnlyInProduction { backend_id }) => {
                assert_eq!(backend_id, "test-backend-fixture");
            }
            Err(other) => panic!("expected TestOnlyInProduction, got {other:?}"),
            Ok(_) => panic!("TestOnly must never be admitted in production"),
        }
    }

    /// `select_isolation_backend` against the live host — no policy
    /// flags. On Linux+KVM and macOS this returns `Admit`; on a
    /// non-Linux+non-macOS host the selector reports
    /// `NoSubstrateForPlatform`. Any non-conformant tier falls back
    /// to `TierBelowR1` (FallbackOnly without the unsafe flag) which
    /// is the production-correct behaviour.
    #[test]
    fn select_isolation_backend_returns_typed_outcome_for_host() {
        let result = select_isolation_backend(&SelectorInputs::new("/tmp/raxis-rt-test"));
        match result {
            Ok(selected) => {
                assert!(matches!(
                    selected.tier,
                    IsolationLevel::R1Conformant | IsolationLevel::R1ConformantStrong,
                ));
                // Backend id is the platform-stable identifier.
                let id = selected.backend.backend_id();
                assert!(
                    id == "firecracker-1.x" || id == "apple-vz-14.x",
                    "unexpected backend_id: {id}",
                );
            }
            Err(SelectError::TierBelowR1 { tier, .. }) => {
                // Linux without /dev/kvm or macOS in unentitled CI.
                // Either is a valid production-correct refusal.
                assert!(matches!(tier, IsolationLevel::FallbackOnly));
            }
            Err(SelectError::NoSubstrateForPlatform { .. }) => {
                // Never on the canonical Linux/macOS hosts; matches
                // the V2 platform list.
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn fallback_admission_with_unsafe_flag_returns_bypass_required_flag() {
        let r = run_admit(IsolationLevel::FallbackOnly, true, false)
            .unwrap_or_else(|e| panic!("FallbackOnly with unsafe flag must admit: {e:?}"));
        assert!(r.fallback_bypass_required);
    }

    #[test]
    fn selector_inputs_default_disallows_fallback_and_wasm() {
        let inputs = SelectorInputs::new("/tmp/raxis-x");
        assert!(!inputs.allow_fallback);
        assert!(!inputs.allow_wasm_sandbox);
        assert_eq!(inputs.runtime_dir, PathBuf::from("/tmp/raxis-x"));
    }
}
