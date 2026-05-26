//! Plan/Policy Builder helper endpoints.
//!
//! These endpoints are deliberately read-only. They exist so the
//! dashboard can ask the kernel-facing data layer to validate draft
//! TOML before an operator signs/submits it, while preserving the
//! invariant that the kernel remains the authority for admission and
//! policy epoch advance.

use axum::extract::State;
use axum::Json;
use serde::Deserialize;

use crate::auth::DashboardRole;
use crate::data::BuilderValidationResponse;
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

/// Request body for builder validation endpoints.
#[derive(Debug, Clone, Deserialize)]
pub struct ValidateBuilderRequest {
    /// Draft TOML source to validate.
    pub toml: String,
}

/// `POST /api/builders/plan/validate`.
pub async fn validate_plan<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Json(body): Json<ValidateBuilderRequest>,
) -> ApiResult<Json<BuilderValidationResponse>>
where
    D: crate::data::DashboardData,
{
    require_read(&op)?;
    let response = state
        .data
        .validate_plan_builder_toml(&op.fingerprint, &body.toml)?;
    Ok(Json(response))
}

/// `POST /api/builders/policy/validate`.
pub async fn validate_policy<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
    Json(body): Json<ValidateBuilderRequest>,
) -> ApiResult<Json<BuilderValidationResponse>>
where
    D: crate::data::DashboardData,
{
    if !op.has_role(DashboardRole::WritePolicy) && !op.has_role(DashboardRole::Admin) {
        return Err(ApiError::Forbidden {
            required: "write_policy".into(),
        });
    }
    let response = state
        .data
        .validate_policy_builder_toml(&op.fingerprint, &body.toml)?;
    Ok(Json(response))
}

fn require_read(op: &AuthorizedOperator) -> ApiResult<()> {
    if !op.has_role(DashboardRole::Read)
        && !op.has_role(DashboardRole::WritePolicy)
        && !op.has_role(DashboardRole::Admin)
    {
        return Err(ApiError::Forbidden {
            required: "read".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::auth::OperatorClaims;
    use crate::config::DashboardConfig;
    use crate::data::InMemoryDashboardData;
    use crate::server::{AppStateInner, ShutdownSignal};

    #[tokio::test]
    async fn plan_validation_is_read_only_and_available_to_read_role() {
        let data = InMemoryDashboardData::new();
        let resp = validate_plan(
            State(app_state(&data)),
            op_with_roles("reader", vec![DashboardRole::Read]),
            Json(ValidateBuilderRequest {
                toml: r#"
[workspace]
name = "Demo"

[[tasks]]
task_id = "t1"
"#
                .to_owned(),
            }),
        )
        .await
        .expect("read role can validate plan drafts");

        assert_eq!(resp.0.artifact_kind, "plan");
        assert_eq!(resp.0.authority, "kernel");
        assert!(resp.0.ok, "fixture plan validation should be ok");
    }

    #[tokio::test]
    async fn policy_validation_requires_policy_write_or_admin() {
        let data = InMemoryDashboardData::new();
        let read_only = validate_policy(
            State(app_state(&data)),
            op_with_roles("reader", vec![DashboardRole::Read]),
            Json(ValidateBuilderRequest {
                toml: "[meta]\nepoch = 2\n".to_owned(),
            }),
        )
        .await;
        assert!(
            matches!(read_only, Err(ApiError::Forbidden { .. })),
            "read-only operators must not validate policy drafts"
        );

        let write = validate_policy(
            State(app_state(&data)),
            op_with_roles(
                "writer",
                vec![DashboardRole::Read, DashboardRole::WritePolicy],
            ),
            Json(ValidateBuilderRequest {
                toml: "[meta]\nepoch = 2\n".to_owned(),
            }),
        )
        .await
        .expect("write_policy role can validate policy drafts");
        assert_eq!(write.0.artifact_kind, "policy");
    }

    fn app_state(data: &Arc<InMemoryDashboardData>) -> AppState<InMemoryDashboardData> {
        let cfg = DashboardConfig {
            enabled: true,
            ..Default::default()
        };
        let auth = crate::auth::build_auth_state(&cfg).expect("build auth");
        Arc::new(AppStateInner {
            data: Arc::clone(data),
            auth,
            config: cfg,
            shutdown: ShutdownSignal::new(),
            observability: None,
            sse_active: Arc::new(std::sync::atomic::AtomicI64::new(0)),
        })
    }

    fn op_with_roles(name: &str, roles: Vec<DashboardRole>) -> AuthorizedOperator {
        let role_names: Vec<String> = roles.iter().map(|r| r.as_str().to_owned()).collect();
        AuthorizedOperator {
            fingerprint: format!("fp-{name}"),
            display_name: name.to_owned(),
            roles,
            claims: OperatorClaims {
                fingerprint: format!("fp-{name}"),
                display_name: name.to_owned(),
                roles: role_names,
                exp: 0,
                iat: 0,
                jti: format!("jti-{name}"),
                gen: 1,
            },
        }
    }
}
