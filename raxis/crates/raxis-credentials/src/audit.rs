//! `AuditingBackend` — a transparent decorator that wraps any
//! [`CredentialBackend`] impl and emits the spec-mandated
//! `CredentialAccessed` / `CredentialRotated` events without the
//! concrete impl having to repeat the audit step in each `resolve`
//! / `rotate`.
//!
//! Normative reference: `extensibility-traits.md §4.3` ("Files to
//! create — `crates/raxis-credentials/src/audit.rs`: wraps any inner
//! backend with the `CredentialAccessed` audit emission so individual
//! impls don't all repeat the audit step").
//!
//! # Why a decorator instead of a default-impl on the trait
//!
//! Two reasons:
//!   1. **Default trait impls cannot capture `Arc<dyn AuditSink>`
//!      from constructor wiring.** Every concrete impl would still
//!      have to take an `Arc<dyn AuditSink>` in its constructor and
//!      thread it through. The decorator owns the sink once.
//!   2. **The decorator is independent of the inner backend's
//!      synchronisation.** The inner impl's `resolve` / `rotate`
//!      mechanics (file locking, Vault HTTP calls, HSM PKCS#11)
//!      can stay focused on storage; the decorator only reads the
//!      result and emits one event.
//!
//! # Audit-emission failure mode
//!
//! Per `R-7`, the kernel treats a sink-write failure as fatal —
//! [`emit_credential_accessed`] returns
//! [`CredentialError::AuditEmissionFailed`] which propagates up to
//! the kernel, which aborts boot or kills the in-flight handler.
//! The decorator does NOT swallow audit failures.

use std::sync::Arc;

use raxis_audit_tools::AuditSink;

use crate::{
    emit_credential_accessed, emit_credential_rotated, ConsumerIdentity, CredentialBackend,
    CredentialError, CredentialName, CredentialValue, Lease, OperatorId,
};

/// A decorator over `Arc<dyn CredentialBackend>` that emits the
/// `CredentialAccessed` / `CredentialRotated` events on every
/// resolve and rotate. The kernel constructs this around its
/// chosen concrete backend at boot:
///
/// ```ignore
/// let inner: Arc<dyn CredentialBackend> = Arc::new(FileCredentialBackend::open(...));
/// let with_audit: Arc<dyn CredentialBackend> = Arc::new(AuditingBackend::new(inner, audit_sink));
/// ctx.credentials = with_audit;
/// ```
pub struct AuditingBackend {
    inner: Arc<dyn CredentialBackend>,
    audit: Arc<dyn AuditSink>,
}

impl AuditingBackend {
    /// Wrap an inner backend with audit emission. The inner
    /// backend's `resolve` and `rotate` are called verbatim; this
    /// decorator only adds the audit step on either side.
    pub fn new(inner: Arc<dyn CredentialBackend>, audit: Arc<dyn AuditSink>) -> Self {
        Self { inner, audit }
    }

    /// Inner-backend handle. Useful in tests when you want to
    /// inspect the wrapped concrete impl without un-wrapping the
    /// `Arc<dyn ...>`.
    pub fn inner(&self) -> &Arc<dyn CredentialBackend> { &self.inner }
}

impl CredentialBackend for AuditingBackend {
    fn resolve(
        &self,
        name: &CredentialName,
        consumer: ConsumerIdentity<'_>,
    ) -> Result<CredentialValue, CredentialError> {
        let result = self.inner.resolve(name, consumer);
        // Emit audit unconditionally — both success and failure
        // are interesting to the operator. The success flag flips
        // accordingly.
        emit_credential_accessed(
            &self.audit,
            name,
            consumer,
            self.inner.backend_kind(),
            result.is_ok(),
        )?;
        result
    }

    fn rotate(
        &self,
        name: &CredentialName,
        new: CredentialValue,
        actor: OperatorId,
    ) -> Result<(), CredentialError> {
        // Forward to inner first; only emit `CredentialRotated`
        // on success (failures don't constitute a rotation).
        self.inner.rotate(name, new, actor.clone())?;
        emit_credential_rotated(&self.audit, name, &actor, self.inner.backend_kind())?;
        Ok(())
    }

    fn exists(&self, name: &CredentialName) -> bool {
        self.inner.exists(name)
    }

    fn lease(&self, name: &CredentialName) -> Lease {
        self.inner.lease(name)
    }

    fn backend_kind(&self) -> &'static str {
        self.inner.backend_kind()
    }
}
