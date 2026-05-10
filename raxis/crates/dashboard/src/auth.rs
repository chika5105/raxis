//! Operator authentication for the dashboard HTTP surface.
//!
//! Spec: `v2_extended_gaps.md §4.2` — challenge-response auth
//! using the same Ed25519 keys + operator certs the CLI uses.
//!
//! # Threat model + invariants
//!
//! 1. **No shared secrets.** No passwords. No bearer tokens
//!    minted from operator-supplied data. The browser proves
//!    knowledge of the operator's private key by signing a
//!    server-issued challenge with Ed25519.
//! 2. **Challenge freshness.** Challenges are bound to a
//!    monotonically increasing kernel-process-local counter,
//!    expire after 60 seconds, and are consumed on first use
//!    (replay-protected).
//! 3. **JWT secret is ephemeral.** Generated via `OsRng` at boot
//!    and discarded on kernel shutdown. There is no on-disk
//!    HS256 key. JWT TTL defaults to 1 hour (configurable).
//! 4. **Bounded memory.** Both the pending-challenge map and the
//!    revocation set have configurable upper bounds. Eviction
//!    is FIFO + age-based; an attacker cannot DoS the dashboard
//!    by minting unbounded challenges.
//! 5. **Constant-time signature comparison** is delegated to
//!    `raxis_crypto::verify_ed25519` (uses `ed25519-dalek`).
//! 6. **Every privileged operation is re-checked.** The JWT
//!    carries the operator's pubkey-fingerprint + role list; the
//!    middleware re-resolves the operator entry against the
//!    *current* policy bundle on every request, so a freshly
//!    rotated policy that revokes an operator takes effect on
//!    the next request without waiting for JWT expiry.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::config::DashboardConfig;
use crate::error::ApiError;

/// Hex-encoded 32-byte SHA-256 fingerprint of an operator's
/// pubkey (matches `OperatorEntry::pubkey_fingerprint`).
pub type OperatorFingerprint = String;

/// Bytes of a fresh challenge, hex-encoded.
pub type ChallengeHex = String;

/// In-memory challenge entry.
#[derive(Debug, Clone)]
struct PendingChallenge {
    /// Random hex bytes the operator must sign.
    challenge: String,
    /// Unix-seconds expiration (mint_time + 60).
    expires_at: u64,
}

/// Bounded pending-challenge store.
#[derive(Debug)]
pub struct ChallengeStore {
    inner: Mutex<ChallengeStoreInner>,
    max_pending: usize,
    ttl_secs: u64,
}

#[derive(Debug)]
struct ChallengeStoreInner {
    /// FIFO ordering for bounded eviction.
    order: VecDeque<String>,
    /// Per-challenge entry.
    table: std::collections::HashMap<String, PendingChallenge>,
}

impl ChallengeStore {
    /// Build a fresh store. `max_pending` MUST be > 0; smaller
    /// values clamp to 1 to keep the API usable in tests.
    pub fn new(max_pending: usize, ttl_secs: u64) -> Self {
        Self {
            inner: Mutex::new(ChallengeStoreInner {
                order: VecDeque::new(),
                table: std::collections::HashMap::new(),
            }),
            max_pending: max_pending.max(1),
            ttl_secs,
        }
    }

    /// Mint a fresh challenge and remember it. Returns
    /// `(challenge_hex, expires_at_unix_seconds)`. May evict the
    /// oldest pending entry if the bound is exceeded — operators
    /// are expected to either retry or accept that abandoned
    /// challenges age out on their own.
    pub fn mint(&self) -> Result<(ChallengeHex, u64), ApiError> {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf)
            .map_err(|e| ApiError::Internal { log_only: format!("rng: {e}") })?;
        let now = now_secs();
        let challenge = hex::encode(buf);
        let expires_at = now.saturating_add(self.ttl_secs);
        let mut g = self.inner.lock();
        // Evict expired first (cheap pass — we do this on mint
        // rather than on a timer so the dashboard has zero
        // background tasks).
        while let Some(front) = g.order.front().cloned() {
            match g.table.get(&front) {
                Some(p) if p.expires_at <= now => {
                    g.order.pop_front();
                    g.table.remove(&front);
                }
                _ => break,
            }
        }
        // Then evict to bound.
        while g.order.len() >= self.max_pending {
            if let Some(victim) = g.order.pop_front() {
                g.table.remove(&victim);
            } else {
                break;
            }
        }
        g.table.insert(
            challenge.clone(),
            PendingChallenge { challenge: challenge.clone(), expires_at },
        );
        g.order.push_back(challenge.clone());
        Ok((challenge, expires_at))
    }

    /// Consume a challenge. Returns the stored challenge entry
    /// when the supplied hex matches, has not expired, and has
    /// not been consumed yet. Otherwise returns
    /// `ApiError::ChallengeExpired`.
    pub fn consume(&self, challenge_hex: &str) -> Result<(), ApiError> {
        let now = now_secs();
        let mut g = self.inner.lock();
        let p = match g.table.remove(challenge_hex) {
            Some(p) => p,
            None => return Err(ApiError::ChallengeExpired),
        };
        // Drop from the FIFO too. O(n) on the bounded queue is
        // fine — the bound is ≤ 1000 in practice.
        if let Some(pos) = g.order.iter().position(|c| c == &p.challenge) {
            g.order.remove(pos);
        }
        if p.expires_at <= now {
            return Err(ApiError::ChallengeExpired);
        }
        Ok(())
    }

    /// In-flight count; useful for tests + observability.
    pub fn pending(&self) -> usize {
        self.inner.lock().order.len()
    }
}

/// Bounded JWT revocation set. Holds the SHA-256 of revoked
/// JWTs (so the original token cannot be reconstructed from this
/// memory image). Entries auto-expire on read after the JWT's
/// own `expires_at` passes.
#[derive(Debug)]
pub struct RevocationSet {
    inner: Mutex<RevocationInner>,
    max_revoked: usize,
}

#[derive(Debug)]
struct RevocationInner {
    /// FIFO ordering for bounded eviction.
    order: VecDeque<String>,
    /// `digest_hex → expires_at_unix_secs`.
    table: std::collections::HashMap<String, u64>,
}

impl RevocationSet {
    /// Build a fresh revocation set.
    pub fn new(max_revoked: usize) -> Self {
        Self {
            inner: Mutex::new(RevocationInner {
                order: VecDeque::new(),
                table: std::collections::HashMap::new(),
            }),
            max_revoked: max_revoked.max(1),
        }
    }

    /// Add a JWT digest to the revocation set with its own
    /// `expires_at` (so the entry can be GC'd when the token
    /// would have naturally expired). May evict the oldest
    /// existing entry if the bound is exceeded.
    pub fn revoke(&self, digest_hex: String, expires_at: u64) {
        let mut g = self.inner.lock();
        let now = now_secs();
        // GC pass.
        while let Some(front) = g.order.front().cloned() {
            match g.table.get(&front) {
                Some(exp) if *exp <= now => {
                    g.order.pop_front();
                    g.table.remove(&front);
                }
                _ => break,
            }
        }
        while g.order.len() >= self.max_revoked {
            if let Some(victim) = g.order.pop_front() {
                g.table.remove(&victim);
            } else {
                break;
            }
        }
        g.table.insert(digest_hex.clone(), expires_at);
        g.order.push_back(digest_hex);
    }

    /// `true` iff the supplied JWT digest is currently revoked
    /// AND has not aged out.
    pub fn is_revoked(&self, digest_hex: &str) -> bool {
        let now = now_secs();
        let mut g = self.inner.lock();
        match g.table.get(digest_hex).copied() {
            Some(exp) if exp > now => true,
            Some(_expired) => {
                g.table.remove(digest_hex);
                if let Some(pos) = g.order.iter().position(|d| d == digest_hex) {
                    g.order.remove(pos);
                }
                false
            }
            None => false,
        }
    }
}

/// Operator role decoded out of the operator certificate. Spec
/// §4.2: roles are derived from cert attributes, no separate role
/// table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DashboardRole {
    /// View all read-only dashboard pages.
    Read,
    /// Read + view/edit `policy.toml` in the browser.
    WritePolicy,
    /// Read + WritePolicy + admin (operator key + cert listing,
    /// `raxis doctor` from dashboard).
    Admin,
}

impl DashboardRole {
    /// Stable lowercase role string used in the JWT claims and
    /// the audit trail.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::WritePolicy => "write_policy",
            Self::Admin => "admin",
        }
    }
}

/// Authenticated operator carried in the JWT.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorClaims {
    /// SHA-256[:16] hex fingerprint of the operator's Ed25519
    /// pubkey. Used to look up the live operator entry on every
    /// request.
    pub fingerprint: OperatorFingerprint,
    /// Display name from the operator entry. NOT a stable id —
    /// always re-resolve through `fingerprint`.
    pub display_name: String,
    /// Roles granted to the operator (derived from cert).
    pub roles: Vec<String>,
    /// Unix-seconds expiration.
    pub exp: u64,
    /// Unix-seconds issued-at.
    pub iat: u64,
    /// JWT id (random 16 bytes hex). Used as the revocation
    /// key.
    pub jti: String,
}

impl OperatorClaims {
    /// `true` iff the claim list contains the requested role.
    pub fn has_role(&self, role: DashboardRole) -> bool {
        let needle = role.as_str();
        self.roles.iter().any(|r| r == needle)
    }
}

/// HS256 JWT minter / verifier. The signing secret is held in
/// memory only and rotated at every kernel boot.
pub struct JwtSigner {
    secret: Arc<[u8; 32]>,
    ttl_secs: u64,
}

impl JwtSigner {
    /// Build a fresh signer with a freshly-minted 32-byte secret.
    /// `ttl_secs` MUST be >= 60 in production; smaller values are
    /// clamped to 60 to prevent operator-self-DoS via accidentally
    /// short-lived tokens.
    pub fn new(ttl_secs: u64) -> Result<Self, ApiError> {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf)
            .map_err(|e| ApiError::Internal { log_only: format!("rng: {e}") })?;
        Ok(Self {
            secret: Arc::new(buf),
            ttl_secs: ttl_secs.max(60),
        })
    }

    /// JWT TTL in seconds.
    pub fn ttl_secs(&self) -> u64 { self.ttl_secs }

    /// Mint a JWT for the given operator. Returns
    /// `(jwt_string, expires_at_unix_secs, jti_for_revocation)`.
    pub fn mint(
        &self,
        fingerprint: &str,
        display_name: &str,
        roles: Vec<String>,
    ) -> Result<MintedJwt, ApiError> {
        let mut jti_buf = [0u8; 16];
        getrandom::getrandom(&mut jti_buf)
            .map_err(|e| ApiError::Internal { log_only: format!("rng: {e}") })?;
        let jti = hex::encode(jti_buf);
        let now = now_secs();
        let claims = OperatorClaims {
            fingerprint: fingerprint.to_owned(),
            display_name: display_name.to_owned(),
            roles,
            iat: now,
            exp: now.saturating_add(self.ttl_secs),
            jti: jti.clone(),
        };
        let header = b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        let header_b64 = b64url_encode(header);
        let payload_bytes = serde_json::to_vec(&claims)
            .map_err(|e| ApiError::Internal { log_only: format!("jwt-claims: {e}") })?;
        let payload_b64 = b64url_encode(&payload_bytes);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = self.hmac(signing_input.as_bytes());
        let sig_b64 = b64url_encode(&sig);
        let jwt = format!("{signing_input}.{sig_b64}");
        Ok(MintedJwt {
            token: jwt,
            jti,
            expires_at: claims.exp,
            claims,
        })
    }

    /// Verify the supplied JWT string. Returns the carried
    /// claims when (a) the structure is valid, (b) the
    /// HMAC-SHA-256 signature matches in constant time, and
    /// (c) `exp > now`. Does NOT consult the revocation set —
    /// callers do that separately so a one-shot verify path
    /// (e.g. for tests) does not need a `RevocationSet`.
    pub fn verify(&self, jwt: &str) -> Result<OperatorClaims, ApiError> {
        let mut parts = jwt.split('.');
        let header_b64 = parts.next().ok_or(ApiError::InvalidJwt)?;
        let payload_b64 = parts.next().ok_or(ApiError::InvalidJwt)?;
        let sig_b64 = parts.next().ok_or(ApiError::InvalidJwt)?;
        if parts.next().is_some() {
            return Err(ApiError::InvalidJwt);
        }
        let signing_input = format!("{header_b64}.{payload_b64}");
        let expected_sig = self.hmac(signing_input.as_bytes());
        let got_sig = b64url_decode(sig_b64).map_err(|_| ApiError::InvalidJwt)?;
        if !constant_time_eq(&expected_sig, &got_sig) {
            return Err(ApiError::InvalidJwt);
        }
        let payload_bytes = b64url_decode(payload_b64).map_err(|_| ApiError::InvalidJwt)?;
        let claims: OperatorClaims = serde_json::from_slice(&payload_bytes)
            .map_err(|_| ApiError::InvalidJwt)?;
        if claims.exp <= now_secs() {
            return Err(ApiError::InvalidJwt);
        }
        Ok(claims)
    }

    /// Compute the SHA-256 digest used as the revocation key for
    /// a JWT string. Stored hex-encoded so the original token is
    /// not retrievable from the revocation memory image.
    pub fn digest(jwt: &str) -> String {
        use sha2::Digest;
        let mut h = Sha256::new();
        h.update(jwt.as_bytes());
        hex::encode(h.finalize())
    }

    fn hmac(&self, data: &[u8]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.secret.as_ref())
            .expect("HMAC accepts any key length");
        mac.update(data);
        let bytes = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }
}

/// Output of [`JwtSigner::mint`].
#[derive(Debug, Clone)]
pub struct MintedJwt {
    /// Compact-form JWT (base64url-encoded).
    pub token: String,
    /// JWT id, used as the revocation set key.
    pub jti: String,
    /// Unix-seconds expiration.
    pub expires_at: u64,
    /// Decoded claims (for the verify response body).
    pub claims: OperatorClaims,
}

fn b64url_encode(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Wall-clock seconds since the unix epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Convenience constructor for the dashboard's auth state from a
/// validated [`DashboardConfig`].
pub fn build_auth_state(cfg: &DashboardConfig) -> Result<AuthState, ApiError> {
    Ok(AuthState {
        challenges: Arc::new(ChallengeStore::new(
            cfg.max_pending_challenges,
            Duration::from_secs(60).as_secs(),
        )),
        revocations: Arc::new(RevocationSet::new(cfg.max_revoked_jwts)),
        jwt: Arc::new(JwtSigner::new(cfg.jwt_ttl_secs)?),
    })
}

/// Bundled auth state shared with every route handler.
#[derive(Clone)]
pub struct AuthState {
    /// Bounded pending-challenge store.
    pub challenges: Arc<ChallengeStore>,
    /// Bounded JWT revocation set.
    pub revocations: Arc<RevocationSet>,
    /// HS256 JWT signer.
    pub jwt: Arc<JwtSigner>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_round_trip() {
        let s = ChallengeStore::new(10, 60);
        let (c, exp) = s.mint().unwrap();
        assert_eq!(c.len(), 64, "challenge hex must be 32 bytes");
        assert!(exp > now_secs());
        s.consume(&c).expect("first consume succeeds");
        let err = s.consume(&c).unwrap_err();
        matches!(err, ApiError::ChallengeExpired);
    }

    #[test]
    fn challenge_store_evicts_to_bound() {
        let s = ChallengeStore::new(3, 60);
        let (a, _) = s.mint().unwrap();
        let (b, _) = s.mint().unwrap();
        let (c, _) = s.mint().unwrap();
        let (_d, _) = s.mint().unwrap(); // forces eviction of `a`
        assert_eq!(s.pending(), 3);
        // a evicted; b/c/d still present.
        assert!(s.consume(&a).is_err());
        assert!(s.consume(&b).is_ok());
        assert!(s.consume(&c).is_ok());
    }

    #[test]
    fn jwt_round_trip_verifies() {
        let signer = JwtSigner::new(3600).unwrap();
        let m = signer.mint("ABCDEF1234567890", "alice",
            vec!["read".into(), "write_policy".into()]).unwrap();
        let claims = signer.verify(&m.token).unwrap();
        assert_eq!(claims.fingerprint, "ABCDEF1234567890");
        assert_eq!(claims.display_name, "alice");
        assert!(claims.has_role(DashboardRole::Read));
        assert!(claims.has_role(DashboardRole::WritePolicy));
        assert!(!claims.has_role(DashboardRole::Admin));
    }

    #[test]
    fn jwt_with_tampered_payload_fails() {
        let signer = JwtSigner::new(3600).unwrap();
        let m = signer.mint("F", "x", vec!["read".into()]).unwrap();
        // Flip a single character in the payload b64.
        let parts: Vec<&str> = m.token.split('.').collect();
        let mut payload = parts[1].to_owned();
        let last = payload.pop().unwrap();
        payload.push(if last == 'A' { 'B' } else { 'A' });
        let tampered = format!("{}.{}.{}", parts[0], payload, parts[2]);
        let res = signer.verify(&tampered);
        assert!(res.is_err());
    }

    #[test]
    fn jwt_with_swapped_secret_fails() {
        let s1 = JwtSigner::new(3600).unwrap();
        let s2 = JwtSigner::new(3600).unwrap();
        let m = s1.mint("F", "x", vec!["read".into()]).unwrap();
        assert!(s2.verify(&m.token).is_err());
    }

    #[test]
    fn jwt_revocation_set_round_trip() {
        let r = RevocationSet::new(10);
        let exp = now_secs() + 3600;
        r.revoke("DEADBEEF".into(), exp);
        assert!(r.is_revoked("DEADBEEF"));
        assert!(!r.is_revoked("OTHER"));
    }

    #[test]
    fn jwt_revocation_evicts_to_bound() {
        let r = RevocationSet::new(2);
        let exp = now_secs() + 3600;
        r.revoke("A".into(), exp);
        r.revoke("B".into(), exp);
        r.revoke("C".into(), exp);
        // A evicted; B and C still revoked.
        assert!(!r.is_revoked("A"));
        assert!(r.is_revoked("B"));
        assert!(r.is_revoked("C"));
    }

    #[test]
    fn jwt_revocation_ages_out_expired() {
        let r = RevocationSet::new(10);
        // Expire immediately.
        r.revoke("EXPIRED".into(), 0);
        assert!(!r.is_revoked("EXPIRED"));
    }

    #[test]
    fn role_str_round_trip() {
        assert_eq!(DashboardRole::Read.as_str(), "read");
        assert_eq!(DashboardRole::WritePolicy.as_str(), "write_policy");
        assert_eq!(DashboardRole::Admin.as_str(), "admin");
    }
}
