//! V3 cloud-forwarding in-memory token cache.
//!
//! Normative reference: `specs/v3/cloud-proxy-forwarding.md §4`.
//!
//! The cache is `tokio::sync::RwLock<HashMap<CacheKey,
//! CachedToken<T>>>` plus a parallel `Mutex<HashMap<CacheKey,
//! Arc<Mutex<()>>>>` for single-flight refresh guards. A safety
//! window (default 5 minutes; minimum 60 seconds) controls when
//! a cache hit triggers a background refresh.
//!
//! # Single-flight refresh
//!
//! Concurrent requests for the same `CacheKey` whose cached
//! token is in the safety window MUST trigger at most one
//! background refresh. The cache maintains an
//! `Arc<tokio::sync::Mutex<()>>` per key; the first caller that
//! successfully `try_lock_owned`s the mutex owns the refresh.
//!
//! # Persistence
//!
//! The cache deliberately does NOT implement `Serialize`. There
//! is no path that writes a cached token to disk. The wrapped
//! payload type is expected to be `Drop`-zeroising (typically
//! a `secrecy::SecretBox<...>`).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, RwLock};

/// Cache key. Provider-specific stringification — the per-provider
/// crate decides what to fold into the key (e.g. `role_arn` +
/// `session_name` + `external_id_hash` + `duration` for AWS).
///
/// The key string MUST NOT contain credential material (the
/// `external_id` is hashed before being folded in; the
/// `client_secret` is never in the key).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey(String);

impl CacheKey {
    /// Construct from an already-rendered stable key string.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Borrow the inner key string. Useful for tracing / debug
    /// paths (never includes credential material).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CacheKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One cache entry: the short-lived payload + expiry / refresh
/// timestamps. The payload is held inside `Arc<T>` so concurrent
/// readers do not clone the bytes; the `T` is expected to be a
/// zeroising wrapper (e.g. `secrecy::SecretBox<...>`).
pub struct CachedToken<T: Send + Sync + 'static> {
    /// Provider-specific short-lived credential payload.
    pub payload: Arc<T>,
    /// Wall-clock instant the upstream said this expires.
    pub expires_at: Instant,
    /// When the cache observed / installed this entry.
    pub refreshed_at: Instant,
}

impl<T: Send + Sync + 'static> Clone for CachedToken<T> {
    fn clone(&self) -> Self {
        Self {
            payload: Arc::clone(&self.payload),
            expires_at: self.expires_at,
            refreshed_at: self.refreshed_at,
        }
    }
}

impl<T: Send + Sync + 'static> CachedToken<T> {
    /// Age since the entry was installed.
    pub fn age(&self) -> Duration {
        Instant::now().saturating_duration_since(self.refreshed_at)
    }

    /// Remaining TTL until expiry. `Duration::ZERO` once expired.
    pub fn ttl_remaining(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }

    /// `true` when the entry is within `safety_window` of
    /// expiry. Such entries are still served from cache (per
    /// `INV-CLOUD-FWD-06`) but trigger a background refresh.
    pub fn is_stale(&self, safety_window: Duration) -> bool {
        self.ttl_remaining() < safety_window
    }

    /// `true` when the entry is past its `expires_at`. Expired
    /// entries are NOT served from cache; the request path
    /// blocks on an upstream call.
    pub fn is_expired(&self) -> bool {
        self.ttl_remaining() == Duration::ZERO
    }
}

/// In-memory short-lived-token cache keyed by [`CacheKey`].
///
/// Safe to share across tasks via `Arc<TokenCache<T>>`. The
/// internal `RwLock` allows concurrent reads (the common case
/// — cache hit) and serialises writes (cache install on
/// refresh).
pub struct TokenCache<T: Send + Sync + 'static> {
    /// Mapping of key → cached token. Only ever contains
    /// successfully-installed tokens.
    tokens: RwLock<HashMap<CacheKey, CachedToken<T>>>,
    /// Per-key refresh-lock map. Used to enforce single-flight
    /// refresh — at most one task at a time may refresh a given
    /// key.
    refresh_locks: Mutex<HashMap<CacheKey, Arc<Mutex<()>>>>,
    /// Refresh-ahead safety window. Tokens within this much of
    /// their expiry are "stale" and trigger a background
    /// refresh, but are still served from cache while the
    /// refresh runs.
    safety_window: Duration,
}

impl<T: Send + Sync + 'static> TokenCache<T> {
    /// Build a cache with `safety_window` as the refresh-ahead
    /// boundary. Per spec the minimum is 60 seconds; anything
    /// shorter is clamped to 60 seconds with a `tracing::warn!`.
    pub fn new(safety_window: Duration) -> Self {
        let clamped = if safety_window < Duration::from_secs(60) {
            tracing::warn!(
                requested_ms = safety_window.as_millis() as u64,
                "cache safety window below 60s minimum; clamping to 60s",
            );
            Duration::from_secs(60)
        } else {
            safety_window
        };
        Self {
            tokens: RwLock::new(HashMap::new()),
            refresh_locks: Mutex::new(HashMap::new()),
            safety_window: clamped,
        }
    }

    /// Configured safety window.
    pub fn safety_window(&self) -> Duration {
        self.safety_window
    }

    /// Look up a key and return a clone of the cached token
    /// when present and not expired. Returns `None` when the
    /// entry is missing or fully expired. `is_stale = true`
    /// entries ARE returned here — the caller is expected to
    /// trigger a background refresh via [`Self::take_refresh_lock`].
    pub async fn get(&self, key: &CacheKey) -> Option<CachedToken<T>> {
        let guard = self.tokens.read().await;
        let entry = guard.get(key)?;
        if entry.is_expired() {
            None
        } else {
            Some(entry.clone())
        }
    }

    /// Insert (or replace) a cache entry. Used by the per-provider
    /// proxy after a successful upstream exchange.
    pub async fn insert(&self, key: CacheKey, payload: T, expires_in: Duration) {
        let now = Instant::now();
        let entry = CachedToken {
            payload: Arc::new(payload),
            expires_at: now + expires_in,
            refreshed_at: now,
        };
        let mut guard = self.tokens.write().await;
        guard.insert(key, entry);
    }

    /// Best-effort acquisition of the per-key refresh lock. The
    /// returned guard is `Some` when the caller has the
    /// exclusive right to refresh this key (and should drive
    /// the upstream call); `None` when another task is already
    /// refreshing.
    pub async fn take_refresh_lock(&self, key: &CacheKey) -> Option<RefreshGuard> {
        // Resolve (or install) the per-key Mutex.
        let lock = {
            let mut guard = self.refresh_locks.lock().await;
            Arc::clone(
                guard
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        // Non-blocking acquire. Existing holders → None.
        let g = lock.try_lock_owned().ok()?;
        Some(RefreshGuard { _inner: g })
    }

    /// Evict an entry (e.g. on credential rotation). The
    /// payload's `Drop` zeroes the underlying bytes; the
    /// per-key refresh lock is also dropped (released).
    pub async fn evict(&self, key: &CacheKey) {
        {
            let mut tokens = self.tokens.write().await;
            tokens.remove(key);
        }
        let mut locks = self.refresh_locks.lock().await;
        locks.remove(key);
    }

    /// Drop every cached entry. Called by the proxy on
    /// shutdown. `INV-CLOUD-FWD-03`.
    pub async fn clear(&self) {
        {
            let mut tokens = self.tokens.write().await;
            tokens.clear();
        }
        let mut locks = self.refresh_locks.lock().await;
        locks.clear();
    }

    /// Test-only: number of entries currently cached.
    #[cfg(test)]
    pub async fn len(&self) -> usize {
        self.tokens.read().await.len()
    }

    /// Test-only: whether the cache currently holds zero entries.
    #[cfg(test)]
    pub async fn is_empty(&self) -> bool {
        self.tokens.read().await.is_empty()
    }
}

/// RAII guard held while a refresh is in flight. Dropping the
/// guard releases the per-key single-flight lock so another
/// concurrent request can attempt a refresh.
#[must_use = "RefreshGuard must be held until the refresh completes"]
pub struct RefreshGuard {
    _inner: tokio::sync::OwnedMutexGuard<()>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone)]
    struct DummyToken {
        value: String,
    }

    #[tokio::test]
    async fn fresh_insert_and_get_round_trip() {
        let cache: TokenCache<DummyToken> = TokenCache::new(Duration::from_secs(60));
        cache
            .insert(
                CacheKey::new("k1"),
                DummyToken { value: "v1".into() },
                Duration::from_secs(300),
            )
            .await;
        let got = cache.get(&CacheKey::new("k1")).await.unwrap();
        assert_eq!(got.payload.value, "v1");
        assert!(got.ttl_remaining() > Duration::from_secs(60));
        assert!(!got.is_stale(Duration::from_secs(60)));
    }

    #[tokio::test]
    async fn safety_window_below_minimum_is_clamped() {
        let cache: TokenCache<DummyToken> = TokenCache::new(Duration::from_secs(10));
        assert_eq!(cache.safety_window(), Duration::from_secs(60));
    }

    #[tokio::test]
    async fn stale_within_safety_window_is_still_served() {
        let cache: TokenCache<DummyToken> = TokenCache::new(Duration::from_secs(60));
        cache
            .insert(
                CacheKey::new("k1"),
                DummyToken { value: "v1".into() },
                Duration::from_secs(30), // less than safety window
            )
            .await;
        let got = cache.get(&CacheKey::new("k1")).await.unwrap();
        assert!(got.is_stale(Duration::from_secs(60)));
        assert!(!got.is_expired());
    }

    #[tokio::test]
    async fn missing_key_returns_none() {
        let cache: TokenCache<DummyToken> = TokenCache::new(Duration::from_secs(60));
        assert!(cache.get(&CacheKey::new("unknown")).await.is_none());
    }

    #[tokio::test]
    async fn evict_clears_entry() {
        let cache: TokenCache<DummyToken> = TokenCache::new(Duration::from_secs(60));
        cache
            .insert(
                CacheKey::new("k1"),
                DummyToken { value: "v".into() },
                Duration::from_secs(300),
            )
            .await;
        cache.evict(&CacheKey::new("k1")).await;
        assert!(cache.get(&CacheKey::new("k1")).await.is_none());
    }

    #[tokio::test]
    async fn clear_drops_every_entry() {
        let cache: TokenCache<DummyToken> = TokenCache::new(Duration::from_secs(60));
        cache
            .insert(
                CacheKey::new("a"),
                DummyToken { value: "1".into() },
                Duration::from_secs(300),
            )
            .await;
        cache
            .insert(
                CacheKey::new("b"),
                DummyToken { value: "2".into() },
                Duration::from_secs(300),
            )
            .await;
        assert_eq!(cache.len().await, 2);
        cache.clear().await;
        assert_eq!(cache.len().await, 0);
    }

    #[tokio::test]
    async fn refresh_lock_is_single_flight() {
        let cache: Arc<TokenCache<DummyToken>> = Arc::new(TokenCache::new(Duration::from_secs(60)));
        // No pre-existing entry — the refresh lock should still
        // be acquirable on first call.
        let guard1 = cache.take_refresh_lock(&CacheKey::new("k1")).await;
        assert!(guard1.is_some(), "first call must acquire");
        let guard2 = cache.take_refresh_lock(&CacheKey::new("k1")).await;
        assert!(guard2.is_none(), "second concurrent call must NOT acquire");
        drop(guard1);
        let guard3 = cache.take_refresh_lock(&CacheKey::new("k1")).await;
        assert!(
            guard3.is_some(),
            "after first drop, third call must acquire"
        );
    }
}
