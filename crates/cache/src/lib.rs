//! Persistent signal cache backed by `sled`.
//!
//! Wraps any [`SignalProvider`] in a [`CachedProvider`] that consults the
//! on-disk store before issuing a network request. Entries older than the
//! configured TTL are refetched. Negative results (`Signal::Unavailable`)
//! are cached too, with a shorter TTL so transient registry hiccups don't
//! get pinned for hours.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use installguard_core::dependency::ResolvedDependency;
use installguard_core::signal::{Signal, SignalError, SignalProvider};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("sled: {0}")]
    Sled(#[from] sled::Error),
    #[error("encode: {0}")]
    Encode(#[from] serde_json::Error),
}

/// Time-to-live policy for cache entries.
#[derive(Debug, Clone, Copy)]
pub struct Ttl {
    /// TTL applied when at least one signal was successfully produced.
    pub success: Duration,
    /// TTL applied when *every* signal is `Unavailable`.
    pub failure: Duration,
}

impl Default for Ttl {
    fn default() -> Self {
        // DESIGN.md §3.4: registry metadata 6h. Failures get 5 minutes so a
        // network blip doesn't block iteration.
        Self {
            success: Duration::from_secs(6 * 3600),
            failure: Duration::from_secs(5 * 60),
        }
    }
}

/// Schema version stamped into every value. Bump whenever the *content*
/// of cached signals changes in a way that would mislead the policy
/// engine if read back verbatim — e.g. when a signal that was previously
/// emitted is no longer emitted, or when a signal's field semantics
/// change. Pure additive changes (a new `Signal` variant) do not need
/// a bump because old entries simply won't carry the new variant.
///
/// In practice, since 0.1.17 the on-disk entries are *also* stamped
/// with the producing tool's `CARGO_PKG_VERSION`, and any version
/// mismatch on read drops the entry just like a schema mismatch. That
/// belt-and-braces design means signal-shape changes that ship
/// without a `SCHEMA_VERSION` bump still invalidate cleanly across
/// releases — closing the historical foot-gun where users had to
/// `rm -rf ~/Library/Caches/installguard` after every upgrade.
///
/// History:
///   1 — initial release (v0.1.0).
///   2 — v0.1.2: `npm-registry` no longer emits `LifecycleScripts` for
///       `prepare` (registry tarballs never run it) and tolerates
///       non-string `deprecated` packument fields. Caches written by
///       v0.1.0 / v0.1.1 contain stale `prepare` entries and stale
///       `Unavailable { provider: "npm-registry" }` entries for any
///       package whose packument hit the decode bug; bumping forces a
///       refetch on first use under v0.1.2.
const SCHEMA_VERSION: u32 = 2;
/// Sled tree name. Changing this implicitly invalidates older caches.
const TREE_NAME: &str = "signals_v1";

/// Producing tool version baked into every entry on write. A read whose
/// stored `tool_version` differs from this value is treated as stale and
/// dropped. This is the load-bearing safety net behind
/// [`SCHEMA_VERSION`]: signal-shape changes that ship without a
/// schema bump still invalidate on the next release.
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    schema: u32,
    /// Tool version that produced this entry (added in 0.1.17). Older
    /// entries written before this field existed deserialize with the
    /// default (`String::new()`), which never equals
    /// [`TOOL_VERSION`] — so they are dropped on first read under
    /// 0.1.17+.
    #[serde(default)]
    tool_version: String,
    fetched_at: DateTime<Utc>,
    signals: Vec<Signal>,
}

/// Public projection of a cache entry for callers performing TTL checks.
#[derive(Debug, Clone)]
pub struct CachedEntry {
    pub fetched_at: DateTime<Utc>,
    pub signals: Vec<Signal>,
}

#[derive(Debug, Clone)]
pub struct SignalCache {
    tree: sled::Tree,
}

impl SignalCache {
    pub fn open(path: &Path) -> Result<Self, CacheError> {
        let db = sled::Config::new()
            .path(path)
            .cache_capacity(64 * 1024 * 1024)
            .open()?;
        let tree = db.open_tree(TREE_NAME)?;
        Ok(Self { tree })
    }

    pub fn get(&self, key: &str) -> Result<Option<Vec<Signal>>, CacheError> {
        let Some(bytes) = self.tree.get(key)? else {
            return Ok(None);
        };
        match serde_json::from_slice::<Entry>(&bytes) {
            Ok(entry) if entry.schema == SCHEMA_VERSION && entry.tool_version == TOOL_VERSION => {
                Ok(Some(entry.signals))
            }
            // Drop entries from older schemas or older tool versions; they'll be refetched.
            _ => {
                let _ = self.tree.remove(key)?;
                Ok(None)
            }
        }
    }

    /// Variant that also returns when the entry was fetched. Used by
    /// `CachedProvider` for TTL checks.
    pub fn get_with_age(&self, key: &str) -> Result<Option<CachedEntry>, CacheError> {
        let Some(bytes) = self.tree.get(key)? else {
            return Ok(None);
        };
        match serde_json::from_slice::<Entry>(&bytes) {
            Ok(entry) if entry.schema == SCHEMA_VERSION && entry.tool_version == TOOL_VERSION => {
                Ok(Some(CachedEntry {
                    fetched_at: entry.fetched_at,
                    signals: entry.signals,
                }))
            }
            _ => {
                let _ = self.tree.remove(key)?;
                Ok(None)
            }
        }
    }

    pub fn put(&self, key: &str, signals: &[Signal]) -> Result<(), CacheError> {
        let entry = Entry {
            schema: SCHEMA_VERSION,
            tool_version: TOOL_VERSION.to_string(),
            fetched_at: Utc::now(),
            signals: signals.to_vec(),
        };
        let bytes = serde_json::to_vec(&entry)?;
        self.tree.insert(key, bytes)?;
        Ok(())
    }

    pub fn flush(&self) -> Result<(), CacheError> {
        self.tree.flush()?;
        Ok(())
    }

    /// Total number of entries (including any that would be dropped
    /// on read). Cheap — sled tracks this internally.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Iterate every entry and report a per-status breakdown. Designed
    /// for `installguard cache info` — not for hot paths.
    pub fn stats(&self) -> Result<CacheStats, CacheError> {
        let mut stats = CacheStats::default();
        for kv in &self.tree {
            let (_, bytes) = kv?;
            stats.total += 1;
            match serde_json::from_slice::<Entry>(&bytes) {
                Ok(entry)
                    if entry.schema == SCHEMA_VERSION && entry.tool_version == TOOL_VERSION =>
                {
                    stats.fresh += 1;
                }
                Ok(entry) if entry.schema != SCHEMA_VERSION => {
                    stats.stale_schema += 1;
                }
                Ok(_) => {
                    stats.stale_version += 1;
                }
                Err(_) => {
                    stats.unreadable += 1;
                }
            }
        }
        Ok(stats)
    }

    /// Drop every entry. Used by `installguard cache clear`.
    pub fn clear(&self) -> Result<(), CacheError> {
        self.tree.clear()?;
        self.tree.flush()?;
        Ok(())
    }
}

/// Per-status breakdown of cache contents. Returned by
/// [`SignalCache::stats`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    pub total: usize,
    /// Entries whose `schema` and `tool_version` both match the
    /// current build — will be served from cache subject to TTL.
    pub fresh: usize,
    /// Entries written by an older `SCHEMA_VERSION`. Will be dropped
    /// on next read.
    pub stale_schema: usize,
    /// Entries written by a different tool version (older or
    /// newer). Will be dropped on next read.
    pub stale_version: usize,
    /// Entries whose JSON payload no longer parses. Will be dropped
    /// on next read.
    pub unreadable: usize,
}

impl CacheStats {
    /// Sum of all non-fresh categories — entries that occupy disk
    /// space but will never be served.
    #[must_use]
    pub fn drop_on_next_read(self) -> usize {
        self.stale_schema + self.stale_version + self.unreadable
    }
}

/// `SignalProvider` decorator that consults a `SignalCache` before falling
/// through to the inner provider.
#[derive(Debug)]
pub struct CachedProvider<P> {
    inner: P,
    cache: Arc<SignalCache>,
    ttl: Ttl,
}

impl<P: SignalProvider> CachedProvider<P> {
    pub fn new(inner: P, cache: Arc<SignalCache>, ttl: Ttl) -> Self {
        Self { inner, cache, ttl }
    }
}

#[async_trait::async_trait]
impl<P: SignalProvider> SignalProvider for CachedProvider<P> {
    fn id(&self) -> &'static str {
        self.inner.id()
    }

    fn supports(&self, dep: &ResolvedDependency) -> bool {
        self.inner.supports(dep)
    }

    async fn signals(&self, dep: &ResolvedDependency) -> Result<Vec<Signal>, SignalError> {
        let key = cache_key(self.inner.id(), dep);
        let now = Utc::now();

        if let Ok(Some(entry)) = self.cache.get_with_age(&key) {
            let age = now.signed_duration_since(entry.fetched_at).to_std().ok();
            let ttl = if all_unavailable(&entry.signals) {
                self.ttl.failure
            } else {
                self.ttl.success
            };
            if let Some(age) = age {
                if age < ttl {
                    tracing::trace!(key, "cache hit");
                    return Ok(entry.signals);
                }
            }
            tracing::trace!(key, "cache stale");
        }

        let fresh = self.inner.signals(dep).await?;
        if let Err(err) = self.cache.put(&key, &fresh) {
            tracing::warn!(%err, key, "failed to write cache entry");
        }
        Ok(fresh)
    }
}

fn all_unavailable(signals: &[Signal]) -> bool {
    !signals.is_empty()
        && signals
            .iter()
            .all(|s| matches!(s, Signal::Unavailable { .. }))
}

fn cache_key(provider: &str, dep: &ResolvedDependency) -> String {
    let registry = dep.ecosystem.registry_family().as_str();
    // `\x1f` (unit separator) keeps the components unambiguously delimited
    // even if a package name contains `/` or `@`.
    format!(
        "{provider}\x1f{registry}\x1f{}\x1f{}",
        dep.name, dep.version
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use installguard_core::dependency::{Ecosystem, Source};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn dep(name: &str, version: &str) -> ResolvedDependency {
        ResolvedDependency {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: version.into(),
            integrity: None,
            source: Source::Registry { url: String::new() },
            direct: true,
            requested_by: vec![],
        }
    }

    #[derive(Debug)]
    struct Counting {
        calls: AtomicUsize,
        signals: Vec<Signal>,
    }

    #[async_trait::async_trait]
    impl SignalProvider for Counting {
        fn id(&self) -> &'static str {
            "counting"
        }
        fn supports(&self, _: &ResolvedDependency) -> bool {
            true
        }
        async fn signals(&self, _: &ResolvedDependency) -> Result<Vec<Signal>, SignalError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.signals.clone())
        }
    }

    #[tokio::test]
    async fn second_call_is_served_from_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = Arc::new(SignalCache::open(tmp.path()).unwrap());
        let inner = Counting {
            calls: AtomicUsize::new(0),
            signals: vec![Signal::PublishedAt { at: Utc::now() }],
        };
        // Move `inner` in but read its counter via the wrapper's `inner`.
        let wrapped = CachedProvider::new(inner, cache.clone(), Ttl::default());

        let d = dep("axios", "1.7.9");
        let _ = wrapped.signals(&d).await.unwrap();
        let _ = wrapped.signals(&d).await.unwrap();
        let _ = wrapped.signals(&d).await.unwrap();
        assert_eq!(wrapped.inner.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unavailable_uses_short_ttl() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = Arc::new(SignalCache::open(tmp.path()).unwrap());
        let inner = Counting {
            calls: AtomicUsize::new(0),
            signals: vec![Signal::Unavailable {
                provider: "x".into(),
                reason: "down".into(),
            }],
        };
        let ttl = Ttl {
            success: Duration::from_secs(3600),
            failure: Duration::from_millis(0), // expires instantly
        };
        let wrapped = CachedProvider::new(inner, cache.clone(), ttl);

        let d = dep("axios", "1.7.9");
        let _ = wrapped.signals(&d).await.unwrap();
        let _ = wrapped.signals(&d).await.unwrap();
        // Failure entry is treated as stale immediately, so two upstream calls.
        assert_eq!(wrapped.inner.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn keys_are_stable_and_distinct() {
        let a = cache_key("npm-registry", &dep("axios", "1.0.0"));
        let b = cache_key("npm-registry", &dep("axios", "1.0.1"));
        let c = cache_key("npm-registry", &dep("@scope/axios", "1.0.0"));
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, cache_key("npm-registry", &dep("axios", "1.0.0")));
    }

    /// Entries written by an older tool version (or by a release that
    /// shipped before stamping existed) are treated as stale and
    /// dropped on first read \u2014 even when the schema number still
    /// matches. This is the safety net behind the historical "rm -rf
    /// the cache after every upgrade" foot-gun.
    #[test]
    fn entry_with_mismatched_tool_version_is_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SignalCache::open(tmp.path()).unwrap();
        let key = "k";
        let stale = Entry {
            schema: SCHEMA_VERSION,
            tool_version: "0.0.0-from-the-before-times".into(),
            fetched_at: Utc::now(),
            signals: vec![Signal::PublishedAt { at: Utc::now() }],
        };
        cache
            .tree
            .insert(key, serde_json::to_vec(&stale).unwrap())
            .unwrap();
        assert_eq!(cache.len(), 1);
        // First read drops it.
        assert!(cache.get(key).unwrap().is_none());
        assert_eq!(cache.len(), 0);
    }

    /// Legacy entries from before the `tool_version` field existed
    /// deserialise with the default empty string and are dropped on
    /// first read \u2014 same path as a true version mismatch. Guards
    /// against in-place upgrades from 0.1.16 and earlier.
    #[test]
    fn legacy_entry_without_tool_version_is_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SignalCache::open(tmp.path()).unwrap();
        let key = "k";
        // Hand-rolled JSON in the pre-0.1.17 shape (no tool_version field).
        let raw = format!(
            r#"{{"schema":{SCHEMA_VERSION},"fetched_at":"{}","signals":[]}}"#,
            Utc::now().to_rfc3339()
        );
        cache.tree.insert(key, raw.as_bytes()).unwrap();
        assert!(cache.get(key).unwrap().is_none());
    }

    #[test]
    fn stats_breaks_down_by_status() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SignalCache::open(tmp.path()).unwrap();
        // Fresh: schema and version both current.
        cache
            .put("fresh", &[Signal::PublishedAt { at: Utc::now() }])
            .unwrap();
        // Stale by version.
        let stale_v = Entry {
            schema: SCHEMA_VERSION,
            tool_version: "0.0.0".into(),
            fetched_at: Utc::now(),
            signals: vec![],
        };
        cache
            .tree
            .insert("stale-v", serde_json::to_vec(&stale_v).unwrap())
            .unwrap();
        // Stale by schema.
        let stale_s = Entry {
            schema: SCHEMA_VERSION + 99,
            tool_version: TOOL_VERSION.to_string(),
            fetched_at: Utc::now(),
            signals: vec![],
        };
        cache
            .tree
            .insert("stale-s", serde_json::to_vec(&stale_s).unwrap())
            .unwrap();
        // Unreadable.
        cache.tree.insert("garbage", b"not json".to_vec()).unwrap();

        let stats = cache.stats().unwrap();
        assert_eq!(stats.total, 4);
        assert_eq!(stats.fresh, 1);
        assert_eq!(stats.stale_version, 1);
        assert_eq!(stats.stale_schema, 1);
        assert_eq!(stats.unreadable, 1);
        assert_eq!(stats.drop_on_next_read(), 3);
    }

    #[test]
    fn clear_drops_every_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SignalCache::open(tmp.path()).unwrap();
        cache
            .put("a", &[Signal::PublishedAt { at: Utc::now() }])
            .unwrap();
        cache
            .put("b", &[Signal::PublishedAt { at: Utc::now() }])
            .unwrap();
        assert_eq!(cache.len(), 2);
        cache.clear().unwrap();
        assert!(cache.is_empty());
    }
}
