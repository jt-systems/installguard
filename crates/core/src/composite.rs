//! Fan-out [`SignalProvider`] that calls multiple child providers
//! concurrently and concatenates their results.
//!
//! ## Behaviour
//!
//! - [`CompositeProvider::supports`] returns `true` if **any**
//!   child supports the dependency. Children that don't support
//!   the ecosystem are simply skipped at `signals()` time — no
//!   error is recorded for them.
//! - [`CompositeProvider::signals`] dispatches all supporting
//!   children in parallel via `futures::future::join_all` and
//!   collects every successful signal. A child that returns
//!   `Err(_)` is **not** propagated; instead a single
//!   [`Signal::Unavailable`] is emitted carrying that child's id
//!   and the error message. This keeps the composite call
//!   infallible from the caller's perspective — partial fan-out
//!   degradation is the steady state when one upstream catalogue
//!   has a bad day.
//!
//! ## What this is not
//!
//! - Not a cache. Wrap with `installguard_cache::CachedProvider`
//!   externally if cross-run caching is wanted.
//! - Not a load balancer. Every child is called for every
//!   supported dependency on every request.
//! - Not a deduplicator. If two children both produce the same
//!   advisory id, both signals appear in the output. Downstream
//!   policy / VEX layers are responsible for collapsing
//!   equivalent reasons; we deliberately preserve provenance.

use async_trait::async_trait;

use crate::dependency::ResolvedDependency;
use crate::signal::{Signal, SignalError, SignalProvider};

pub struct CompositeProvider {
    children: Vec<Box<dyn SignalProvider>>,
}

impl std::fmt::Debug for CompositeProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeProvider")
            .field(
                "children",
                &self
                    .children
                    .iter()
                    .map(|c| SignalProvider::id(&**c))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl CompositeProvider {
    #[must_use]
    pub fn new(children: Vec<Box<dyn SignalProvider>>) -> Self {
        Self { children }
    }

    /// Borrows the underlying child providers in order. Useful
    /// for tests that need to introspect composition.
    #[must_use]
    pub fn children(&self) -> &[Box<dyn SignalProvider>] {
        &self.children
    }
}

#[async_trait]
impl SignalProvider for CompositeProvider {
    fn id(&self) -> &'static str {
        "composite"
    }

    fn supports(&self, dep: &ResolvedDependency) -> bool {
        self.children.iter().any(|c| c.supports(dep))
    }

    async fn signals(&self, dep: &ResolvedDependency) -> Result<Vec<Signal>, SignalError> {
        let supporting: Vec<&Box<dyn SignalProvider>> =
            self.children.iter().filter(|c| c.supports(dep)).collect();
        let futs = supporting.iter().map(|c| async move {
            let id = c.id();
            (id, c.signals(dep).await)
        });
        let results = futures::future::join_all(futs).await;
        let mut out = Vec::new();
        for (id, res) in results {
            match res {
                Ok(mut sigs) => out.append(&mut sigs),
                Err(e) => out.push(Signal::Unavailable {
                    provider: id.to_string(),
                    reason: e.to_string(),
                }),
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependency::{Ecosystem, Source};

    fn dep() -> ResolvedDependency {
        ResolvedDependency {
            ecosystem: Ecosystem::Npm,
            name: "x".into(),
            version: "1.0.0".into(),
            integrity: None,
            source: Source::Registry { url: String::new() },
            direct: true,
            requested_by: Vec::new(),
        }
    }

    struct StaticProvider {
        id: &'static str,
        out: Vec<Signal>,
    }
    #[async_trait]
    impl SignalProvider for StaticProvider {
        fn id(&self) -> &'static str {
            self.id
        }
        fn supports(&self, _dep: &ResolvedDependency) -> bool {
            true
        }
        async fn signals(&self, _dep: &ResolvedDependency) -> Result<Vec<Signal>, SignalError> {
            Ok(self.out.clone())
        }
    }

    struct FailingProvider;
    #[async_trait]
    impl SignalProvider for FailingProvider {
        fn id(&self) -> &'static str {
            "boom"
        }
        fn supports(&self, _dep: &ResolvedDependency) -> bool {
            true
        }
        async fn signals(&self, _dep: &ResolvedDependency) -> Result<Vec<Signal>, SignalError> {
            Err(SignalError::Network("nope".into()))
        }
    }

    struct UnsupportedProvider;
    #[async_trait]
    impl SignalProvider for UnsupportedProvider {
        fn id(&self) -> &'static str {
            "unsupp"
        }
        fn supports(&self, _dep: &ResolvedDependency) -> bool {
            false
        }
        async fn signals(&self, _dep: &ResolvedDependency) -> Result<Vec<Signal>, SignalError> {
            panic!("must not be called when supports() is false");
        }
    }

    #[tokio::test]
    async fn fans_out_and_concatenates_in_child_order() {
        let composite = CompositeProvider::new(vec![
            Box::new(StaticProvider {
                id: "a",
                out: vec![Signal::ProvenanceClaimed {
                    bundle_url: "u1".into(),
                }],
            }),
            Box::new(StaticProvider {
                id: "b",
                out: vec![Signal::ProvenanceClaimed {
                    bundle_url: "u2".into(),
                }],
            }),
        ]);
        let sigs = composite.signals(&dep()).await.unwrap();
        assert_eq!(sigs.len(), 2);
        match (&sigs[0], &sigs[1]) {
            (
                Signal::ProvenanceClaimed { bundle_url: u1 },
                Signal::ProvenanceClaimed { bundle_url: u2 },
            ) => {
                assert_eq!(u1, "u1");
                assert_eq!(u2, "u2");
            }
            _ => panic!("unexpected signal shape"),
        }
    }

    #[tokio::test]
    async fn child_error_becomes_unavailable_signal() {
        let composite = CompositeProvider::new(vec![
            Box::new(StaticProvider {
                id: "ok",
                out: vec![Signal::ProvenanceClaimed {
                    bundle_url: "u".into(),
                }],
            }),
            Box::new(FailingProvider),
        ]);
        let sigs = composite.signals(&dep()).await.unwrap();
        assert_eq!(sigs.len(), 2);
        assert!(matches!(
            sigs[1],
            Signal::Unavailable { ref provider, .. } if provider == "boom"
        ));
    }

    #[tokio::test]
    async fn unsupported_children_are_skipped() {
        let composite = CompositeProvider::new(vec![
            Box::new(UnsupportedProvider),
            Box::new(StaticProvider {
                id: "ok",
                out: vec![Signal::ProvenanceClaimed {
                    bundle_url: "u".into(),
                }],
            }),
        ]);
        let sigs = composite.signals(&dep()).await.unwrap();
        assert_eq!(sigs.len(), 1);
    }

    #[test]
    fn supports_is_or_of_children() {
        let composite = CompositeProvider::new(vec![
            Box::new(UnsupportedProvider),
            Box::new(FailingProvider),
        ]);
        assert!(composite.supports(&dep()));
        let none = CompositeProvider::new(vec![Box::new(UnsupportedProvider)]);
        assert!(!none.supports(&dep()));
    }
}
