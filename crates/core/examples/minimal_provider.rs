//! Minimal third-party `SignalProvider` example.
//!
//! Run with: `cargo run --example minimal_provider -p installguard-core`
//!
//! Demonstrates the full plugin contract in ~30 lines: a struct
//! that holds an in-memory blocklist of (name, version) tuples
//! and emits an `AdvisoryKnown` signal whenever a dependency
//! matches. A real internal-threat-intel provider would replace
//! the `HashSet` with whatever data source the team trusts.
//!
//! The example also shows how to fold a custom provider into the
//! built-in `CompositeProvider` so it runs alongside the standard
//! npm-registry / OSV / deps.dev / Scorecard providers.

use std::collections::HashSet;

use installguard_core::dependency::{Ecosystem, ResolvedDependency, Source};
use installguard_core::signal::{Signal, SignalError, SignalProvider};
use installguard_core::CompositeProvider;

pub struct InternalBlocklist {
    blocked: HashSet<(String, String)>,
}

impl std::fmt::Debug for InternalBlocklist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InternalBlocklist")
            .field("entries", &self.blocked.len())
            .finish()
    }
}

impl InternalBlocklist {
    pub fn new<I: IntoIterator<Item = (String, String)>>(items: I) -> Self {
        Self {
            blocked: items.into_iter().collect(),
        }
    }
}

#[async_trait::async_trait]
impl SignalProvider for InternalBlocklist {
    fn id(&self) -> &'static str {
        "internal-blocklist"
    }

    fn supports(&self, dep: &ResolvedDependency) -> bool {
        matches!(dep.ecosystem, Ecosystem::Npm)
    }

    async fn signals(&self, dep: &ResolvedDependency) -> Result<Vec<Signal>, SignalError> {
        if self
            .blocked
            .contains(&(dep.name.clone(), dep.version.clone()))
        {
            return Ok(vec![Signal::AdvisoryKnown {
                id: format!("INTERNAL:{}:{}", dep.name, dep.version),
                severity: "high".into(),
                summary: "matched internal blocklist".into(),
                source: "internal-blocklist".into(),
            }]);
        }
        Ok(Vec::new())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Compose the custom provider with whatever others the host
    // already runs. The composite is itself a `SignalProvider`,
    // so the same wrapper would work inside `CachedProvider` or
    // any other layered host plumbing.
    let provider = CompositeProvider::new(vec![Box::new(InternalBlocklist::new([(
        "evil".into(),
        "1.0.0".into(),
    )]))]);
    let dep = ResolvedDependency {
        ecosystem: Ecosystem::Npm,
        name: "evil".into(),
        version: "1.0.0".into(),
        integrity: None,
        source: Source::Registry { url: String::new() },
        direct: true,
        requested_by: Vec::new(),
    };
    let sigs = provider.signals(&dep).await.expect("infallible composite");
    println!(
        "{} signal(s) produced for {}@{}",
        sigs.len(),
        dep.name,
        dep.version
    );
    for s in sigs {
        println!("  - {s:?}");
    }
}
