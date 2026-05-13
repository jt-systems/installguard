//! npm registry signal provider.
//!
//! Hits `GET {registry}/{name}` (the packument) and extracts:
//! * publish time for the resolved version (`PublishedAt`)
//! * declared lifecycle scripts (`LifecycleScripts`)
//!
//! The packument response is large but stable. Future milestones add ETag
//! revalidation and an on-disk cache (DESIGN.md §3.4).

use chrono::{DateTime, Utc};
use installguard_core::dependency::{Ecosystem, ResolvedDependency};
use installguard_core::signal::{Signal, SignalError, SignalProvider};
use serde::Deserialize;
use std::collections::HashMap;

const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org";
const USER_AGENT: &str = concat!("installguard/", env!("CARGO_PKG_VERSION"));

/// Lifecycle script names treated as security-relevant.
/// `prepare` runs on `npm install` from a git source — included.
const LIFECYCLE_SCRIPTS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "preuninstall",
    "postuninstall",
];

#[derive(Debug)]
pub struct NpmRegistryProvider {
    client: reqwest::Client,
    registry: String,
}

impl NpmRegistryProvider {
    pub fn new() -> Result<Self, reqwest::Error> {
        Self::with_registry(DEFAULT_REGISTRY)
    }

    pub fn with_registry(registry: impl Into<String>) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self {
            client,
            registry: registry.into().trim_end_matches('/').to_string(),
        })
    }
}

#[async_trait::async_trait]
impl SignalProvider for NpmRegistryProvider {
    fn id(&self) -> &'static str {
        "npm-registry"
    }

    fn supports(&self, dep: &ResolvedDependency) -> bool {
        matches!(
            dep.ecosystem,
            Ecosystem::Npm | Ecosystem::Pnpm | Ecosystem::Yarn
        )
    }

    async fn signals(&self, dep: &ResolvedDependency) -> Result<Vec<Signal>, SignalError> {
        let url = format!("{}/{}", self.registry, encode_name(&dep.name));
        tracing::debug!(url, "fetching packument");

        let resp = self
            .client
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| SignalError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            return Ok(vec![Signal::Unavailable {
                provider: "npm-registry".into(),
                reason: format!("HTTP {}", resp.status()),
            }]);
        }

        let body: Packument = resp
            .json()
            .await
            .map_err(|e| SignalError::Decode(e.to_string()))?;

        let mut out = Vec::new();
        if let Some(t) = body.time.get(&dep.version) {
            out.push(Signal::PublishedAt { at: *t });
        } else {
            out.push(Signal::Unavailable {
                provider: "npm-registry".into(),
                reason: format!("no time entry for {}@{}", dep.name, dep.version),
            });
        }

        if let Some(version_meta) = body.versions.get(&dep.version) {
            let scripts: Vec<String> = version_meta
                .scripts
                .as_ref()
                .map(|m| {
                    m.keys()
                        .filter(|k| LIFECYCLE_SCRIPTS.contains(&k.as_str()))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            if !scripts.is_empty() {
                out.push(Signal::LifecycleScripts { scripts });
            }
        }

        Ok(out)
    }
}

fn encode_name(name: &str) -> String {
    // Scoped names need their `/` percent-encoded for the packument URL.
    name.replacen('/', "%2F", 1)
}

#[derive(Debug, Deserialize)]
struct Packument {
    #[serde(default)]
    time: HashMap<String, DateTime<Utc>>,
    #[serde(default)]
    versions: HashMap<String, VersionMeta>,
}

#[derive(Debug, Deserialize)]
struct VersionMeta {
    #[serde(default)]
    scripts: Option<HashMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_names_are_encoded() {
        assert_eq!(encode_name("@scope/pkg"), "@scope%2Fpkg");
        assert_eq!(encode_name("axios"), "axios");
    }
}
