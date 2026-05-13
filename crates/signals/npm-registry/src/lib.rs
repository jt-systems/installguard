//! npm registry signal provider.
//!
//! Hits `GET {registry}/{name}` (the packument) and extracts:
//! * publish time for the resolved version (`PublishedAt`)
//! * declared lifecycle scripts (`LifecycleScripts`)
//! * publisher change vs the immediately-prior released version
//!   (`PublisherChange`), comparing the npm account stored in
//!   `versions[v]._npmUser.name`.
//!
//! The packument response is large but stable. Future milestones add ETag
//! revalidation and an on-disk cache (DESIGN.md §3.4).

use chrono::{DateTime, Utc};
use installguard_core::dependency::{Ecosystem, ResolvedDependency};
use installguard_core::signal::{Signal, SignalError, SignalProvider};
use semver::Version;
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
            if let Some(sig) = deprecation_signal(version_meta) {
                out.push(sig);
            }
        }

        if let Some(change) = detect_publisher_change(&body, &dep.version) {
            out.push(change);
        }

        Ok(out)
    }
}

/// Builds a `DeprecatedVersion` signal from a packument version entry.
/// The wire field is `versions[v].deprecated`, a string. By npm
/// convention the presence of the field — even with an empty value
/// — is the deprecation marker; an absent field means "not
/// deprecated". An empty string normalises to `message = None`.
fn deprecation_signal(meta: &VersionMeta) -> Option<Signal> {
    let raw = meta.deprecated.as_deref()?;
    let message = if raw.is_empty() {
        None
    } else {
        Some(raw.to_string())
    };
    Some(Signal::DeprecatedVersion { message })
}

/// Compares `_npmUser.name` for `current_version` against the immediately
/// prior released version under semver ordering. Returns `None` when the
/// version is unparseable, when there is no prior version, or when either
/// version is missing publisher metadata. Pre-releases (`1.0.0-rc.1`) are
/// considered alongside releases — the highest version strictly less than
/// `current_version` wins.
fn detect_publisher_change(packument: &Packument, current_version: &str) -> Option<Signal> {
    let current_sem = Version::parse(current_version).ok()?;
    let current_publisher = packument
        .versions
        .get(current_version)
        .and_then(|m| m.npm_user.as_ref())
        .map(|u| u.name.as_str())?;

    let prev = packument
        .versions
        .iter()
        .filter_map(|(v, meta)| {
            let parsed = Version::parse(v).ok()?;
            if parsed >= current_sem {
                return None;
            }
            let publisher = meta.npm_user.as_ref()?.name.as_str();
            Some((parsed, v.as_str(), publisher))
        })
        .max_by(|a, b| a.0.cmp(&b.0))?;

    if prev.2 == current_publisher {
        None
    } else {
        Some(Signal::PublisherChange {
            previous_version: prev.1.to_string(),
            previous: prev.2.to_string(),
            current: current_publisher.to_string(),
        })
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
    /// `_npmUser` records the npm account that published this specific
    /// version. Field is `_npmUser` on the wire.
    #[serde(default, rename = "_npmUser")]
    npm_user: Option<NpmUser>,
    /// `deprecated` is a free-form string set by `npm deprecate`. The
    /// presence of the field — even with an empty value — is the
    /// deprecation marker. Absence means "not deprecated".
    #[serde(default)]
    deprecated: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NpmUser {
    name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_names_are_encoded() {
        assert_eq!(encode_name("@scope/pkg"), "@scope%2Fpkg");
        assert_eq!(encode_name("axios"), "axios");
    }

    fn pkmt(versions: &[(&str, Option<&str>)]) -> Packument {
        let versions = versions
            .iter()
            .map(|(v, user)| {
                (
                    (*v).to_string(),
                    VersionMeta {
                        scripts: None,
                        npm_user: user.map(|n| NpmUser {
                            name: n.to_string(),
                        }),
                        deprecated: None,
                    },
                )
            })
            .collect();
        Packument {
            time: HashMap::new(),
            versions,
        }
    }

    fn meta_with_deprecation(d: Option<&str>) -> VersionMeta {
        VersionMeta {
            scripts: None,
            npm_user: None,
            deprecated: d.map(str::to_string),
        }
    }

    #[test]
    fn deprecation_absent_field_returns_none() {
        let m = meta_with_deprecation(None);
        assert!(deprecation_signal(&m).is_none());
    }

    #[test]
    fn deprecation_empty_string_is_marker_with_no_message() {
        let m = meta_with_deprecation(Some(""));
        match deprecation_signal(&m).expect("present") {
            Signal::DeprecatedVersion { message } => assert!(message.is_none()),
            other => panic!("unexpected signal {other:?}"),
        }
    }

    #[test]
    fn deprecation_message_preserved_verbatim() {
        let m = meta_with_deprecation(Some("use foo@2 instead"));
        match deprecation_signal(&m).expect("present") {
            Signal::DeprecatedVersion { message } => {
                assert_eq!(message.as_deref(), Some("use foo@2 instead"));
            }
            other => panic!("unexpected signal {other:?}"),
        }
    }

    #[test]
    fn publisher_change_detected_against_prior_version() {
        let p = pkmt(&[
            ("1.0.0", Some("alice")),
            ("1.0.1", Some("alice")),
            ("1.1.0", Some("mallory")),
        ]);
        let s = detect_publisher_change(&p, "1.1.0").unwrap();
        match s {
            Signal::PublisherChange {
                previous_version,
                previous,
                current,
            } => {
                assert_eq!(previous_version, "1.0.1");
                assert_eq!(previous, "alice");
                assert_eq!(current, "mallory");
            }
            other => panic!("unexpected signal {other:?}"),
        }
    }

    #[test]
    fn publisher_change_silent_when_publisher_stable() {
        let p = pkmt(&[("1.0.0", Some("alice")), ("1.1.0", Some("alice"))]);
        assert!(detect_publisher_change(&p, "1.1.0").is_none());
    }

    #[test]
    fn publisher_change_silent_for_first_release() {
        let p = pkmt(&[("1.0.0", Some("alice"))]);
        assert!(detect_publisher_change(&p, "1.0.0").is_none());
    }

    #[test]
    fn publisher_change_silent_when_metadata_missing() {
        // No previous version has _npmUser → no signal (avoid false positive).
        let p = pkmt(&[("1.0.0", None), ("1.1.0", Some("mallory"))]);
        assert!(detect_publisher_change(&p, "1.1.0").is_none());

        // Current version has no publisher → can't compare.
        let p = pkmt(&[("1.0.0", Some("alice")), ("1.1.0", None)]);
        assert!(detect_publisher_change(&p, "1.1.0").is_none());
    }

    #[test]
    fn publisher_change_uses_highest_prior_under_semver() {
        // 2.0.0 is the resolved version. 1.10.0 (alice) > 1.2.0 (mallory)
        // under semver, so the comparison is alice vs eve.
        let p = pkmt(&[
            ("1.2.0", Some("mallory")),
            ("1.10.0", Some("alice")),
            ("2.0.0", Some("eve")),
        ]);
        let s = detect_publisher_change(&p, "2.0.0").unwrap();
        if let Signal::PublisherChange {
            previous_version,
            previous,
            ..
        } = s
        {
            assert_eq!(previous_version, "1.10.0");
            assert_eq!(previous, "alice");
        } else {
            panic!();
        }
    }

    #[test]
    fn publisher_change_skips_unparseable_versions() {
        // npm packuments occasionally contain non-semver tags; they must
        // not crash or shadow real prior versions.
        let p = pkmt(&[
            ("1.0.0", Some("alice")),
            ("not-semver", Some("ghost")),
            ("1.1.0", Some("mallory")),
        ]);
        let s = detect_publisher_change(&p, "1.1.0").unwrap();
        if let Signal::PublisherChange { previous, .. } = s {
            assert_eq!(previous, "alice");
        } else {
            panic!();
        }
    }
}
