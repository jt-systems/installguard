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

        // Name-squat check is purely local — emit before any network
        // dependency so it surfaces even when the packument fetch
        // later degrades to `Unavailable`.
        if let installguard_core::name_similarity::Classification::Suspicious { kind, target } =
            installguard_core::name_similarity::classify(&dep.name)
        {
            out.push(Signal::NameSquat {
                style: kind.as_str().to_string(),
                target,
            });
        }

        if let Some(t) = body.time.get(&dep.version) {
            out.push(Signal::PublishedAt { at: *t });
        } else {
            out.push(Signal::Unavailable {
                provider: "npm-registry".into(),
                reason: format!("no time entry for {}@{}", dep.name, dep.version),
            });
        }

        if let Some(version_meta) = body.versions.get(&dep.version) {
            let lifecycle: Vec<(&String, &String)> = version_meta
                .scripts
                .as_ref()
                .map(|m| {
                    m.iter()
                        .filter(|(k, _)| LIFECYCLE_SCRIPTS.contains(&k.as_str()))
                        .collect()
                })
                .unwrap_or_default();
            if !lifecycle.is_empty() {
                out.push(Signal::LifecycleScripts {
                    scripts: lifecycle.iter().map(|(k, _)| (*k).clone()).collect(),
                });
                // Static analysis on the script body — same packument,
                // no extra fetch. One Signal per (script, pattern).
                for (name, body) in &lifecycle {
                    for finding in installguard_core::script_scan::scan(body) {
                        out.push(Signal::SuspiciousScript {
                            script: (*name).clone(),
                            pattern: finding.pattern.to_string(),
                            excerpt: finding.excerpt,
                        });
                    }
                }
            }
            if let Some(sig) = deprecation_signal(version_meta) {
                out.push(sig);
            }
        }

        if let Some(change) = detect_publisher_change(&body, &dep.version) {
            out.push(change);
        }
        if let Some(change) = detect_version_surface_change(&body, &dep.version) {
            out.push(change);
        }
        if let Some(anomaly) = detect_dist_tag_anomaly(&body) {
            out.push(anomaly);
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

/// Detects new `bin` entries and new lifecycle-script names introduced
/// between the immediately-prior released version and the resolved
/// version. Returns `None` if either version is unparseable, no prior
/// version exists, or nothing was added (we never emit an empty
/// signal). Removed entries are intentionally ignored — removals
/// don’t expand attack surface.
fn detect_version_surface_change(packument: &Packument, current_version: &str) -> Option<Signal> {
    let current_sem = Version::parse(current_version).ok()?;
    let current = packument.versions.get(current_version)?;

    let prev = packument
        .versions
        .iter()
        .filter_map(|(v, meta)| {
            let parsed = Version::parse(v).ok()?;
            if parsed >= current_sem {
                return None;
            }
            Some((parsed, v.as_str(), meta))
        })
        .max_by(|a, b| a.0.cmp(&b.0))?;

    let prev_bins: std::collections::BTreeSet<String> =
        bin_names(prev.2.bin.as_ref()).into_iter().collect();
    let cur_bins: std::collections::BTreeSet<String> =
        bin_names(current.bin.as_ref()).into_iter().collect();
    let mut added_bins: Vec<String> = cur_bins.difference(&prev_bins).cloned().collect();
    added_bins.sort();

    let prev_scripts: std::collections::BTreeSet<&str> = prev
        .2
        .scripts
        .as_ref()
        .map(|m| {
            m.keys()
                .map(String::as_str)
                .filter(|k| LIFECYCLE_SCRIPTS.contains(k))
                .collect()
        })
        .unwrap_or_default();
    let cur_scripts: std::collections::BTreeSet<&str> = current
        .scripts
        .as_ref()
        .map(|m| {
            m.keys()
                .map(String::as_str)
                .filter(|k| LIFECYCLE_SCRIPTS.contains(k))
                .collect()
        })
        .unwrap_or_default();
    let mut added_scripts: Vec<String> = cur_scripts
        .difference(&prev_scripts)
        .map(|s| (*s).to_string())
        .collect();
    added_scripts.sort();

    if added_bins.is_empty() && added_scripts.is_empty() {
        return None;
    }
    Some(Signal::VersionSurfaceChange {
        previous_version: prev.1.to_string(),
        added_bins,
        added_scripts,
    })
}

/// Normalises npm’s polymorphic `bin` field into a list of bin
/// *names*. The package.json schema allows either a map
/// `{name: path}` or a single string path; in the latter case there
/// is exactly one implicit bin and we use the sentinel
/// `"<single>"` so both sides of a diff see the same name. We only
/// ever compare names within the same package, so the sentinel is
/// safe and avoids leaking the package name through the API.
fn bin_names(bin: Option<&serde_json::Value>) -> Vec<String> {
    match bin {
        Some(serde_json::Value::String(_)) => vec!["<single>".to_string()],
        Some(serde_json::Value::Object(map)) => map.keys().cloned().collect(),
        _ => Vec::new(),
    }
}

/// Detects the “`latest` moved backwards” pattern: `dist-tags.latest`
/// resolves to a version that is strictly older than the highest
/// non-prerelease published version. Pre-releases are excluded from
/// the “highest” comparison because shipping `2.0.0-rc.1` while
/// `latest=1.4.0` is normal release-train behaviour, not an attack.
/// Returns `None` when there is no `latest` tag, the tag points to
/// an unparseable version, or the tag points at the maximum
/// non-prerelease version (the healthy case).
fn detect_dist_tag_anomaly(packument: &Packument) -> Option<Signal> {
    let latest = packument.dist_tags.get("latest")?;
    let latest_sem = Version::parse(latest).ok()?;

    let max_release = packument
        .versions
        .keys()
        .filter_map(|v| Version::parse(v).ok())
        .filter(|v| v.pre.is_empty())
        .max()?;

    if latest_sem >= max_release {
        None
    } else {
        Some(Signal::DistTagAnomaly {
            latest_version: latest.clone(),
            highest_published: max_release.to_string(),
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
    /// Top-level `dist-tags` map, e.g. `{ "latest": "1.2.3" }`.
    /// Used by [`detect_dist_tag_anomaly`].
    #[serde(default, rename = "dist-tags")]
    dist_tags: HashMap<String, String>,
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
    /// `bin` may be either a map of `{ name: path }` or a single string
    /// (whose key is the package name). We normalise via
    /// [`bin_names`].
    #[serde(default)]
    bin: Option<serde_json::Value>,
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
                        bin: None,
                    },
                )
            })
            .collect();
        Packument {
            time: HashMap::new(),
            versions,
            dist_tags: HashMap::new(),
        }
    }

    fn meta_with_deprecation(d: Option<&str>) -> VersionMeta {
        VersionMeta {
            scripts: None,
            npm_user: None,
            deprecated: d.map(str::to_string),
            bin: None,
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

    fn meta_with_bin_and_scripts(bin: serde_json::Value, scripts: &[(&str, &str)]) -> VersionMeta {
        let scripts_map = if scripts.is_empty() {
            None
        } else {
            Some(
                scripts
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
            )
        };
        VersionMeta {
            scripts: scripts_map,
            npm_user: None,
            deprecated: None,
            bin: Some(bin),
        }
    }

    fn surface_pkmt(prior: VersionMeta, current: VersionMeta) -> Packument {
        let mut versions = HashMap::new();
        versions.insert("1.0.0".to_string(), prior);
        versions.insert("1.0.1".to_string(), current);
        Packument {
            time: HashMap::new(),
            versions,
            dist_tags: HashMap::new(),
        }
    }

    #[test]
    fn surface_change_detects_added_bin_and_script() {
        let prior =
            meta_with_bin_and_scripts(serde_json::json!({ "foo": "./foo.js" }), &[("test", "tsc")]);
        let current = meta_with_bin_and_scripts(
            serde_json::json!({ "foo": "./foo.js", "bar": "./bar.js" }),
            &[("test", "tsc"), ("postinstall", "node ./pi.js")],
        );
        let p = surface_pkmt(prior, current);
        let s = detect_version_surface_change(&p, "1.0.1").expect("present");
        match s {
            Signal::VersionSurfaceChange {
                previous_version,
                added_bins,
                added_scripts,
            } => {
                assert_eq!(previous_version, "1.0.0");
                assert_eq!(added_bins, vec!["bar"]);
                assert_eq!(added_scripts, vec!["postinstall"]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn surface_change_returns_none_when_nothing_added() {
        let prior = meta_with_bin_and_scripts(
            serde_json::json!({ "foo": "./foo.js" }),
            &[("postinstall", "x")],
        );
        // Removed bin + removed script — must not fire.
        let current = meta_with_bin_and_scripts(serde_json::json!({}), &[]);
        let p = surface_pkmt(prior, current);
        assert!(detect_version_surface_change(&p, "1.0.1").is_none());
    }

    #[test]
    fn surface_change_no_prior_version_returns_none() {
        let only = meta_with_bin_and_scripts(
            serde_json::json!({ "foo": "./foo.js" }),
            &[("postinstall", "x")],
        );
        let mut versions = HashMap::new();
        versions.insert("1.0.0".to_string(), only);
        let p = Packument {
            time: HashMap::new(),
            versions,
            dist_tags: HashMap::new(),
        };
        assert!(detect_version_surface_change(&p, "1.0.0").is_none());
    }

    #[test]
    fn surface_change_string_form_bin_normalised() {
        // Both sides use the string form → same `<single>` sentinel,
        // so no spurious add. Then current adds a script.
        let prior = meta_with_bin_and_scripts(serde_json::json!("./cli.js"), &[("test", "x")]);
        let current = meta_with_bin_and_scripts(
            serde_json::json!("./cli.js"),
            &[("test", "x"), ("preinstall", "y")],
        );
        let p = surface_pkmt(prior, current);
        let s = detect_version_surface_change(&p, "1.0.1").expect("present");
        if let Signal::VersionSurfaceChange {
            added_bins,
            added_scripts,
            ..
        } = s
        {
            assert!(added_bins.is_empty());
            assert_eq!(added_scripts, vec!["preinstall"]);
        } else {
            panic!();
        }
    }

    #[test]
    fn surface_change_ignores_non_lifecycle_scripts() {
        // Adding a `lint` script must not trigger; only the
        // npm lifecycle script set counts.
        let prior = meta_with_bin_and_scripts(serde_json::json!({}), &[("test", "tsc")]);
        let current = meta_with_bin_and_scripts(
            serde_json::json!({}),
            &[("test", "tsc"), ("lint", "eslint .")],
        );
        let p = surface_pkmt(prior, current);
        assert!(detect_version_surface_change(&p, "1.0.1").is_none());
    }

    fn pkmt_with_dist_tags(versions: &[&str], dist_tags: &[(&str, &str)]) -> Packument {
        let versions = versions
            .iter()
            .map(|v| {
                (
                    (*v).to_string(),
                    VersionMeta {
                        scripts: None,
                        npm_user: None,
                        deprecated: None,
                        bin: None,
                    },
                )
            })
            .collect();
        let dist_tags = dist_tags
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        Packument {
            time: HashMap::new(),
            versions,
            dist_tags,
        }
    }

    #[test]
    fn dist_tag_anomaly_detects_latest_pointing_backwards() {
        let p = pkmt_with_dist_tags(&["1.0.0", "1.1.0", "2.0.0"], &[("latest", "1.1.0")]);
        match detect_dist_tag_anomaly(&p).expect("present") {
            Signal::DistTagAnomaly {
                latest_version,
                highest_published,
            } => {
                assert_eq!(latest_version, "1.1.0");
                assert_eq!(highest_published, "2.0.0");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn dist_tag_anomaly_quiet_when_latest_is_max() {
        let p = pkmt_with_dist_tags(&["1.0.0", "1.1.0", "2.0.0"], &[("latest", "2.0.0")]);
        assert!(detect_dist_tag_anomaly(&p).is_none());
    }

    #[test]
    fn dist_tag_anomaly_ignores_prereleases_in_max() {
        // 2.0.0-rc.1 must not count as the "real" max.
        let p = pkmt_with_dist_tags(&["1.0.0", "1.1.0", "2.0.0-rc.1"], &[("latest", "1.1.0")]);
        assert!(detect_dist_tag_anomaly(&p).is_none());
    }

    #[test]
    fn dist_tag_anomaly_no_latest_tag_returns_none() {
        let p = pkmt_with_dist_tags(&["1.0.0", "2.0.0"], &[("next", "2.0.0")]);
        assert!(detect_dist_tag_anomaly(&p).is_none());
    }
}
