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
use std::sync::Mutex;

const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org";
const USER_AGENT: &str = concat!("installguard/", env!("CARGO_PKG_VERSION"));

/// Lifecycle script names treated as security-relevant for
/// **registry-sourced** dependencies.
///
/// Notably absent: `prepare`. The npm registry runs `prepare`
/// **only** when a package is installed from a git source (so the
/// consumer can compile the source tree on the fly). When the same
/// package is installed from the registry, npm uses the
/// pre-published tarball and never invokes `prepare`. Reporting
/// `prepare` for registry deps therefore generates noise on every
/// package that defines a build-time `prepare` script (Husky,
/// TypeScript libraries, etc.) without flagging anything that can
/// actually execute on the user's machine.
///
/// Git-sourced dependencies are gated separately by the
/// `Source::Git` rules in policy.rs; the npm registry adapter
/// only ever sees registry packuments.
const LIFECYCLE_SCRIPTS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "postuninstall",
];

#[derive(Debug)]
pub struct NpmRegistryProvider {
    client: reqwest::Client,
    registry: String,
    /// Per-instance, in-memory cache of npm user records. Keyed by
    /// account name. `Some(created)` means we've successfully
    /// fetched the user record; `None` means we tried and failed
    /// (404, network error, malformed body) and don't want to keep
    /// retrying for the duration of this run. The underlying
    /// [`Mutex`] is held only across map mutations — never across
    /// the network call.
    user_cache: Mutex<HashMap<String, Option<DateTime<Utc>>>>,
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
            user_cache: Mutex::new(HashMap::new()),
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

    // Each detector block is intentionally inline so the read order
    // matches the priority order. Refactoring into helper methods
    // would obscure that flow without removing complexity.
    #[allow(clippy::too_many_lines)]
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

        // Maintainer account age: only fetch the user record when we
        // actually know the publisher AND we know the publish time;
        // pure-helper logic is unit-tested separately.
        if let Some(version_meta) = body.versions.get(&dep.version) {
            if let Some(account) = version_meta.npm_user.as_ref().map(|u| u.name.clone()) {
                if let Some(published_at) = body.time.get(&dep.version).copied() {
                    let created = self.fetch_user_created(&account).await;
                    if let Some(sig) =
                        compute_maintainer_account_signal(&account, created, published_at)
                    {
                        out.push(sig);
                    }
                }
            }
        }

        // Provenance: structural verification only — we confirm the
        // bundle's in-toto subject digest matches `dist.integrity`,
        // proving the publisher tied the bundle to this exact
        // tarball. We do NOT verify the bundle's signature against
        // Sigstore's Fulcio roots (deferred alongside keyless
        // Sigstore). Absence is silent — most npm packages do not
        // yet publish with `--provenance`.
        if let Some(version_meta) = body.versions.get(&dep.version) {
            if let Some(dist) = version_meta.dist.as_ref() {
                if let (Some(integrity), Some(att)) =
                    (dist.integrity.as_deref(), dist.attestations.as_ref())
                {
                    if let Some(bundle_json) = self.fetch_attestation_bundle(&att.url).await {
                        if let Some(sig) =
                            compute_provenance_signal(&att.url, &bundle_json, integrity)
                        {
                            out.push(sig);
                        }
                    }
                }
            }
        }

        Ok(out)
    }
}

impl NpmRegistryProvider {
    /// Fetches the npm user record at
    /// `/-/user/org.couchdb.user:<name>` and returns the `created`
    /// timestamp. Memoised in `self.user_cache` for the lifetime
    /// of this provider instance — npm user records are stable
    /// enough that re-fetching during a single scan would only add
    /// latency. Returns `None` on any failure (404, network,
    /// decode); the cache stores the failure too so we don't retry.
    async fn fetch_user_created(&self, name: &str) -> Option<DateTime<Utc>> {
        if let Ok(cache) = self.user_cache.lock() {
            if let Some(hit) = cache.get(name) {
                return *hit;
            }
        }
        let url = format!(
            "{}/-/user/org.couchdb.user:{}",
            self.registry,
            urlencoding(name)
        );
        tracing::debug!(url, "fetching npm user record");
        let result: Option<DateTime<Utc>> = async {
            let resp = self
                .client
                .get(&url)
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
                .await
                .ok()?;
            if !resp.status().is_success() {
                return None;
            }
            let body: NpmUserRecord = resp.json().await.ok()?;
            body.created
        }
        .await;
        if let Ok(mut cache) = self.user_cache.lock() {
            cache.insert(name.to_string(), result);
        }
        result
    }

    /// Fetches the npm-hosted attestation bundle as raw JSON text.
    /// Not cached — bundles are version-specific and only fetched
    /// once per dependency anyway. Returns `None` on any failure;
    /// callers treat absence as "no provenance evidence".
    async fn fetch_attestation_bundle(&self, url: &str) -> Option<String> {
        tracing::debug!(url, "fetching npm attestation bundle");
        let resp = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.text().await.ok()
    }
}

/// Minimal percent-encoder for the user-record path component. The
/// CouchDB key form is `org.couchdb.user:<name>`; npm usernames
/// are restricted to URL-safe ASCII so this is essentially a
/// passthrough, but we encode `:` defensively just in case.
fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            other => format!("%{:02X}", other as u32),
        })
        .collect()
}

#[derive(Debug, Deserialize)]
struct NpmUserRecord {
    /// User-record creation timestamp. Field shape varies across
    /// registry mirrors — we accept the canonical ISO-8601 string
    /// form and treat anything else as `None`.
    #[serde(default)]
    created: Option<DateTime<Utc>>,
}

/// Pure decision: given an account name, the account's optional
/// creation time, and the version's publish time, returns a
/// [`Signal::MaintainerNewAccount`] iff the account was created at
/// or before the publish time AND the absolute age in days fits in
/// `u32`. When `created` is `None` (we never resolved the user)
/// or the timestamps are inverted, returns `None` — we never
/// fabricate evidence.
#[must_use]
pub fn compute_maintainer_account_signal(
    account: &str,
    created: Option<DateTime<Utc>>,
    published_at: DateTime<Utc>,
) -> Option<Signal> {
    let created = created?;
    if created > published_at {
        return None;
    }
    let age_days = (published_at - created).num_days();
    if age_days < 0 {
        return None;
    }
    let age_days = u32::try_from(age_days).ok()?;
    Some(Signal::MaintainerNewAccount {
        account: account.to_string(),
        age_days,
    })
}

/// Pure helper: given the URL the bundle was fetched from, the
/// raw JSON body, and the package's `dist.integrity` SRI string
/// (e.g. `"sha512-<base64>"`), returns a
/// [`Signal::ProvenanceClaimed`] iff at least one in-toto subject
/// digest inside any DSSE-wrapped attestation matches the
/// integrity hash. This is a *structural* match — it confirms the
/// publisher tied the bundle to this exact tarball, but does NOT
/// cryptographically verify the bundle's signature.
///
/// Returns `None` on any parse failure or if no subject digest
/// matches; we never fabricate trust evidence from malformed input.
#[must_use]
pub fn compute_provenance_signal(
    bundle_url: &str,
    bundle_json: &str,
    dist_integrity: &str,
) -> Option<Signal> {
    let (algo, expected_hex) = decode_sri(dist_integrity)?;
    let root: serde_json::Value = serde_json::from_str(bundle_json).ok()?;
    let attestations = root.get("attestations")?.as_array()?;
    for entry in attestations {
        // Two shapes seen in the wild: the DSSE envelope is either
        // directly under `bundle.dsseEnvelope` (Sigstore bundle
        // format) or directly under `dsseEnvelope` (older shape).
        let envelope = entry
            .pointer("/bundle/dsseEnvelope")
            .or_else(|| entry.pointer("/dsseEnvelope"))?;
        let payload_b64 = envelope.get("payload")?.as_str()?;
        let payload = base64_decode(payload_b64)?;
        let statement: serde_json::Value = serde_json::from_slice(&payload).ok()?;
        let subjects = statement.get("subject")?.as_array()?;
        for subject in subjects {
            let Some(digest) = subject.get("digest").and_then(serde_json::Value::as_object) else {
                continue;
            };
            if let Some(hex_str) = digest.get(algo).and_then(serde_json::Value::as_str) {
                if hex_str.eq_ignore_ascii_case(&expected_hex) {
                    return Some(Signal::ProvenanceClaimed {
                        bundle_url: bundle_url.to_string(),
                    });
                }
            }
        }
    }
    None
}

/// Splits an SRI string `"<algo>-<base64>"` into its algorithm
/// name and the lowercase-hex form of the digest. Returns `None`
/// for any malformed input. We accept only `sha256`, `sha384`,
/// `sha512` — the algorithms in-toto subjects are known to use.
fn decode_sri(sri: &str) -> Option<(&'static str, String)> {
    let (prefix, b64) = sri.split_once('-')?;
    let algo = match prefix {
        "sha256" => "sha256",
        "sha384" => "sha384",
        "sha512" => "sha512",
        _ => return None,
    };
    let bytes = base64_decode(b64)?;
    Some((algo, hex::encode(bytes)))
}

/// Tolerant base64 decoder accepting standard or URL-safe alphabets,
/// with or without padding. npm and Sigstore bundles in the wild
/// use the standard alphabet with padding, but Sigstore's spec
/// permits either; be liberal in what we accept.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s))
        .ok()
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
/// Detects the “`latest` moved backwards” pattern: `dist-tags.latest`
/// resolves to a version that is strictly older than the highest
/// non-prerelease published version. Pre-releases are excluded from
/// the “highest” comparison because shipping `2.0.0-rc.1` while
/// `latest=1.4.0` is normal release-train behaviour, not an attack.
///
/// We only fire when the gap crosses a major-version boundary
/// (i.e. `latest.major < highest.major`). Same-major patch / minor
/// drift is overwhelmingly intentional LTS-line maintenance — e.g.
/// Storybook keeps `latest=8.6.14` while `8.6.18` exists because
/// `8.6.x` is the supported line and `9.x` rides `next` — and is
/// the dominant source of false-positive blocks in real lockfiles.
/// A genuine compromised-account "rollback" attack ships a patch
/// or minor *under* the existing major (e.g. `1.4.5` after
/// `latest` was `1.5.0`), which appears as `latest.major ==
/// highest.major` AND `latest < highest` — exactly the case we no
/// longer flag here. The signal is currently structural and one-shot,
/// with no packument history; once we cache the prior `latest` value
/// we can re-add the same-major case as a separate, history-aware
/// signal. Until then, suppressing same-major gaps trades a class
/// of true positives we cannot reliably distinguish from LTS
/// maintenance against far higher precision on the cross-major case.
///
/// Returns `None` when there is no `latest` tag, the tag points to
/// an unparseable version, the tag points at the maximum
/// non-prerelease version (the healthy case), or the gap is within
/// a single major.
fn detect_dist_tag_anomaly(packument: &Packument) -> Option<Signal> {
    let latest = packument.dist_tags.get("latest")?;
    let latest_sem = Version::parse(latest).ok()?;

    let max_release = packument
        .versions
        .keys()
        .filter_map(|v| Version::parse(v).ok())
        .filter(|v| v.pre.is_empty())
        .max()?;

    if latest_sem >= max_release || latest_sem.major == max_release.major {
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

/// Deserialize `versions[v].deprecated`, accepting either a string
/// (the documented shape — the value is the deprecation message) or
/// any non-string JSON value (which we treat as "not deprecated").
///
/// Some major packages on the npm registry ship `"deprecated": false`
/// when not deprecated (react 19.x, react-dom 19.x, scheduler 0.25+,
/// react-is, react-reconciler, …). The default `Option<String>`
/// deserializer rejected `false` with a hard `invalid type: boolean`
/// error, which propagated as `decode: error decoding response body`
/// and forced every affected package into `Signal::Unavailable` —
/// effectively blocking core React installs unconditionally.
///
/// We tolerate the wire bug rather than reject it: false / null /
/// numbers / objects / arrays all coerce to `None` (= not
/// deprecated). Strings — including the empty string — round-trip
/// unchanged so [`build_deprecated_signal`]'s existing semantics
/// (presence of any string is the deprecation marker) are preserved.
fn deserialize_deprecated<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(match value {
        serde_json::Value::String(s) => Some(s),
        _ => None,
    })
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
    /// presence of a *non-empty string* is the deprecation marker;
    /// absence (or any non-string value) means "not deprecated".
    ///
    /// Some packages on the registry — `react@19.x`, `react-dom@19.x`,
    /// `scheduler@0.25+` and others — ship `"deprecated": false` on
    /// the wire (a JSON boolean) when *not* deprecated. The npm spec
    /// only documents string-or-absent, but in practice the registry
    /// returns booleans here too. We accept either by deserialising
    /// through a permissive helper that maps any non-string into
    /// `None`.
    #[serde(default, deserialize_with = "deserialize_deprecated")]
    deprecated: Option<String>,
    /// `bin` may be either a map of `{ name: path }` or a single string
    /// (whose key is the package name). We normalise via
    /// [`bin_names`].
    #[serde(default)]
    bin: Option<serde_json::Value>,
    /// `dist` carries delivery metadata: tarball URL, integrity hash,
    /// and — when the version was published with `--provenance` —
    /// a pointer to the Sigstore attestation bundle.
    #[serde(default)]
    dist: Option<DistMeta>,
}

#[derive(Debug, Deserialize)]
struct DistMeta {
    /// SRI-format hash, e.g. `"sha512-<base64>=="`. We split on the
    /// first `-`; the prefix names the algorithm and the suffix is
    /// base64. Always populated by modern npm publishes.
    #[serde(default)]
    integrity: Option<String>,
    /// Pointer to the npm-hosted attestation bundle, present only
    /// when the publisher used `npm publish --provenance`.
    #[serde(default)]
    attestations: Option<DistAttestations>,
}

#[derive(Debug, Deserialize)]
struct DistAttestations {
    url: String,
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
                        dist: None,
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
            dist: None,
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

    /// Regression for v0.1.0 production bug — `react@19.x`,
    /// `react-dom@19.x`, `scheduler@0.25+`, `react-is`, and
    /// `react-reconciler` ship `"deprecated": false` on the wire,
    /// which the default `Option<String>` deserializer rejected as
    /// `invalid type: boolean`. The error propagated as
    /// `decode: error decoding response body` and turned every
    /// install of these packages into a hard
    /// `Signal::Unavailable` block. The custom
    /// [`deserialize_deprecated`] now coerces non-strings to `None`.
    #[test]
    fn packument_with_boolean_deprecated_decodes() {
        let body = r#"{
          "dist-tags": {"latest": "19.1.1"},
          "time": {"19.1.1": "2026-04-01T12:00:00Z"},
          "versions": {
            "19.1.1": {
              "deprecated": false,
              "dist": {"integrity": "sha512-abc"}
            }
          }
        }"#;
        let p: Packument = serde_json::from_str(body).expect("decodes");
        let v = p.versions.get("19.1.1").expect("version present");
        assert!(v.deprecated.is_none(), "false should coerce to None");
    }

    #[test]
    fn packument_with_null_deprecated_decodes() {
        let body = r#"{
          "versions": {"1.0.0": {"deprecated": null}}
        }"#;
        let p: Packument = serde_json::from_str(body).expect("decodes");
        assert!(p.versions["1.0.0"].deprecated.is_none());
    }

    #[test]
    fn packument_with_string_deprecated_round_trips() {
        let body = r#"{
          "versions": {"1.0.0": {"deprecated": "use foo@2 instead"}}
        }"#;
        let p: Packument = serde_json::from_str(body).expect("decodes");
        assert_eq!(
            p.versions["1.0.0"].deprecated.as_deref(),
            Some("use foo@2 instead")
        );
    }

    #[test]
    fn packument_with_empty_string_deprecated_preserves_marker() {
        // Empty string on the wire is the "deprecated, no message"
        // marker — see deprecation_empty_string_is_marker_with_no_message.
        let body = r#"{"versions": {"1.0.0": {"deprecated": ""}}}"#;
        let p: Packument = serde_json::from_str(body).expect("decodes");
        assert_eq!(p.versions["1.0.0"].deprecated.as_deref(), Some(""));
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
            dist: None,
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

    #[test]
    fn prepare_is_not_a_registry_lifecycle_script() {
        // The npm registry adapter never sees git-source installs, so
        // `prepare` (which only runs on `npm install <git-url>`) must
        // not be reported for registry packuments. See LIFECYCLE_SCRIPTS
        // for the rationale.
        assert!(!LIFECYCLE_SCRIPTS.contains(&"prepare"));
        // The traditional install-time hooks must still be present.
        for s in ["preinstall", "install", "postinstall"] {
            assert!(
                LIFECYCLE_SCRIPTS.contains(&s),
                "{s} missing from LIFECYCLE_SCRIPTS"
            );
        }
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
                        dist: None,
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

    /// Storybook ships `8.6.x` as the supported line and rides
    /// `9.x` on `next`. Patch / minor drift inside one major is
    /// dominated by intentional LTS maintenance and must not
    /// produce the signal.
    #[test]
    fn dist_tag_anomaly_quiet_for_same_major_drift() {
        // Patch-level (real Storybook lockfile shape).
        let p = pkmt_with_dist_tags(&["8.6.14", "8.6.15", "8.6.18"], &[("latest", "8.6.14")]);
        assert!(detect_dist_tag_anomaly(&p).is_none());
        // Minor-level inside one major.
        let p = pkmt_with_dist_tags(&["1.0.0", "1.5.0", "1.7.0"], &[("latest", "1.5.0")]);
        assert!(detect_dist_tag_anomaly(&p).is_none());
    }

    /// Cross-major regression — `latest` sits on `1.x` while `2.x`
    /// is published — remains the structural high-precision case
    /// we still want to surface.
    #[test]
    fn dist_tag_anomaly_fires_across_major_boundary() {
        let p = pkmt_with_dist_tags(&["1.0.0", "1.1.0", "2.0.0"], &[("latest", "1.1.0")]);
        assert!(detect_dist_tag_anomaly(&p).is_some());
    }

    #[test]
    fn maintainer_account_signal_emitted_with_age() {
        let created = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let published = chrono::DateTime::parse_from_rfc3339("2024-01-11T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        match compute_maintainer_account_signal("alice", Some(created), published).unwrap() {
            Signal::MaintainerNewAccount { account, age_days } => {
                assert_eq!(account, "alice");
                assert_eq!(age_days, 10);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn maintainer_account_signal_none_without_created() {
        let published = Utc::now();
        assert!(compute_maintainer_account_signal("ghost", None, published).is_none());
    }

    #[test]
    fn maintainer_account_signal_none_when_created_after_publish() {
        // Future-dated `created` (clock skew, mirror inconsistency) —
        // never fabricate negative ages.
        let created = chrono::DateTime::parse_from_rfc3339("2024-02-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let published = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(compute_maintainer_account_signal("alice", Some(created), published).is_none());
    }

    #[test]
    fn urlencoding_is_passthrough_for_npm_safe_names() {
        assert_eq!(urlencoding("alice"), "alice");
        assert_eq!(urlencoding("alice.bob"), "alice.bob");
        assert_eq!(urlencoding("a:b"), "a%3Ab");
    }

    fn make_bundle(subject_sha512_hex: &str) -> String {
        use base64::Engine as _;
        let statement = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{
                "name": "pkg:npm/example@1.0.0",
                "digest": { "sha512": subject_sha512_hex }
            }],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {}
        });
        let payload_b64 = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&statement).unwrap());
        serde_json::json!({
            "attestations": [{
                "predicateType": "https://slsa.dev/provenance/v1",
                "bundle": {
                    "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
                    "dsseEnvelope": {
                        "payloadType": "application/vnd.in-toto+json",
                        "payload": payload_b64,
                        "signatures": []
                    }
                }
            }]
        })
        .to_string()
    }

    #[test]
    fn provenance_signal_emitted_on_subject_match() {
        // Construct a tarball blob, hash it, base64-encode for SRI,
        // hex-encode for in-toto subject. Both forms must agree.
        use base64::Engine as _;
        use sha2::{Digest, Sha512};
        let blob = b"fake-tarball-bytes";
        let hash = Sha512::digest(blob);
        let hex_form = hex::encode(hash);
        let sri = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(hash)
        );
        let bundle = make_bundle(&hex_form);
        let sig = compute_provenance_signal("https://r/att", &bundle, &sri).unwrap();
        match sig {
            Signal::ProvenanceClaimed { bundle_url } => {
                assert_eq!(bundle_url, "https://r/att");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn provenance_signal_none_on_subject_mismatch() {
        use base64::Engine as _;
        use sha2::{Digest, Sha512};
        let real = Sha512::digest(b"real-bytes");
        let other = Sha512::digest(b"other-bytes");
        let sri = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(real)
        );
        let bundle = make_bundle(&hex::encode(other));
        assert!(compute_provenance_signal("u", &bundle, &sri).is_none());
    }

    #[test]
    fn provenance_signal_none_on_malformed_bundle() {
        assert!(compute_provenance_signal("u", "not-json", "sha512-aGVsbG8=").is_none());
        assert!(compute_provenance_signal("u", "{}", "sha512-aGVsbG8=").is_none());
    }

    #[test]
    fn provenance_signal_rejects_unknown_sri_algo() {
        let bundle = make_bundle("00");
        assert!(compute_provenance_signal("u", &bundle, "md5-aGVsbG8=").is_none());
        assert!(compute_provenance_signal("u", &bundle, "no-dash").is_none());
    }
}
