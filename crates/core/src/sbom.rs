//! CycloneDX 1.5 SBOM emitter for an InstallGuard evaluation.
//!
//! Each `ResolvedDependency` becomes a `component` with:
//!
//! * `purl`     — `pkg:npm/<name>@<version>` (registry family is npm for
//!   all currently-supported ecosystems).
//! * `bom-ref`  — same as `purl`, used to wire dependency relationships.
//! * `properties[installguard:*]` — InstallGuard-specific decision data
//!   carried in the CycloneDX-blessed `properties` extension point so the
//!   SBOM remains a valid CycloneDX document for any consumer.
//!
//! Output is byte-stable: components sorted by `bom-ref`, properties sorted
//! by name, no wall-clock noise in identity-bearing fields. The single
//! `metadata.timestamp` is the only time-varying field and lives outside
//! the parts a downstream SBOM diff would care about.
//!
//! Reference: <https://cyclonedx.org/docs/1.5/json/>
//!
//! Notes on intentional omissions:
//! * No vulnerabilities[] (that's the VEX surface, shipped separately).
//! * No services[] / compositions[] (out of scope for a dep SBOM).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::decision::{Decision, Reason};
use crate::dependency::{Ecosystem, ResolvedDependency};

/// CycloneDX bom format string.
pub const BOM_FORMAT: &str = "CycloneDX";
/// Spec version we emit. Bump deliberately; consumers pin on this.
pub const SPEC_VERSION: &str = "1.5";

/// Top-level CycloneDX BOM document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bom {
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    /// CycloneDX expects an unsigned integer; we always emit `1` for a
    /// fresh document.
    pub version: u32,
    /// Random per-document URN. We use a deterministic URN derived from
    /// the lockfile digest so two runs over identical inputs produce the
    /// same `serialNumber`.
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub metadata: Metadata,
    pub components: Vec<Component>,
    pub dependencies: Vec<DependencyEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    pub timestamp: DateTime<Utc>,
    pub tools: Tools,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tools {
    pub components: Vec<ToolComponent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolComponent {
    #[serde(rename = "type")]
    pub type_: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub name: String,
    pub version: String,
    pub purl: String,
    /// CycloneDX-blessed extension point. We use it for our
    /// `installguard:*` namespace.
    pub properties: Vec<Property>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Property {
    pub name: String,
    pub value: String,
}

/// CycloneDX dependency edge: every direct dependency is listed under the
/// synthetic root `bom-ref`. We do not currently surface transitive edges
/// because adapters do not yet emit a tree; this keeps the SBOM honest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyEdge {
    #[serde(rename = "ref")]
    pub ref_: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "dependsOn")]
    pub depends_on: Vec<String>,
}

/// One row of input to `Bom::build`.
#[derive(Debug, Clone, Copy)]
pub struct SbomEntry<'a> {
    pub dep: &'a ResolvedDependency,
    pub decision: &'a Decision,
}

impl Bom {
    /// Build a deterministic CycloneDX 1.5 BOM.
    ///
    /// `lockfile_digest` becomes both the `serialNumber` (URN) and a
    /// `metadata.tools` property so downstream diffs can detect lockfile
    /// drift without re-hashing the lockfile.
    #[must_use]
    pub fn build(
        entries: &[SbomEntry<'_>],
        lockfile_digest: &str,
        generated_at: DateTime<Utc>,
        tool_version: &str,
    ) -> Self {
        let mut components: Vec<Component> = entries
            .iter()
            .map(|e| component_from(e.dep, e.decision))
            .collect();
        components.sort_by(|a, b| a.bom_ref.cmp(&b.bom_ref));
        components.dedup_by(|a, b| a.bom_ref == b.bom_ref);

        let mut direct_refs: Vec<String> = entries
            .iter()
            .filter(|e| e.dep.direct)
            .map(|e| purl_for(e.dep))
            .collect();
        direct_refs.sort();
        direct_refs.dedup();

        let dependencies = vec![DependencyEdge {
            ref_: ROOT_REF.to_string(),
            depends_on: direct_refs,
        }];

        Self {
            bom_format: BOM_FORMAT.to_string(),
            spec_version: SPEC_VERSION.to_string(),
            version: 1,
            serial_number: format!("urn:uuid:{}", uuid_from_digest(lockfile_digest)),
            metadata: Metadata {
                timestamp: generated_at,
                tools: Tools {
                    components: vec![ToolComponent {
                        type_: "application".to_string(),
                        name: "installguard".to_string(),
                        version: tool_version.to_string(),
                    }],
                },
            },
            components,
            dependencies,
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let mut s = serde_json::to_string_pretty(self)?;
        s.push('\n');
        Ok(s)
    }
}

/// Synthetic root `bom-ref` for the project itself. CycloneDX requires
/// edges have a `ref` even when there's no formal root component.
const ROOT_REF: &str = "installguard:project";

fn component_from(dep: &ResolvedDependency, decision: &Decision) -> Component {
    let purl = purl_for(dep);
    let mut properties = vec![
        Property {
            name: "installguard:decision".to_string(),
            value: decision_label(decision).to_string(),
        },
        Property {
            name: "installguard:direct".to_string(),
            value: dep.direct.to_string(),
        },
    ];
    for r in decision_reasons(decision) {
        properties.push(Property {
            name: "installguard:reason".to_string(),
            value: r.code().to_string(),
        });
    }
    properties.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.value.cmp(&b.value)));
    properties.dedup();

    Component {
        type_: "library".to_string(),
        bom_ref: purl.clone(),
        name: dep.name.clone(),
        version: dep.version.clone(),
        purl,
        properties,
    }
}

/// Canonical purl for a resolved dependency. `pkg:npm/<name>@<version>`
/// for all currently-supported ecosystems; scoped names percent-encode
/// the leading `@`. Re-used by the VEX emitter so SBOM and VEX stay
/// referentially compatible.
#[must_use]
pub fn purl_for(dep: &ResolvedDependency) -> String {
    // All currently-supported ecosystems share the npm registry, so the
    // purl type is always `npm`. Revisit when we add non-npm ecosystems.
    let _ = Ecosystem::Npm;
    format!("pkg:npm/{}@{}", encode_purl_segment(&dep.name), dep.version)
}

/// Encode a name segment for purl: scoped npm names like `@scope/pkg`
/// keep the `/` but `@` must be percent-encoded.
fn encode_purl_segment(name: &str) -> String {
    name.replace('@', "%40")
}

fn decision_label(d: &Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Warn { .. } => "warn",
        Decision::Block { .. } => "block",
    }
}

fn decision_reasons(d: &Decision) -> &[Reason] {
    match d {
        Decision::Allow => &[],
        Decision::Warn { reasons } | Decision::Block { reasons } => reasons,
    }
}

/// Derive a stable UUID-shaped identifier from the lockfile digest. We do
/// not need RFC 4122 uniqueness; we need the same inputs to produce the
/// same URN so SBOMs round-trip byte-stably.
fn uuid_from_digest(digest: &str) -> String {
    // Take the first 32 hex chars of a sha256 digest and lay them out as
    // 8-4-4-4-12. Any 64-hex-char input works.
    let h = if digest.len() >= 32 {
        &digest[..32]
    } else {
        // Pad with zeros if the caller passed a short digest. Keeps this
        // function infallible without panicking.
        return format!("{digest:0<32}");
    };
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::Reason;
    use crate::dependency::{Ecosystem, Source};

    fn dep(name: &str, version: &str, direct: bool) -> ResolvedDependency {
        ResolvedDependency {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: version.into(),
            integrity: None,
            source: Source::Registry { url: String::new() },
            direct,
            requested_by: Vec::new(),
        }
    }

    fn ts() -> DateTime<Utc> {
        use chrono::TimeZone;
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    #[test]
    fn purl_encodes_scope() {
        let d = dep("@scope/pkg", "1.2.3", true);
        assert_eq!(purl_for(&d), "pkg:npm/%40scope/pkg@1.2.3");
    }

    #[test]
    fn components_sorted_and_deduped() {
        let a = dep("b", "1.0.0", true);
        let b = dep("a", "2.0.0", true);
        let dec = Decision::Allow;
        let entries = vec![
            SbomEntry {
                dep: &a,
                decision: &dec,
            },
            SbomEntry {
                dep: &b,
                decision: &dec,
            },
        ];
        let bom = Bom::build(&entries, &"0".repeat(64), ts(), "0.0.0");
        assert_eq!(bom.components.len(), 2);
        assert_eq!(bom.components[0].name, "a");
        assert_eq!(bom.components[1].name, "b");
    }

    #[test]
    fn decision_properties_emitted() {
        let d = dep("esbuild", "0.21.5", true);
        let dec = Decision::Block {
            reasons: vec![Reason::DisallowedLifecycleScript {
                script: "preinstall".into(),
            }],
        };
        let entries = vec![SbomEntry {
            dep: &d,
            decision: &dec,
        }];
        let bom = Bom::build(&entries, &"a".repeat(64), ts(), "0.0.0");
        let props = &bom.components[0].properties;
        assert!(props
            .iter()
            .any(|p| p.name == "installguard:decision" && p.value == "block"));
        assert!(props.iter().any(|p| p.name == "installguard:reason"));
    }

    #[test]
    fn serial_number_stable_across_calls() {
        let d = dep("x", "1", true);
        let dec = Decision::Allow;
        let entries = vec![SbomEntry {
            dep: &d,
            decision: &dec,
        }];
        let digest = "deadbeef".repeat(8);
        let a = Bom::build(&entries, &digest, ts(), "0.0.0");
        let b = Bom::build(&entries, &digest, ts(), "0.0.0");
        assert_eq!(a.serial_number, b.serial_number);
        assert_eq!(
            a.serial_number,
            "urn:uuid:deadbeef-dead-beef-dead-beefdeadbeef"
        );
    }
}
