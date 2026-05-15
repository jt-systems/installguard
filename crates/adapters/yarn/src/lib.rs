//! `yarn.lock` adapter for **Yarn Berry** (Yarn 2+, `__metadata.version >= 4`).
//!
//! Berry's `yarn.lock` is a YAML document. Each entry's key is one or more
//! comma-separated *descriptors* (`name@protocol:range`), and the value
//! carries a canonical `resolution` descriptor plus the resolved `version`.
//!
//! Yarn 1 (Classic) lockfiles are **not** YAML and are rejected. Users
//! should migrate to Berry or stay on the npm/pnpm adapters.
//!
//! Direct-dep detection requires reading the sibling `package.json`: the
//! lockfile alone does not distinguish direct from transitive. If no
//! `package.json` is found next to the lockfile, no entries are marked
//! direct (a conservative under-approximation — direct-only checks will
//! simply not fire).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use installguard_core::adapter::{AdapterError, LockfileAdapter};
use installguard_core::dependency::{Ecosystem, Integrity, ResolvedDependency, Source};
use serde::Deserialize;

#[derive(Debug, Default)]
pub struct YarnAdapter;

impl YarnAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LockfileAdapter for YarnAdapter {
    fn id(&self) -> &'static str {
        "yarn"
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Yarn
    }

    fn detects(&self, path: &Path) -> bool {
        path.file_name().and_then(|n| n.to_str()) == Some("yarn.lock")
    }

    fn parse(&self, path: &Path) -> Result<Vec<ResolvedDependency>, AdapterError> {
        let raw = std::fs::read_to_string(path)?;
        let direct = path
            .parent()
            .map(collect_workspace_direct_specs)
            .unwrap_or_default();
        parse_str(&raw, &direct)
    }
}

/// Parse a Berry `yarn.lock` into normalised dependencies.
///
/// `direct_specs` is the set of `(name, range)` pairs declared in the
/// project's `package.json`. Pass an empty set to skip direct-dep marking.
pub fn parse_str(
    raw: &str,
    direct_specs: &BTreeSet<DirectSpec>,
) -> Result<Vec<ResolvedDependency>, AdapterError> {
    // Reject Yarn Classic up-front: its lockfile is a custom format that
    // would silently parse as the empty YAML document under serde_yaml.
    if !raw.contains("__metadata:") {
        return Err(AdapterError::UnsupportedVersion(
            "yarn.lock is missing `__metadata:` — likely Yarn Classic v1; \
             use `yarn set version berry` to migrate, or remove yarn.lock"
                .into(),
        ));
    }

    let doc: BTreeMap<String, YarnEntry> =
        serde_yaml::from_str(raw).map_err(|e| AdapterError::Parse(e.to_string()))?;

    if let Some(meta) = doc.get("__metadata") {
        if let Some(v) = &meta.version {
            // Yarn Berry started at metadata version 4 (Yarn 2.0). v6 is
            // current at time of writing. Reject anything lower.
            if !is_supported_metadata_version(v) {
                return Err(AdapterError::UnsupportedVersion(format!(
                    "__metadata.version `{v:?}` (need >= 4; regenerate with Yarn Berry)"
                )));
            }
        }
    }

    let mut out: Vec<ResolvedDependency> = Vec::with_capacity(doc.len());
    for (key, entry) in &doc {
        if key == "__metadata" {
            continue;
        }
        let Some(version) = entry.version.as_ref().and_then(value_as_string) else {
            continue;
        };
        let Some(resolution) = entry.resolution.as_deref() else {
            continue;
        };
        let Some((name, locator)) = split_descriptor(resolution) else {
            continue;
        };

        // Workspace entries (`name@workspace:.` etc.) describe the project
        // itself, not a downloaded dependency. Skip.
        if locator.starts_with("workspace:") {
            continue;
        }

        let direct = key
            .split(", ")
            .filter_map(split_descriptor)
            .any(|(n, range)| {
                let r = strip_protocol(&range);
                direct_specs.contains(&DirectSpec {
                    name: n,
                    range: r.to_string(),
                })
            });

        let source = classify_source(&locator);
        let integrity = entry.checksum.as_ref().and_then(|c| parse_checksum(c));

        out.push(ResolvedDependency {
            ecosystem: Ecosystem::Yarn,
            name,
            version,
            integrity,
            source,
            direct,
            requested_by: vec![],
        });
    }

    out.sort_by(|a, b| (a.name.as_str(), a.version.as_str()).cmp(&(&b.name, &b.version)));
    Ok(out)
}

fn is_supported_metadata_version(v: &serde_yaml::Value) -> bool {
    let n = match v {
        serde_yaml::Value::Number(n) => n.as_u64(),
        serde_yaml::Value::String(s) => s.parse::<u64>().ok(),
        _ => None,
    };
    n.is_some_and(|n| n >= 4)
}

/// Split a Berry descriptor like `"name@npm:^1.0.0"` or
/// `"@scope/name@npm:1.0.0"` into `(name, locator)`.
fn split_descriptor(s: &str) -> Option<(String, String)> {
    let s = s.trim();
    // `@scope/name@…` — the *separating* `@` is the one that is not at
    // index 0. Find the last `@`; if that yields an empty name (scoped
    // package edge case), fall back to splitting after the scope.
    let at = s.rfind('@')?;
    if at == 0 {
        return None;
    }
    let (name, rest) = s.split_at(at);
    let locator = rest.strip_prefix('@')?;
    if name.is_empty() || locator.is_empty() {
        None
    } else {
        Some((name.to_string(), locator.to_string()))
    }
}

/// Berry locators use a `protocol:value` shape. Returns `value` (or the
/// whole string if no protocol was present, which happens in some
/// `package.json` shorthand entries).
fn strip_protocol(s: &str) -> &str {
    s.split_once(':').map_or(s, |(_, rest)| rest)
}

fn classify_source(locator: &str) -> Source {
    let (protocol, value) = locator
        .split_once(':')
        .map_or(("npm", locator), |(p, v)| (p, v));
    match protocol {
        "npm" => Source::Registry { url: String::new() },
        "workspace" => Source::Workspace,
        "git" | "git+ssh" | "git+https" | "git+http" => Source::Git {
            url: value.to_string(),
            reference: None,
        },
        "github" => Source::GithubShortcut {
            spec: value.to_string(),
        },
        "file" | "link" | "portal" => Source::File {
            path: value.to_string(),
        },
        // Berry encodes git deps as `name@https://…#commit=…` without a
        // `git+` prefix, so we have to sniff the URL itself.
        "https" | "http" if locator.contains("#commit=") || locator.contains(".git") => {
            Source::Git {
                url: locator.to_string(),
                reference: None,
            }
        }
        // `https:`, `http:`, `patch:`, `exec:`, and any unknown protocol
        // are treated as exotic tarball-like sources.
        _ => Source::Tarball {
            url: locator.to_string(),
        },
    }
}

/// Berry checksums are recorded as `cacheKey/hash` (e.g. `10/abc…`). We
/// store the raw hash as a hex-prefixed integrity string. Yarn does not
/// expose the algorithm in the lockfile, so we tag it as `sha512` (Berry's
/// only supported algorithm for npm packages today).
fn parse_checksum(checksum: &str) -> Option<Integrity> {
    let hash = checksum.rsplit('/').next()?;
    if hash.is_empty() {
        None
    } else {
        Some(Integrity(format!("sha512-{hash}")))
    }
}

/// `(name, range)` pair from a `package.json` dependency entry, used for
/// direct-dep detection. The `range` is the *literal* string from
/// package.json (e.g. `"^1.0.0"`, `"npm:other@^1.0.0"`, `"workspace:*"`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DirectSpec {
    pub name: String,
    pub range: String,
}

/// Extract the union of `dependencies`, `devDependencies`,
/// `optionalDependencies`, and `peerDependencies` from a package.json.
pub fn collect_direct_specs(package_json: &str) -> BTreeSet<DirectSpec> {
    let mut out = BTreeSet::new();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(package_json) else {
        return out;
    };
    for field in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let Some(obj) = value.get(field).and_then(|v| v.as_object()) else {
            continue;
        };
        for (name, range) in obj {
            if let Some(range) = range.as_str() {
                out.insert(DirectSpec {
                    name: name.clone(),
                    range: strip_protocol(range).to_string(),
                });
            }
        }
    }
    out
}

/// Read the root `package.json` at `root_dir/package.json` and union
/// its direct deps with those of every workspace member declared in
/// the `workspaces` field. Yarn supports two shapes:
///
/// * `"workspaces": ["packages/*", "apps/web"]` — array of patterns.
/// * `"workspaces": { "packages": [...] }` — object form (Yarn 1
///   nohoist compatibility shape, still accepted by Berry).
///
/// Each pattern is resolved against `root_dir`. We support the two
/// shapes seen in real-world workspaces:
///
/// * literal segment (`packages/web`) — read that one directory's
///   `package.json` directly,
/// * trailing single-star (`packages/*`) — list the parent directory
///   and read every immediate-child `package.json` it contains.
///
/// More exotic globs (`**`, character classes) are deliberately not
/// supported; they're vanishingly rare in `workspaces` arrays. A
/// member `package.json` that fails to read or parse is silently
/// skipped (consistent with the rest of this adapter — direct-dep
/// detection is a best-effort enrichment, never load-bearing for
/// correctness).
///
/// If the root `package.json` is missing or cannot be parsed, the
/// caller still gets an empty set (the prior behaviour) — it just
/// means no entries get marked direct.
pub fn collect_workspace_direct_specs(root_dir: &Path) -> BTreeSet<DirectSpec> {
    let mut out = BTreeSet::new();
    let root_pj_path = root_dir.join("package.json");
    let Ok(root_raw) = std::fs::read_to_string(&root_pj_path) else {
        return out;
    };
    out.extend(collect_direct_specs(&root_raw));

    let Ok(value) = serde_json::from_str::<serde_json::Value>(&root_raw) else {
        return out;
    };
    let patterns = workspace_patterns(&value);
    for pattern in patterns {
        for member_pj in expand_workspace_pattern(root_dir, &pattern) {
            if let Ok(raw) = std::fs::read_to_string(&member_pj) {
                out.extend(collect_direct_specs(&raw));
            }
        }
    }
    out
}

/// Extract the workspace pattern array from either the bare-array
/// (`"workspaces": [...]`) or the object form
/// (`"workspaces": { "packages": [...] }`). Yarn Berry accepts both.
fn workspace_patterns(value: &serde_json::Value) -> Vec<String> {
    let Some(ws) = value.get("workspaces") else {
        return Vec::new();
    };
    let arr = ws
        .as_array()
        .or_else(|| ws.get("packages").and_then(|v| v.as_array()));
    let Some(arr) = arr else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

/// Resolve a workspace pattern to the set of `<member>/package.json`
/// paths it matches under `root_dir`. Supports literal paths and a
/// trailing `/*` glob. Other glob shapes are returned as the empty
/// set (i.e. silently skipped — see [`collect_workspace_direct_specs`]).
fn expand_workspace_pattern(root_dir: &Path, pattern: &str) -> Vec<std::path::PathBuf> {
    let pattern = pattern.trim_matches('/');
    if pattern.is_empty() || pattern.contains("**") {
        return Vec::new();
    }

    if let Some(parent) = pattern.strip_suffix("/*") {
        // Trailing single-star: list immediate children of `parent`.
        if parent.contains('*') {
            return Vec::new();
        }
        let dir = root_dir.join(parent);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let pj = path.join("package.json");
                if pj.is_file() {
                    out.push(pj);
                }
            }
        }
        return out;
    }

    if pattern.contains('*') {
        // Mid-string glob — not supported.
        return Vec::new();
    }

    // Literal path.
    let pj = root_dir.join(pattern).join("package.json");
    if pj.is_file() {
        vec![pj]
    } else {
        Vec::new()
    }
}

// ── Berry yarn.lock schema (subset) ────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct YarnEntry {
    /// `serde_yaml::Value` because `__metadata.version` is a number while
    /// per-entry `version` is a string. Coerce via [`value_as_string`].
    version: Option<serde_yaml::Value>,
    resolution: Option<String>,
    checksum: Option<String>,
}

fn value_as_string(v: &serde_yaml::Value) -> Option<String> {
    match v {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE: &str = r#"# THIS IS AN AUTOGENERATED FILE.

__metadata:
  version: 6
  cacheKey: 8

"left-pad@npm:^1.3.0":
  version: 1.3.0
  resolution: "left-pad@npm:1.3.0"
  checksum: 10/abcdef
  languageName: node
  linkType: hard

"@scope/util@npm:^2.0.0":
  version: 2.0.5
  resolution: "@scope/util@npm:2.0.5"
  checksum: 10/cafebabe
  languageName: node
  linkType: hard

"deep@npm:1.0.0":
  version: 1.0.0
  resolution: "deep@npm:1.0.0"
  checksum: 10/deadbeef
  languageName: node
  linkType: hard

"git-dep@https://github.com/x/y.git#commit=abc":
  version: 0.0.0
  resolution: "git-dep@https://github.com/x/y.git#commit=abc"
  languageName: node
  linkType: hard

"my-app@workspace:.":
  version: 0.0.0-use.local
  resolution: "my-app@workspace:."
  languageName: unknown
  linkType: soft
"#;

    const PKG_JSON: &str = r#"{
        "name": "my-app",
        "dependencies": {
            "left-pad": "^1.3.0",
            "@scope/util": "^2.0.0"
        }
    }"#;

    #[test]
    fn parses_v6_marks_direct_skips_workspace() {
        let direct = collect_direct_specs(PKG_JSON);
        let deps = parse_str(SIMPLE, &direct).unwrap();
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        // Workspace entry `my-app` is excluded.
        assert_eq!(names, vec!["@scope/util", "deep", "git-dep", "left-pad"]);

        let left_pad = deps.iter().find(|d| d.name == "left-pad").unwrap();
        assert!(left_pad.direct);
        assert_eq!(left_pad.version, "1.3.0");
        assert!(matches!(left_pad.source, Source::Registry { .. }));
        assert_eq!(
            left_pad.integrity.as_ref().map(|i| i.0.as_str()),
            Some("sha512-abcdef")
        );

        let scoped = deps.iter().find(|d| d.name == "@scope/util").unwrap();
        assert!(scoped.direct);

        let deep = deps.iter().find(|d| d.name == "deep").unwrap();
        assert!(!deep.direct, "transitive deps must not be marked direct");

        let git = deps.iter().find(|d| d.name == "git-dep").unwrap();
        assert!(matches!(git.source, Source::Git { .. }));
    }

    #[test]
    fn rejects_yarn_classic() {
        let classic = "# yarn lockfile v1\n\nleft-pad@^1.3.0:\n  version \"1.3.0\"\n";
        let err = parse_str(classic, &BTreeSet::new()).unwrap_err();
        assert!(matches!(err, AdapterError::UnsupportedVersion(_)));
    }

    #[test]
    fn rejects_old_metadata_version() {
        let raw = "__metadata:\n  version: 3\n";
        let err = parse_str(raw, &BTreeSet::new()).unwrap_err();
        assert!(matches!(err, AdapterError::UnsupportedVersion(_)));
    }

    #[test]
    fn descriptor_split_handles_scope() {
        assert_eq!(
            split_descriptor("@scope/name@npm:1.0.0"),
            Some(("@scope/name".into(), "npm:1.0.0".into()))
        );
        assert_eq!(
            split_descriptor("name@workspace:."),
            Some(("name".into(), "workspace:.".into()))
        );
        assert_eq!(split_descriptor("@scope"), None);
    }

    #[test]
    fn direct_specs_collects_all_dep_kinds() {
        let pj = r#"{
            "dependencies": { "a": "^1.0.0" },
            "devDependencies": { "b": "^2.0.0" },
            "peerDependencies": { "c": "^3.0.0" },
            "optionalDependencies": { "d": "^4.0.0" }
        }"#;
        let s = collect_direct_specs(pj);
        let names: Vec<&str> = s.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c", "d"]);
    }

    /// End-to-end workspace fixture: root has two members under
    /// `packages/*` plus an explicitly-named `apps/web`. Each member
    /// declares its own direct deps. Verify the union surfaces every
    /// member's deps as direct.
    #[test]
    fn collect_workspace_direct_specs_walks_members() {
        use std::fs;
        let tmp = std::env::temp_dir().join(format!(
            "ig-yarn-ws-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(tmp.join("packages/a")).unwrap();
        fs::create_dir_all(tmp.join("packages/b")).unwrap();
        fs::create_dir_all(tmp.join("apps/web")).unwrap();
        fs::write(
            tmp.join("package.json"),
            r#"{
              "name": "root",
              "private": true,
              "workspaces": ["packages/*", "apps/web"],
              "devDependencies": { "root-dev": "^1.0.0" }
            }"#,
        )
        .unwrap();
        fs::write(
            tmp.join("packages/a/package.json"),
            r#"{ "name": "a", "dependencies": { "left-pad": "^1.3.0" } }"#,
        )
        .unwrap();
        fs::write(
            tmp.join("packages/b/package.json"),
            r#"{ "name": "b", "dependencies": { "right-pad": "^2.0.0" } }"#,
        )
        .unwrap();
        fs::write(
            tmp.join("apps/web/package.json"),
            r#"{ "name": "web", "dependencies": { "react": "^18" } }"#,
        )
        .unwrap();

        let specs = collect_workspace_direct_specs(&tmp);
        let names: Vec<&str> = specs.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["left-pad", "react", "right-pad", "root-dev"]);

        let _ = fs::remove_dir_all(&tmp);
    }

    /// Object-shaped `workspaces: { packages: [...] }` is the Yarn 1
    /// nohoist compatibility form. Berry still accepts it.
    #[test]
    fn workspace_object_shape_supported() {
        use std::fs;
        let tmp = std::env::temp_dir().join(format!(
            "ig-yarn-wsobj-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(tmp.join("pkgs/x")).unwrap();
        fs::write(
            tmp.join("package.json"),
            r#"{ "workspaces": { "packages": ["pkgs/*"] } }"#,
        )
        .unwrap();
        fs::write(
            tmp.join("pkgs/x/package.json"),
            r#"{ "dependencies": { "lodash": "^4" } }"#,
        )
        .unwrap();
        let specs = collect_workspace_direct_specs(&tmp);
        assert_eq!(
            specs.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            vec!["lodash"]
        );
        let _ = fs::remove_dir_all(&tmp);
    }
}
