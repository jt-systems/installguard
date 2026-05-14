//! `package-lock.json` (npm v7+, lockfileVersion 2 and 3) adapter.
//!
//! npm v1 lockfiles are *not* supported — they predate `lockfileVersion` and
//! lack the `packages` map we rely on. Users on npm < 7 should regenerate.

use std::collections::BTreeMap;
use std::path::Path;

use installguard_core::adapter::{AdapterError, LockfileAdapter};
use installguard_core::dependency::{Ecosystem, Integrity, ResolvedDependency, Source};
use serde::Deserialize;

#[derive(Debug, Default)]
pub struct NpmAdapter;

impl NpmAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LockfileAdapter for NpmAdapter {
    fn id(&self) -> &'static str {
        "npm"
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn detects(&self, path: &Path) -> bool {
        path.file_name().and_then(|n| n.to_str()) == Some("package-lock.json")
    }

    fn parse(&self, path: &Path) -> Result<Vec<ResolvedDependency>, AdapterError> {
        let raw = std::fs::read_to_string(path)?;
        parse_str(&raw)
    }
}

/// Parse a `package-lock.json` document into normalised dependencies.
pub fn parse_str(raw: &str) -> Result<Vec<ResolvedDependency>, AdapterError> {
    let lock: PackageLock =
        serde_json::from_str(raw).map_err(|e| AdapterError::Parse(e.to_string()))?;

    if lock.lockfile_version < 2 {
        return Err(AdapterError::UnsupportedVersion(format!(
            "lockfileVersion {} (need >= 2; regenerate with npm >= 7)",
            lock.lockfile_version
        )));
    }

    let packages = lock
        .packages
        .ok_or_else(|| AdapterError::Parse("missing `packages` map".into()))?;

    let mut out = Vec::with_capacity(packages.len());
    for (key, entry) in packages {
        // Skip the root project entry (key == "") and workspace links.
        if key.is_empty() {
            continue;
        }
        if entry.link.unwrap_or(false) {
            continue;
        }

        let name = entry
            .name
            .clone()
            .or_else(|| derive_name_from_path(&key))
            .ok_or_else(|| AdapterError::Parse(format!("no name for entry `{key}`")))?;

        let Some(version) = entry.version.clone() else {
            // Workspace roots inside `node_modules/<name>` may have no version.
            continue;
        };

        // Direct iff installed at top level: key starts with `node_modules/`
        // and contains no nested `/node_modules/` segment.
        let direct = is_direct_path(&key);

        // Workspace member: any non-empty key that does not live under
        // `node_modules/`. npm v3+ records workspace packages at their
        // on-disk path (e.g. `apps/api`, `packages/utils`) with no
        // `resolved` URL because the package is local to the repo.
        // Treat as `Source::Workspace` so the policy can short-circuit
        // to `Allow` rather than asking the registry for a private name
        // and getting a 404.
        let source = if key.starts_with("node_modules/") {
            classify_source(entry.resolved.as_deref())
        } else {
            Source::Workspace
        };
        let integrity = entry.integrity.clone().map(Integrity);

        out.push(ResolvedDependency {
            ecosystem: Ecosystem::Npm,
            name,
            version,
            integrity,
            source,
            direct,
            requested_by: vec![],
        });
    }

    // Stable order for deterministic downstream behaviour.
    out.sort_by(|a, b| (a.name.as_str(), a.version.as_str()).cmp(&(&b.name, &b.version)));
    Ok(out)
}

fn derive_name_from_path(key: &str) -> Option<String> {
    // `node_modules/foo` ⇒ "foo"; `node_modules/foo/node_modules/@scope/bar` ⇒ "@scope/bar"
    let last = key.rsplit("node_modules/").next()?.trim_start_matches('/');
    if last.is_empty() {
        None
    } else {
        Some(last.to_string())
    }
}

fn is_direct_path(key: &str) -> bool {
    if let Some(rest) = key.strip_prefix("node_modules/") {
        !rest.contains("/node_modules/")
    } else {
        false
    }
}

fn has_ext(url: &str, ext: &str) -> bool {
    url.len() >= ext.len() && url[url.len() - ext.len()..].eq_ignore_ascii_case(ext)
}

fn classify_source(resolved: Option<&str>) -> Source {
    let Some(url) = resolved else {
        return Source::Registry { url: String::new() };
    };
    if url.starts_with("git+") || url.starts_with("git://") || url.starts_with("git@") {
        Source::Git {
            url: url.to_string(),
            reference: None,
        }
    } else if has_ext(url, ".tgz") && url.contains("/-/") {
        // `https://registry.npmjs.org/axios/-/axios-1.7.9.tgz` — registry tarball.
        Source::Registry {
            url: url.to_string(),
        }
    } else if has_ext(url, ".tgz") || has_ext(url, ".tar.gz") {
        Source::Tarball {
            url: url.to_string(),
        }
    } else if let Some(rest) = url.strip_prefix("file:") {
        Source::File {
            path: rest.to_string(),
        }
    } else if url.starts_with("github:") {
        Source::GithubShortcut {
            spec: url.to_string(),
        }
    } else {
        Source::Registry {
            url: url.to_string(),
        }
    }
}

// ── npm lockfile schema (subset we consume) ────────────────────────────────

#[derive(Debug, Deserialize)]
struct PackageLock {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: u32,
    packages: Option<BTreeMap<String, PackageEntry>>,
}

#[derive(Debug, Deserialize)]
struct PackageEntry {
    name: Option<String>,
    version: Option<String>,
    resolved: Option<String>,
    integrity: Option<String>,
    #[serde(default)]
    link: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE: &str = r#"{
        "name": "demo",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": { "name": "demo", "version": "0.0.0" },
            "node_modules/axios": {
                "version": "1.7.9",
                "resolved": "https://registry.npmjs.org/axios/-/axios-1.7.9.tgz",
                "integrity": "sha512-deadbeef"
            },
            "node_modules/axios/node_modules/follow-redirects": {
                "version": "1.15.6",
                "resolved": "https://registry.npmjs.org/follow-redirects/-/follow-redirects-1.15.6.tgz",
                "integrity": "sha512-cafebabe"
            },
            "node_modules/exotic": {
                "version": "0.0.0",
                "resolved": "git+https://github.com/x/y.git#abc"
            }
        }
    }"#;

    #[test]
    fn parses_v3() {
        let deps = parse_str(SIMPLE).unwrap();
        assert_eq!(deps.len(), 3);
        let axios = deps.iter().find(|d| d.name == "axios").unwrap();
        assert!(axios.direct);
        assert_eq!(axios.version, "1.7.9");
        assert!(matches!(axios.source, Source::Registry { .. }));

        let follow = deps.iter().find(|d| d.name == "follow-redirects").unwrap();
        assert!(!follow.direct);

        let exotic = deps.iter().find(|d| d.name == "exotic").unwrap();
        assert!(matches!(exotic.source, Source::Git { .. }));
    }

    #[test]
    fn rejects_v1() {
        let raw = r#"{ "lockfileVersion": 1, "packages": {} }"#;
        assert!(matches!(
            parse_str(raw),
            Err(AdapterError::UnsupportedVersion(_))
        ));
    }

    /// Real-world npm workspace shape: package-lock.json records each
    /// workspace member at its on-disk path (no `node_modules/`
    /// prefix, no `resolved` URL, no `link: true` flag) with the
    /// member's name + version inline. These are first-party packages
    /// that don't exist on the public registry; classify them as
    /// `Source::Workspace` so policy can short-circuit to Allow.
    #[test]
    fn workspace_members_classified_as_workspace_source() {
        let raw = r#"{
            "name": "monorepo",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "monorepo", "version": "1.0.0" },
                "apps/api": { "name": "@acme/api", "version": "0.1.0" },
                "packages/utils": { "name": "@acme/utils", "version": "0.2.0" },
                "node_modules/axios": {
                    "version": "1.7.9",
                    "resolved": "https://registry.npmjs.org/axios/-/axios-1.7.9.tgz",
                    "integrity": "sha512-x"
                }
            }
        }"#;
        let deps = parse_str(raw).unwrap();
        let api = deps.iter().find(|d| d.name == "@acme/api").unwrap();
        assert!(
            matches!(api.source, Source::Workspace),
            "got {:?}",
            api.source
        );
        let utils = deps.iter().find(|d| d.name == "@acme/utils").unwrap();
        assert!(matches!(utils.source, Source::Workspace));
        let axios = deps.iter().find(|d| d.name == "axios").unwrap();
        assert!(matches!(axios.source, Source::Registry { .. }));
    }

    #[test]
    fn detects_filename() {
        let a = NpmAdapter::new();
        assert!(a.detects(Path::new("/x/package-lock.json")));
        assert!(!a.detects(Path::new("/x/pnpm-lock.yaml")));
    }
}
