//! `pnpm-lock.yaml` adapter.
//!
//! Supports `lockfileVersion`:
//! * `'6.0'` (pnpm 8) — `packages` keys are `/<name>@<version>`,
//!   top-level `dependencies` / `devDependencies`.
//! * `'9.0'` (pnpm 9 and 10) — `packages` keys are `<name>@<version>`,
//!   importers under `importers."."`.
//!
//! Older formats (v5 and earlier) are deliberately rejected; users should
//! regenerate with a current pnpm.

use std::collections::BTreeMap;
use std::path::Path;

use installguard_core::adapter::{AdapterError, LockfileAdapter};
use installguard_core::dependency::{Ecosystem, Integrity, ResolvedDependency, Source};
use serde::Deserialize;

#[derive(Debug, Default)]
pub struct PnpmAdapter;

impl PnpmAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LockfileAdapter for PnpmAdapter {
    fn id(&self) -> &'static str {
        "pnpm"
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Pnpm
    }

    fn detects(&self, path: &Path) -> bool {
        path.file_name().and_then(|n| n.to_str()) == Some("pnpm-lock.yaml")
    }

    fn parse(&self, path: &Path) -> Result<Vec<ResolvedDependency>, AdapterError> {
        let raw = std::fs::read_to_string(path)?;
        parse_str(&raw)
    }
}

/// Parse a `pnpm-lock.yaml` document into normalised dependencies.
pub fn parse_str(raw: &str) -> Result<Vec<ResolvedDependency>, AdapterError> {
    let lock: PnpmLock =
        serde_yaml::from_str(raw).map_err(|e| AdapterError::Parse(e.to_string()))?;

    let major = lock
        .lockfile_version
        .split('.')
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| {
            AdapterError::Parse(format!(
                "invalid lockfileVersion `{}`",
                lock.lockfile_version
            ))
        })?;

    let direct_specs: Vec<DirectSpec> = match major {
        9 => collect_direct_v9(&lock),
        6 => collect_direct_v6(&lock),
        v => {
            return Err(AdapterError::UnsupportedVersion(format!(
                "lockfileVersion {v} (need 6 or 9; regenerate with pnpm >= 8)"
            )))
        }
    };

    let mut out = Vec::with_capacity(lock.packages.len());
    for (key, entry) in &lock.packages {
        let Some((name, version)) = parse_package_key(key, major) else {
            // Unrecognised key shape — skip rather than fail the whole
            // lockfile. pnpm occasionally introduces new key suffixes
            // (e.g. peer-dep disambiguators) we may not yet handle.
            continue;
        };

        let direct = direct_specs
            .iter()
            .any(|d| d.name == name && d.version == version);

        let source = classify_source(entry);
        let integrity = entry
            .resolution
            .as_ref()
            .and_then(|r| r.integrity.clone())
            .map(Integrity);

        out.push(ResolvedDependency {
            ecosystem: Ecosystem::Pnpm,
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

#[derive(Debug)]
struct DirectSpec {
    name: String,
    version: String,
}

fn collect_direct_v9(lock: &PnpmLock) -> Vec<DirectSpec> {
    let Some(importers) = &lock.importers else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for importer in importers.values() {
        for section in [&importer.dependencies, &importer.dev_dependencies] {
            let Some(map) = section else { continue };
            for (name, entry) in map {
                if let Some(version) = strip_version_suffix(&entry.version) {
                    out.push(DirectSpec {
                        name: name.clone(),
                        version,
                    });
                }
            }
        }
    }
    out
}

fn collect_direct_v6(lock: &PnpmLock) -> Vec<DirectSpec> {
    let mut out = Vec::new();
    for section in [&lock.dependencies, &lock.dev_dependencies] {
        let Some(map) = section else { continue };
        for (name, entry) in map {
            if let Some(version) = strip_version_suffix(&entry.version) {
                out.push(DirectSpec {
                    name: name.clone(),
                    version,
                });
            }
        }
    }
    out
}

/// pnpm encodes peer-dep disambiguation as `1.2.3(peer@4.5.6)`. The base
/// version is everything before the first `(`.
fn strip_version_suffix(raw: &str) -> Option<String> {
    let trimmed = raw.split('(').next()?.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Parse a `packages` map key:
/// * v9: `lodash@4.17.21`, `@scope/pkg@1.0.0`, `pkg@1.0.0(peer@2.0.0)`
/// * v6: `/lodash@4.17.21`, `/@scope/pkg@1.0.0`
fn parse_package_key(key: &str, major: u32) -> Option<(String, String)> {
    let body = if major == 6 {
        key.strip_prefix('/')?
    } else {
        key
    };
    let body = body.split('(').next()?; // drop peer suffix
                                        // Last `@` separates name from version (handles `@scope/name`).
    let at = body.rfind('@')?;
    if at == 0 {
        return None;
    }
    let (name, version) = body.split_at(at);
    let version = version.strip_prefix('@')?;
    if name.is_empty() || version.is_empty() {
        None
    } else {
        Some((name.to_string(), version.to_string()))
    }
}

fn classify_source(entry: &PackageEntry) -> Source {
    if let Some(res) = &entry.resolution {
        if let Some(tarball) = &res.tarball {
            // Registry tarballs go through `tarball:` resolution in pnpm only
            // when the source isn't the default registry — treat as exotic.
            return Source::Tarball {
                url: tarball.clone(),
            };
        }
        if let Some(repo) = &res.repo {
            return Source::Git {
                url: repo.clone(),
                reference: res.commit.clone(),
            };
        }
        if let Some(dir) = &res.directory {
            return Source::File { path: dir.clone() };
        }
        if res.integrity.is_some() {
            // Standard registry resolution: `{ integrity: sha512-... }`.
            return Source::Registry { url: String::new() };
        }
    }
    Source::Registry { url: String::new() }
}

// ── pnpm-lock schema (subset we consume) ────────────────────────────────

#[derive(Debug, Deserialize)]
struct PnpmLock {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: String,

    // v9
    importers: Option<BTreeMap<String, Importer>>,

    // v6
    dependencies: Option<BTreeMap<String, DependencyRef>>,
    #[serde(rename = "devDependencies")]
    dev_dependencies: Option<BTreeMap<String, DependencyRef>>,

    #[serde(default)]
    packages: BTreeMap<String, PackageEntry>,
}

#[derive(Debug, Deserialize)]
struct Importer {
    dependencies: Option<BTreeMap<String, DependencyRef>>,
    #[serde(rename = "devDependencies")]
    dev_dependencies: Option<BTreeMap<String, DependencyRef>>,
}

#[derive(Debug, Deserialize)]
struct DependencyRef {
    version: String,
    #[serde(rename = "specifier")]
    _specifier: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PackageEntry {
    resolution: Option<Resolution>,
}

#[derive(Debug, Deserialize)]
struct Resolution {
    integrity: Option<String>,
    tarball: Option<String>,
    repo: Option<String>,
    commit: Option<String>,
    directory: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const V9: &str = r"
lockfileVersion: '9.0'
settings:
  autoInstallPeers: true
importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21
    devDependencies:
      typescript:
        specifier: ^5.4.0
        version: 5.4.5
packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-deadbeef}
  typescript@5.4.5:
    resolution: {integrity: sha512-cafebabe}
  follow-redirects@1.15.6:
    resolution: {integrity: sha512-x}
  some-git-dep@0.0.0:
    resolution:
      repo: https://github.com/x/y.git
      commit: abc123
";

    const V6: &str = r"
lockfileVersion: '6.0'
dependencies:
  lodash:
    specifier: ^4.17.21
    version: 4.17.21
devDependencies:
  typescript:
    specifier: ^5.4.0
    version: 5.4.5
packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-deadbeef}
  /@scope/pkg@1.0.0:
    resolution: {integrity: sha512-x}
  /typescript@5.4.5:
    resolution: {integrity: sha512-cafebabe}
";

    #[test]
    fn parses_v9() {
        let deps = parse_str(V9).unwrap();
        assert_eq!(deps.len(), 4);

        let lodash = deps.iter().find(|d| d.name == "lodash").unwrap();
        assert_eq!(lodash.version, "4.17.21");
        assert!(lodash.direct);
        assert!(matches!(lodash.source, Source::Registry { .. }));

        let ts = deps.iter().find(|d| d.name == "typescript").unwrap();
        assert!(ts.direct, "devDependencies count as direct");

        let follow = deps.iter().find(|d| d.name == "follow-redirects").unwrap();
        assert!(!follow.direct);

        let git = deps.iter().find(|d| d.name == "some-git-dep").unwrap();
        assert!(matches!(git.source, Source::Git { .. }));
    }

    #[test]
    fn parses_v6_with_scoped_keys() {
        let deps = parse_str(V6).unwrap();
        assert_eq!(deps.len(), 3);
        assert!(deps
            .iter()
            .any(|d| d.name == "@scope/pkg" && d.version == "1.0.0"));
        let lodash = deps.iter().find(|d| d.name == "lodash").unwrap();
        assert!(lodash.direct);
    }

    #[test]
    fn rejects_old_versions() {
        let raw = "lockfileVersion: '5.4'\npackages: {}\n";
        assert!(matches!(
            parse_str(raw),
            Err(AdapterError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn package_key_handles_peer_suffix() {
        assert_eq!(
            parse_package_key("react-dom@18.3.1(react@18.3.1)", 9),
            Some(("react-dom".into(), "18.3.1".into()))
        );
        assert_eq!(
            parse_package_key("/@scope/pkg@1.0.0", 6),
            Some(("@scope/pkg".into(), "1.0.0".into()))
        );
    }

    #[test]
    fn detects_filename() {
        let a = PnpmAdapter::new();
        assert!(a.detects(Path::new("/x/pnpm-lock.yaml")));
        assert!(!a.detects(Path::new("/x/package-lock.json")));
    }
}
