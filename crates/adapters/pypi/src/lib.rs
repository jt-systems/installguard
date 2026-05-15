//! PyPI lockfile adapter.
//!
//! Two formats are supported:
//!
//! * **`uv.lock`** — the TOML lockfile produced by [`uv`](https://docs.astral.sh/uv/).
//!   Schema version 1. The first-class format for new Python projects and the
//!   one we recommend; it has the shape of a real lockfile (pinned versions,
//!   integrity hashes, full source URLs).
//!
//! * **`requirements.txt`** — the legacy pip format, **only** when produced
//!   by `pip-compile` / `uv pip compile` with `--generate-hashes`. A
//!   requirements.txt without `--hash=...` entries is a *wishlist*, not a
//!   lockfile, and is rejected with [`AdapterError::Parse`]. This is a
//!   deliberate security posture: lockfile-shaped behaviour requires
//!   lockfile-strength integrity.
//!
//! No support yet (file an issue if you need them):
//! `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `pyproject.toml` `[tool.uv]` sections.

use std::path::Path;

use installguard_core::adapter::{AdapterError, LockfileAdapter};
use installguard_core::dependency::{Ecosystem, Integrity, ResolvedDependency, Source};
use serde::Deserialize;

#[derive(Debug, Default)]
pub struct PypiAdapter;

impl PypiAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl LockfileAdapter for PypiAdapter {
    fn id(&self) -> &'static str {
        "pypi"
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Pypi
    }

    fn detects(&self, path: &Path) -> bool {
        matches!(
            path.file_name().and_then(|n| n.to_str()),
            Some("uv.lock" | "requirements.txt")
        )
    }

    fn parse(&self, path: &Path) -> Result<Vec<ResolvedDependency>, AdapterError> {
        let raw = std::fs::read_to_string(path)?;
        match path.file_name().and_then(|n| n.to_str()) {
            Some("uv.lock") => parse_uv_lock(&raw),
            Some("requirements.txt") => parse_requirements_txt(&raw),
            _ => Err(AdapterError::Parse(format!(
                "unsupported pypi lockfile name: {}",
                path.display()
            ))),
        }
    }
}

// ── uv.lock ────────────────────────────────────────────────────────────────

/// Parse a `uv.lock` document into normalised dependencies.
///
/// `uv.lock` is the canonical lockfile for [`uv`](https://docs.astral.sh/uv/).
/// We accept `version = 1` only; future schema bumps will need an explicit
/// arm here so we can map their shape.
pub fn parse_uv_lock(raw: &str) -> Result<Vec<ResolvedDependency>, AdapterError> {
    let lock: UvLock = toml::from_str(raw).map_err(|e| AdapterError::Parse(e.to_string()))?;
    if lock.version != 1 {
        return Err(AdapterError::UnsupportedVersion(format!(
            "uv.lock version {} (this build supports version 1 only)",
            lock.version
        )));
    }

    // Identify the root virtual package (the workspace root). Its
    // `dependencies` list is what we treat as direct deps; everything else
    // is transitive.
    let direct_names: std::collections::BTreeSet<String> = lock
        .package
        .iter()
        .find(|p| matches!(p.source, Some(UvSource::Virtual { .. })))
        .map(|root| {
            root.dependencies
                .iter()
                .map(|d| normalise_pypi_name(&d.name))
                .collect()
        })
        .unwrap_or_default();

    let mut out = Vec::with_capacity(lock.package.len());
    for entry in lock.package {
        let normalised = normalise_pypi_name(&entry.name);
        let Some(version) = entry.version.clone() else {
            // Virtual root has no version; skip (it's the project itself).
            continue;
        };

        let source = classify_uv_source(entry.source.as_ref(), entry.sdist.as_ref(), &entry.wheels);
        // Skip the virtual root (the project itself, serialised as
        // `source = { virtual = "." }`). Other workspace members keep
        // their `Source::Workspace` and surface in the dep list.
        if matches!(
            entry.source,
            Some(UvSource::Virtual { ref virtual_path }) if virtual_path == "."
        ) {
            continue;
        }

        // First sdist hash (preferred) or the first wheel hash.
        let integrity = entry
            .sdist
            .as_ref()
            .and_then(|s| s.hash.clone())
            .or_else(|| entry.wheels.first().and_then(|w| w.hash.clone()))
            .map(Integrity);

        out.push(ResolvedDependency {
            ecosystem: Ecosystem::Pypi,
            name: normalised.clone(),
            version,
            integrity,
            source,
            direct: direct_names.contains(&normalised),
            requested_by: vec![],
        });
    }

    out.sort_by(|a, b| (a.name.as_str(), a.version.as_str()).cmp(&(&b.name, &b.version)));
    Ok(out)
}

fn classify_uv_source(
    source: Option<&UvSource>,
    sdist: Option<&UvDistribution>,
    wheels: &[UvDistribution],
) -> Source {
    match source {
        Some(UvSource::Registry { .. }) | None => {
            // Prefer the sdist URL (the canonical artifact); fall back to
            // the first wheel URL.
            let url = sdist
                .and_then(|s| s.url.clone())
                .or_else(|| wheels.first().and_then(|w| w.url.clone()))
                .unwrap_or_default();
            Source::Pypi { url }
        }
        Some(UvSource::Virtual { .. }) => Source::Workspace,
        Some(UvSource::Editable { editable }) => Source::File {
            path: editable.clone(),
        },
        Some(UvSource::Directory { directory }) => Source::File {
            path: directory.clone(),
        },
        Some(UvSource::Git { git }) => Source::Git {
            url: git.clone(),
            reference: None,
        },
        Some(UvSource::Url { url }) => Source::Tarball { url: url.clone() },
    }
}

#[derive(Debug, Deserialize)]
struct UvLock {
    version: u32,
    #[serde(default)]
    package: Vec<UvPackage>,
}

#[derive(Debug, Deserialize)]
struct UvPackage {
    name: String,
    version: Option<String>,
    source: Option<UvSource>,
    sdist: Option<UvDistribution>,
    #[serde(default)]
    wheels: Vec<UvDistribution>,
    #[serde(default)]
    dependencies: Vec<UvDep>,
}

#[derive(Debug, Deserialize)]
struct UvDep {
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum UvSource {
    Registry {
        #[allow(dead_code)]
        registry: String,
    },
    Virtual {
        #[serde(rename = "virtual")]
        #[allow(dead_code)]
        virtual_path: String,
    },
    Editable {
        editable: String,
    },
    Directory {
        directory: String,
    },
    Git {
        git: String,
    },
    Url {
        url: String,
    },
}

#[derive(Debug, Deserialize)]
struct UvDistribution {
    url: Option<String>,
    hash: Option<String>,
}

// ── requirements.txt (pip-compile / uv pip compile --generate-hashes) ──────

/// Parse a hash-pinned `requirements.txt` produced by `pip-compile` or
/// `uv pip compile --generate-hashes`.
///
/// Every package entry **must** carry at least one `--hash=...` line;
/// otherwise the file is rejected with [`AdapterError::Parse`]. Loose
/// `requirements.txt` files are wishlists, not lockfiles, and shipping a
/// lockfile-shaped adapter against them would silently lower the bar.
pub fn parse_requirements_txt(raw: &str) -> Result<Vec<ResolvedDependency>, AdapterError> {
    // Two-pass: collapse `\`-continuations into logical lines first, then
    // pair each requirement with the `# via ...` annotation pip-compile
    // emits *immediately after* it (before the next requirement).
    let mut logical: Vec<String> = Vec::new();
    let mut buf = String::new();
    for line in raw.lines() {
        let trimmed = line.trim_end();
        let no_cont = trimmed.strip_suffix('\\').unwrap_or(trimmed);
        buf.push_str(no_cont);
        buf.push('\n');
        if !trimmed.ends_with('\\') {
            let line = std::mem::take(&mut buf);
            let line = line.trim().to_string();
            if !line.is_empty() {
                logical.push(line);
            }
        }
    }

    // Now walk logical lines. A requirement entry is followed (optionally)
    // by one or more `# via ...` comment lines that belong to it.
    let mut entries: Vec<(String, Option<String>)> = Vec::new();
    for line in logical {
        if let Some(rest) = line.strip_prefix("# via ") {
            // Attach to the most recent requirement, if any.
            if let Some(last) = entries.last_mut() {
                last.1 = Some(rest.trim().to_string());
            }
            continue;
        }
        if line.trim_start().starts_with('#') {
            continue;
        }
        if line.starts_with('-') {
            // pip directive (`-r`, `-c`, `-e`, `--index-url`, ...). Skip.
            continue;
        }
        entries.push((line, None));
    }

    let mut out = Vec::with_capacity(entries.len());
    for (line, via) in entries {
        out.push(parse_requirement_line(&line, via.as_deref())?);
    }

    if out.is_empty() {
        return Err(AdapterError::Parse(
            "requirements.txt contained no package entries (is it empty?)".into(),
        ));
    }

    out.sort_by(|a, b| (a.name.as_str(), a.version.as_str()).cmp(&(&b.name, &b.version)));
    Ok(out)
}

fn parse_requirement_line(
    line: &str,
    via: Option<&str>,
) -> Result<ResolvedDependency, AdapterError> {
    // Split off `--hash=...` tokens.
    let mut tokens = line.split_whitespace();
    let head = tokens
        .next()
        .ok_or_else(|| AdapterError::Parse(format!("empty requirement line: {line:?}")))?;

    let mut hashes: Vec<&str> = Vec::new();
    for tok in tokens {
        if let Some(h) = tok.strip_prefix("--hash=") {
            hashes.push(h);
        }
    }

    if hashes.is_empty() {
        return Err(AdapterError::Parse(format!(
            "requirements.txt entry `{head}` is missing `--hash=` pins; \
             regenerate with `uv pip compile --generate-hashes` or \
             `pip-compile --generate-hashes` so InstallGuard can treat it as a lockfile"
        )));
    }

    // `head` is `<name>[extras]==<version>` (pip-compile always emits `==`
    // pins). Strip extras like `requests[security]==2.31.0` → `requests`.
    let (raw_name, version) = head.split_once("==").ok_or_else(|| {
        AdapterError::Parse(format!(
            "requirements.txt entry `{head}` is not pinned with `==`; \
             only fully-pinned entries are accepted"
        ))
    })?;
    let name = raw_name.split_once('[').map_or(raw_name, |(n, _)| n);
    let normalised = normalise_pypi_name(name);

    // pip-compile's `# via -r requirements.in` (or `# via -c ...`) marks a
    // top-level entry pulled directly from the user's input file. Anything
    // with a different `via` is transitive. No `via` annotation at all
    // (older pip-compile, or hand-written hash-pinned files) defaults to
    // direct.
    let direct = via.is_none_or(|v| v.starts_with("-r ") || v.starts_with("-c ") || v.is_empty());

    Ok(ResolvedDependency {
        ecosystem: Ecosystem::Pypi,
        name: normalised,
        version: version.to_string(),
        integrity: Some(Integrity(hashes[0].to_string())),
        source: Source::Pypi { url: String::new() },
        direct,
        requested_by: vec![],
    })
}

// ── PEP 503 name normalisation ────────────────────────────────────────────

/// Normalise a PyPI distribution name per [PEP 503].
///
/// Lower-case the name and collapse any run of `-`, `_`, `.` to a single
/// `-`. `Requests`, `requests`, `Re_quests` and `re.quests` all become
/// `requests`.
///
/// [PEP 503]: https://peps.python.org/pep-0503/#normalized-names
#[must_use]
pub fn normalise_pypi_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_was_sep = false;
    for ch in name.chars() {
        if ch == '-' || ch == '_' || ch == '.' {
            if !last_was_sep && !out.is_empty() {
                out.push('-');
            }
            last_was_sep = true;
        } else {
            out.extend(ch.to_lowercase());
            last_was_sep = false;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── uv.lock ────────────────────────────────────────────────────────────

    const UV_SIMPLE: &str = r#"
version = 1

[[package]]
name = "demo-app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
    { name = "rich" },
]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/.../requests-2.31.0.tar.gz", hash = "sha256:abc" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/.../requests-2.31.0-py3-none-any.whl", hash = "sha256:def" },
]
dependencies = [{ name = "urllib3" }]

[[package]]
name = "Rich"
version = "13.7.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/.../rich-13.7.0.tar.gz", hash = "sha256:ghi" }

[[package]]
name = "urllib3"
version = "2.2.1"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/.../urllib3-2.2.1.tar.gz", hash = "sha256:jkl" }
"#;

    #[test]
    fn parses_uv_lock_v1() {
        let deps = parse_uv_lock(UV_SIMPLE).unwrap();
        // demo-app (virtual root) is suppressed; 3 deps remain.
        assert_eq!(deps.len(), 3, "got {deps:#?}");

        let requests = deps.iter().find(|d| d.name == "requests").unwrap();
        assert_eq!(requests.version, "2.31.0");
        assert!(requests.direct, "requests is in root deps");
        assert!(matches!(requests.source, Source::Pypi { .. }));
        assert_eq!(requests.integrity.as_ref().unwrap().0, "sha256:abc");

        // PEP 503: `Rich` normalises to `rich`.
        let rich = deps.iter().find(|d| d.name == "rich").unwrap();
        assert!(rich.direct);

        let urllib3 = deps.iter().find(|d| d.name == "urllib3").unwrap();
        assert!(
            !urllib3.direct,
            "urllib3 is transitive (only requests lists it)"
        );
    }

    #[test]
    fn rejects_unknown_uv_lock_version() {
        let raw = r#"version = 99
[[package]]
name = "x"
version = "1.0"
source = { virtual = "." }
"#;
        assert!(matches!(
            parse_uv_lock(raw),
            Err(AdapterError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn uv_lock_dep_keys_use_pypi_prefix() {
        let deps = parse_uv_lock(UV_SIMPLE).unwrap();
        let requests = deps.iter().find(|d| d.name == "requests").unwrap();
        assert_eq!(requests.key(), "pypi/requests@2.31.0");
    }

    // ── requirements.txt ───────────────────────────────────────────────────

    const REQ_HASHED: &str = "\
# This file was autogenerated by uv via the following command:
#    uv pip compile pyproject.toml --generate-hashes -o requirements.txt
requests==2.31.0 \\
    --hash=sha256:abc \\
    --hash=sha256:def
    # via -r requirements.in
urllib3==2.2.1 \\
    --hash=sha256:jkl
    # via requests
";

    #[test]
    fn parses_hashed_requirements_txt() {
        let deps = parse_requirements_txt(REQ_HASHED).unwrap();
        assert_eq!(deps.len(), 2);

        let requests = deps.iter().find(|d| d.name == "requests").unwrap();
        assert_eq!(requests.version, "2.31.0");
        assert_eq!(requests.integrity.as_ref().unwrap().0, "sha256:abc");
        assert!(requests.direct, "via -r ... means top-level");

        let urllib3 = deps.iter().find(|d| d.name == "urllib3").unwrap();
        assert!(!urllib3.direct, "via requests means transitive");
    }

    #[test]
    fn rejects_requirements_without_hashes() {
        let raw = "requests==2.31.0\nurllib3==2.2.1\n";
        let err = parse_requirements_txt(raw).unwrap_err();
        assert!(
            matches!(err, AdapterError::Parse(ref m) if m.contains("missing `--hash=`")),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_unpinned_requirements() {
        let raw = "requests>=2.31.0 --hash=sha256:abc\n";
        let err = parse_requirements_txt(raw).unwrap_err();
        assert!(
            matches!(err, AdapterError::Parse(ref m) if m.contains("not pinned with `==`")),
            "got {err:?}"
        );
    }

    #[test]
    fn strips_extras_from_name() {
        let raw = "requests[security]==2.31.0 --hash=sha256:abc\n";
        let deps = parse_requirements_txt(raw).unwrap();
        assert_eq!(deps[0].name, "requests");
    }

    #[test]
    fn skips_pip_directives() {
        let raw = "\
-r other.txt
--index-url https://example.com/simple
requests==2.31.0 --hash=sha256:abc
";
        let deps = parse_requirements_txt(raw).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "requests");
    }

    // ── PEP 503 normalisation ─────────────────────────────────────────────

    #[test]
    fn pep503_normalisation() {
        assert_eq!(normalise_pypi_name("requests"), "requests");
        assert_eq!(normalise_pypi_name("Requests"), "requests");
        assert_eq!(normalise_pypi_name("zope.interface"), "zope-interface");
        assert_eq!(normalise_pypi_name("Re_quests"), "re-quests");
        assert_eq!(normalise_pypi_name("foo--bar__baz"), "foo-bar-baz");
        assert_eq!(normalise_pypi_name("pip-tools"), "pip-tools");
    }

    // ── adapter trait surface ─────────────────────────────────────────────

    #[test]
    fn detects_both_filenames() {
        let a = PypiAdapter::new();
        assert!(a.detects(Path::new("/x/uv.lock")));
        assert!(a.detects(Path::new("/x/requirements.txt")));
        assert!(!a.detects(Path::new("/x/package-lock.json")));
        assert!(!a.detects(Path::new("/x/poetry.lock")));
    }

    #[test]
    fn id_and_ecosystem() {
        let a = PypiAdapter::new();
        assert_eq!(a.id(), "pypi");
        assert_eq!(a.ecosystem(), Ecosystem::Pypi);
    }
}
