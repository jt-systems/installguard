//! PyPI lockfile adapter.
//!
//! Three formats are supported:
//!
//! * **`uv.lock`** — the TOML lockfile produced by [`uv`](https://docs.astral.sh/uv/).
//!   Schema version 1. The first-class format for new Python projects and the
//!   one we recommend; it has the shape of a real lockfile (pinned versions,
//!   integrity hashes, full source URLs).
//!
//! * **`poetry.lock`** — the TOML lockfile produced by
//!   [Poetry](https://python-poetry.org/). Lock-version `1.x`, `2.x` are
//!   accepted; we read package entries plus the optional sibling
//!   `pyproject.toml` for the project's direct-dependency set
//!   (`[tool.poetry.dependencies]`, `[tool.poetry.group.*.dependencies]`,
//!   and PEP 621 `[project.dependencies]`). If no `pyproject.toml` sits
//!   beside the lockfile every entry is conservatively marked as
//!   transitive.
//!
//! * **`requirements.txt`** — the legacy pip format, **only** when produced
//!   by `pip-compile` / `uv pip compile` with `--generate-hashes`. A
//!   requirements.txt without `--hash=...` entries is a *wishlist*, not a
//!   lockfile, and is rejected with [`AdapterError::Parse`]. This is a
//!   deliberate security posture: lockfile-shaped behaviour requires
//!   lockfile-strength integrity.
//!
//! No support yet (file an issue if you need them):
//! `Pipfile.lock`, `pdm.lock`, `pyproject.toml` `[tool.uv]` sections.

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
            Some("uv.lock" | "poetry.lock" | "requirements.txt")
        )
    }

    fn parse(&self, path: &Path) -> Result<Vec<ResolvedDependency>, AdapterError> {
        let raw = std::fs::read_to_string(path)?;
        match path.file_name().and_then(|n| n.to_str()) {
            Some("uv.lock") => parse_uv_lock(&raw),
            Some("poetry.lock") => {
                // Poetry stores direct deps in pyproject.toml, not the
                // lockfile. Peek at the sibling file if present.
                let pyproject = path
                    .parent()
                    .and_then(|dir| std::fs::read_to_string(dir.join("pyproject.toml")).ok());
                parse_poetry_lock(&raw, pyproject.as_deref())
            }
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

// ── poetry.lock ────────────────────────────────────────────────────────────

/// Parse a `poetry.lock` document into normalised dependencies.
///
/// `poetry.lock` is the TOML lockfile written by
/// [Poetry](https://python-poetry.org/). Lock-version `1.x` and `2.x` are
/// both accepted; the package shape is the same across them (only the
/// `[metadata.files]` location differs, and we do not rely on it).
///
/// Direct vs transitive: poetry stores the project's direct
/// dependencies in `pyproject.toml`, not in `poetry.lock`. Pass the
/// pyproject contents via `pyproject_toml` to populate the
/// `direct = true` flag; with `None` every entry is conservatively
/// marked transitive.
pub fn parse_poetry_lock(
    raw: &str,
    pyproject_toml: Option<&str>,
) -> Result<Vec<ResolvedDependency>, AdapterError> {
    let lock: PoetryLock = toml::from_str(raw).map_err(|e| AdapterError::Parse(e.to_string()))?;

    if let Some(meta) = lock.metadata.as_ref() {
        if let Some(ver) = meta.lock_version.as_deref() {
            // Major version gate. Poetry has shipped 1.x and 2.x; they
            // share the per-package shape we read. Reject 0.x or future 3.x
            // explicitly so a schema change can't slip through silently.
            let major = ver.split('.').next().unwrap_or("");
            if !matches!(major, "1" | "2") {
                return Err(AdapterError::UnsupportedVersion(format!(
                    "poetry.lock lock-version {ver} (this build supports 1.x and 2.x)"
                )));
            }
        }
    }

    let direct_names: std::collections::BTreeSet<String> = pyproject_toml
        .map(extract_poetry_direct_names)
        .unwrap_or_default();

    let mut out = Vec::with_capacity(lock.package.len());
    for entry in lock.package {
        let normalised = normalise_pypi_name(&entry.name);
        let source = classify_poetry_source(entry.source.as_ref());
        let integrity = entry
            .files
            .iter()
            .find(|f| {
                std::path::Path::new(&f.file)
                    .extension()
                    .is_none_or(|ext| !ext.eq_ignore_ascii_case("whl"))
            })
            .or_else(|| entry.files.first())
            .and_then(|f| f.hash.clone())
            .map(Integrity);

        out.push(ResolvedDependency {
            ecosystem: Ecosystem::Pypi,
            name: normalised.clone(),
            version: entry.version,
            integrity,
            source,
            direct: direct_names.contains(&normalised),
            requested_by: vec![],
        });
    }

    out.sort_by(|a, b| (a.name.as_str(), a.version.as_str()).cmp(&(&b.name, &b.version)));
    Ok(out)
}

fn classify_poetry_source(source: Option<&PoetrySource>) -> Source {
    match source {
        None | Some(PoetrySource { type_: None, .. }) => Source::Pypi { url: String::new() },
        Some(s) => match s.type_.as_deref() {
            Some("git") => Source::Git {
                url: s.url.clone().unwrap_or_default(),
                reference: s.resolved_reference.clone().or_else(|| s.reference.clone()),
            },
            Some("url") => Source::Tarball {
                url: s.url.clone().unwrap_or_default(),
            },
            Some("file" | "directory") => Source::File {
                path: s.url.clone().unwrap_or_default(),
            },
            // "legacy" is poetry's name for a custom PEP 503 index;
            // semantically still a registry install, just not pypi.org.
            _ => Source::Pypi {
                url: s.url.clone().unwrap_or_default(),
            },
        },
    }
}

/// Extract the union of direct dependency names from a poetry-style
/// `pyproject.toml`. Reads three locations:
///
/// * `[tool.poetry.dependencies]` (poetry 1.x / 2.x in legacy mode)
/// * `[tool.poetry.group.<name>.dependencies]` (any group, including dev)
/// * `[project.dependencies]` (PEP 621, used by poetry 2.x in modern mode)
///
/// The `python` pin is excluded — it's the interpreter constraint, not a
/// package. Names are PEP 503 normalised. PEP 621 entries may carry
/// version markers (`requests>=2`) or extras (`requests[security]`); we
/// strip both to recover the bare distribution name.
fn extract_poetry_direct_names(pyproject_raw: &str) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    let Ok(value) = pyproject_raw.parse::<toml::Value>() else {
        return out;
    };

    // [tool.poetry.dependencies] and [tool.poetry.group.*.dependencies]
    if let Some(poetry) = value
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.as_table())
    {
        if let Some(deps) = poetry.get("dependencies").and_then(|d| d.as_table()) {
            for name in deps.keys() {
                if name != "python" {
                    out.insert(normalise_pypi_name(name));
                }
            }
        }
        if let Some(groups) = poetry.get("group").and_then(|g| g.as_table()) {
            for group in groups.values() {
                if let Some(deps) = group.get("dependencies").and_then(|d| d.as_table()) {
                    for name in deps.keys() {
                        if name != "python" {
                            out.insert(normalise_pypi_name(name));
                        }
                    }
                }
            }
        }
    }

    // PEP 621 [project.dependencies] is an array of PEP 508 strings.
    if let Some(deps) = value
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_array())
    {
        for entry in deps {
            if let Some(s) = entry.as_str() {
                if let Some(name) = pep508_name(s) {
                    out.insert(normalise_pypi_name(&name));
                }
            }
        }
    }

    out
}

/// Pull the bare distribution name out of a PEP 508 requirement string.
/// `requests`, `requests>=2.31`, `requests[security]>=2.31; python_version>='3.8'`
/// all collapse to `requests`.
fn pep508_name(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Stop at the first character that can't appear in a name.
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'))
        .unwrap_or(s.len());
    if end == 0 {
        None
    } else {
        Some(s[..end].to_string())
    }
}

#[derive(Debug, Deserialize)]
struct PoetryLock {
    #[serde(default)]
    package: Vec<PoetryPackage>,
    metadata: Option<PoetryMetadata>,
}

#[derive(Debug, Deserialize)]
struct PoetryMetadata {
    #[serde(rename = "lock-version", default)]
    lock_version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PoetryPackage {
    name: String,
    version: String,
    #[serde(default)]
    files: Vec<PoetryFile>,
    source: Option<PoetrySource>,
}

#[derive(Debug, Deserialize)]
struct PoetryFile {
    file: String,
    hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PoetrySource {
    #[serde(rename = "type", default)]
    type_: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    reference: Option<String>,
    #[serde(rename = "resolved_reference", default)]
    resolved_reference: Option<String>,
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

    // ── poetry.lock ────────────────────────────────────────────────────────

    const POETRY_SIMPLE: &str = r#"
[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=3.7"
files = [
    {file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:whl"},
    {file = "requests-2.31.0.tar.gz", hash = "sha256:sdist"},
]

[package.dependencies]
urllib3 = ">=1.21.1,<3"

[[package]]
name = "Urllib3"
version = "2.2.1"
description = "HTTP library."
optional = false
python-versions = ">=3.7"
files = [
    {file = "urllib3-2.2.1.tar.gz", hash = "sha256:u3"},
]

[[package]]
name = "vcs-pkg"
version = "0.1.0"
description = "From a git repo."
optional = false
python-versions = "*"
files = []

[package.source]
type = "git"
url = "https://github.com/example/vcs-pkg.git"
reference = "main"
resolved_reference = "deadbeefcafebabe"

[metadata]
lock-version = "2.0"
python-versions = ">=3.8"
content-hash = "abc123"
"#;

    const PYPROJECT_POETRY: &str = r#"
[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.8"
requests = "^2.31"

[tool.poetry.group.dev.dependencies]
vcs-pkg = { git = "https://github.com/example/vcs-pkg.git" }
"#;

    #[test]
    fn parses_poetry_lock_with_pyproject() {
        let deps = parse_poetry_lock(POETRY_SIMPLE, Some(PYPROJECT_POETRY)).unwrap();
        assert_eq!(deps.len(), 3, "got {deps:#?}");

        let requests = deps.iter().find(|d| d.name == "requests").unwrap();
        assert_eq!(requests.version, "2.31.0");
        assert!(requests.direct, "requests is in [tool.poetry.dependencies]");
        assert!(matches!(requests.source, Source::Pypi { .. }));
        // sdist hash preferred over wheel hash.
        assert_eq!(requests.integrity.as_ref().unwrap().0, "sha256:sdist");

        // PEP 503: `Urllib3` normalises to `urllib3`.
        let urllib3 = deps.iter().find(|d| d.name == "urllib3").unwrap();
        assert!(!urllib3.direct, "urllib3 only appears as a transitive dep");

        // Git source plumbed through with resolved reference.
        let vcs = deps.iter().find(|d| d.name == "vcs-pkg").unwrap();
        assert!(vcs.direct, "vcs-pkg is in the dev group");
        match &vcs.source {
            Source::Git { url, reference } => {
                assert_eq!(url, "https://github.com/example/vcs-pkg.git");
                assert_eq!(reference.as_deref(), Some("deadbeefcafebabe"));
            }
            other => panic!("expected git source, got {other:?}"),
        }
    }

    #[test]
    fn poetry_lock_without_pyproject_marks_all_transitive() {
        let deps = parse_poetry_lock(POETRY_SIMPLE, None).unwrap();
        assert!(
            deps.iter().all(|d| !d.direct),
            "no pyproject means no direct-set; got {deps:#?}"
        );
    }

    #[test]
    fn poetry_lock_pep621_dependencies_count_as_direct() {
        let pyproject = r#"
[project]
name = "demo"
dependencies = [
    "requests>=2.31",
    "urllib3[secure]>=2 ; python_version >= '3.8'",
]
"#;
        let deps = parse_poetry_lock(POETRY_SIMPLE, Some(pyproject)).unwrap();
        let requests = deps.iter().find(|d| d.name == "requests").unwrap();
        let urllib3 = deps.iter().find(|d| d.name == "urllib3").unwrap();
        assert!(requests.direct);
        assert!(urllib3.direct, "PEP 508 markers + extras stripped");
    }

    #[test]
    fn poetry_lock_rejects_unknown_lock_version() {
        let raw = r#"
[[package]]
name = "x"
version = "1.0"
files = []

[metadata]
lock-version = "3.0"
"#;
        let err = parse_poetry_lock(raw, None).unwrap_err();
        assert!(
            matches!(err, AdapterError::UnsupportedVersion(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn poetry_lock_dep_keys_use_pypi_prefix() {
        let deps = parse_poetry_lock(POETRY_SIMPLE, Some(PYPROJECT_POETRY)).unwrap();
        let requests = deps.iter().find(|d| d.name == "requests").unwrap();
        assert_eq!(requests.key(), "pypi/requests@2.31.0");
    }

    #[test]
    fn pep508_name_strips_markers_and_extras() {
        assert_eq!(pep508_name("requests").as_deref(), Some("requests"));
        assert_eq!(pep508_name("requests>=2.31").as_deref(), Some("requests"));
        assert_eq!(
            pep508_name("requests[security]").as_deref(),
            Some("requests")
        );
        assert_eq!(
            pep508_name("requests[security]>=2.31; python_version>='3.8'").as_deref(),
            Some("requests")
        );
        assert_eq!(pep508_name("").as_deref(), None);
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
    fn detects_supported_filenames() {
        let a = PypiAdapter::new();
        assert!(a.detects(Path::new("/x/uv.lock")));
        assert!(a.detects(Path::new("/x/poetry.lock")));
        assert!(a.detects(Path::new("/x/requirements.txt")));
        assert!(!a.detects(Path::new("/x/package-lock.json")));
        assert!(!a.detects(Path::new("/x/Pipfile.lock")));
    }

    #[test]
    fn id_and_ecosystem() {
        let a = PypiAdapter::new();
        assert_eq!(a.id(), "pypi");
        assert_eq!(a.ecosystem(), Ecosystem::Pypi);
    }
}
