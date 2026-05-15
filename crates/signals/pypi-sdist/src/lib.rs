//! PyPI sdist scanner.
//!
//! For each resolved PyPI dependency, this provider:
//!
//! 1. Fetches `/pypi/<name>/<version>/json` to discover the
//!    canonical sdist (`.tar.gz` / `.zip` is out of scope today
//!    — only gzipped tarballs are scanned).
//! 2. Downloads the sdist (subject to a configurable size cap;
//!    25 MiB by default — large enough for everything reasonable,
//!    small enough that a malicious 5 GiB tarball can't DoS a CI
//!    job).
//! 3. Verifies the tarball's SHA-256 against the digest PyPI
//!    publishes for that file, when available. A digest mismatch
//!    is silent (no signal) — that is a registry-integrity
//!    concern, separately handled by lockfile-hash verification.
//! 4. Iterates the tar entries, locates `setup.py` at any depth
//!    (typically `<pkg>-<ver>/setup.py`), reads its body up to a
//!    1 MiB cap, and:
//!    * emits [`Signal::LifecycleScripts`] with `["setup.py"]`
//!      when the file is present (sdists with a `setup.py`
//!      execute it during `pip install`);
//!    * runs the body through [`scan_python_install_script`] —
//!      a union of the existing shell-pattern detector
//!      ([`installguard_core::script_scan::scan`], which
//!      catches things like `os.system("curl … | sh")`) and a
//!      Python-aware ruleset for idioms specific to install-time
//!      Python tradecraft (network-fetched payloads passed to
//!      `exec` / `eval`, `base64.b64decode(...)` smuggling,
//!      socket-based reverse shells). Each match emits a
//!      [`Signal::SuspiciousScript`].
//!
//! The provider fails soft on every kind of network or parse
//! error: anything other than "the file was scanned and we
//! found findings" produces zero signals (or a single
//! [`Signal::Unavailable`] when the failure is informative).
//! Absence of a signal means "we could not scan", not
//! "the package is safe" — true to the rest of the InstallGuard
//! signal model.

use std::io::Read;
use std::time::Duration;

use async_trait::async_trait;
use installguard_core::dependency::{Ecosystem, ResolvedDependency};
use installguard_core::signal::{Signal, SignalError, SignalProvider};
use serde::Deserialize;

mod python_patterns;

pub use python_patterns::{scan_python_install_script, PythonFinding};

const DEFAULT_BASE: &str = "https://pypi.org/pypi";
const DEFAULT_MAX_SDIST_BYTES: usize = 25 * 1024 * 1024; // 25 MiB
const SETUP_PY_BYTES_CAP: usize = 1024 * 1024; // 1 MiB
const USER_AGENT: &str = concat!("installguard-signal-pypi-sdist/", env!("CARGO_PKG_VERSION"));

#[derive(Debug)]
pub struct PypiSdistProvider {
    client: reqwest::Client,
    base: String,
    max_sdist_bytes: usize,
}

impl PypiSdistProvider {
    pub fn new() -> Result<Self, reqwest::Error> {
        Self::with_base(DEFAULT_BASE)
    }

    pub fn with_base(base: impl Into<String>) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(60))
            .build()?;
        Ok(Self {
            client,
            base: base.into().trim_end_matches('/').to_string(),
            max_sdist_bytes: DEFAULT_MAX_SDIST_BYTES,
        })
    }

    /// Override the maximum number of bytes the provider will
    /// download per sdist. Anything larger is skipped silently
    /// (returns [`Signal::Unavailable`] with reason
    /// `"sdist exceeds size cap"`).
    #[must_use]
    pub fn with_max_sdist_bytes(mut self, cap: usize) -> Self {
        self.max_sdist_bytes = cap;
        self
    }
}

#[async_trait]
impl SignalProvider for PypiSdistProvider {
    fn id(&self) -> &'static str {
        "pypi-sdist"
    }

    fn supports(&self, dep: &ResolvedDependency) -> bool {
        matches!(dep.ecosystem, Ecosystem::Pypi)
    }

    async fn signals(&self, dep: &ResolvedDependency) -> Result<Vec<Signal>, SignalError> {
        let metadata_url = format!("{}/{}/{}/json", self.base, dep.name, dep.version);
        tracing::debug!(url = %metadata_url, "fetching pypi metadata for sdist scan");
        let resp = self
            .client
            .get(&metadata_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| SignalError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Ok(vec![Signal::Unavailable {
                provider: "pypi-sdist".into(),
                reason: format!("metadata HTTP {}", resp.status()),
            }]);
        }
        let body: PypiResponse = resp
            .json()
            .await
            .map_err(|e| SignalError::Decode(e.to_string()))?;

        let Some(sdist) = pick_targz_sdist(&body.urls) else {
            return Ok(vec![Signal::Unavailable {
                provider: "pypi-sdist".into(),
                reason: "no .tar.gz sdist for this release".into(),
            }]);
        };

        // Check Content-Length up-front when the server provides it,
        // so we can skip pathological-size releases without spending
        // bandwidth.
        let head = self
            .client
            .head(&sdist.url)
            .send()
            .await
            .map_err(|e| SignalError::Network(e.to_string()))?;
        if let Some(len) = head.content_length() {
            if usize::try_from(len).is_ok_and(|n| n > self.max_sdist_bytes) {
                return Ok(vec![Signal::Unavailable {
                    provider: "pypi-sdist".into(),
                    reason: format!(
                        "sdist exceeds size cap ({len} bytes > {} bytes)",
                        self.max_sdist_bytes
                    ),
                }]);
            }
        }

        let bytes = self
            .client
            .get(&sdist.url)
            .send()
            .await
            .map_err(|e| SignalError::Network(e.to_string()))?
            .bytes()
            .await
            .map_err(|e| SignalError::Network(e.to_string()))?;

        if bytes.len() > self.max_sdist_bytes {
            return Ok(vec![Signal::Unavailable {
                provider: "pypi-sdist".into(),
                reason: format!(
                    "downloaded sdist exceeds size cap ({} > {})",
                    bytes.len(),
                    self.max_sdist_bytes
                ),
            }]);
        }

        // Verify SHA-256 against PyPI's published digest when
        // available. A mismatch produces no signal — registry
        // integrity is a separate concern (the lockfile hash
        // check is the gating one). Logged for audit.
        if let Some(expected) = sdist.digests.as_ref().and_then(|d| d.sha256.as_deref()) {
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            hasher.update(&bytes);
            let actual = hex::encode(hasher.finalize());
            if !actual.eq_ignore_ascii_case(expected) {
                tracing::warn!(
                    package = %dep.name,
                    version = %dep.version,
                    "pypi sdist sha256 mismatch (expected {expected}, got {actual})"
                );
                return Ok(vec![Signal::Unavailable {
                    provider: "pypi-sdist".into(),
                    reason: "sdist sha256 mismatch against PyPI metadata".into(),
                }]);
            }
        }

        let Some(setup_py) = extract_setup_py(&bytes, SETUP_PY_BYTES_CAP)
            .map_err(|e| SignalError::Decode(e.to_string()))?
        else {
            // No setup.py — increasingly common for modern
            // PEP 517-only sdists (pyproject.toml + a build
            // backend, no install-time Python). That's a
            // good thing; emit nothing.
            return Ok(Vec::new());
        };

        let mut out = vec![Signal::LifecycleScripts {
            scripts: vec!["setup.py".into()],
        }];

        for finding in scan_python_install_script(&setup_py) {
            out.push(Signal::SuspiciousScript {
                script: "setup.py".into(),
                pattern: finding.pattern.into(),
                excerpt: finding.excerpt,
            });
        }

        Ok(out)
    }
}

/// Pick the canonical sdist URL from a release's file list.
///
/// PyPI ships per-platform wheels alongside the sdist; we want
/// the source distribution (the file pip installs by running
/// `setup.py`). Today we only handle gzipped tarballs — `.zip`
/// sdists exist but are rare and use a different decompressor.
#[must_use]
pub fn pick_targz_sdist(files: &[PypiFile]) -> Option<&PypiFile> {
    files
        .iter()
        .find(|f| f.packagetype.as_deref() == Some("sdist") && f.filename.ends_with(".tar.gz"))
}

/// Decompress a `.tar.gz` blob, walk its entries, and return the
/// contents of the first `setup.py` found at any depth (capped at
/// `cap` bytes). Returns `Ok(None)` when no `setup.py` is in the
/// archive (a valid outcome for PEP 517-only sdists).
///
/// The reader is bounded by `cap` so a malicious tarball can't
/// inflate a setup.py to gigabytes; entries are streamed, not
/// buffered in full.
pub fn extract_setup_py(targz_bytes: &[u8], cap: usize) -> Result<Option<String>, std::io::Error> {
    let gz = flate2::read::GzDecoder::new(targz_bytes);
    let mut tar = tar::Archive::new(gz);
    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        if path.file_name().and_then(|n| n.to_str()) != Some("setup.py") {
            continue;
        }
        let mut buf = Vec::with_capacity(8 * 1024);
        let mut limited = entry.by_ref().take(cap as u64 + 1);
        limited.read_to_end(&mut buf)?;
        if buf.len() > cap {
            buf.truncate(cap);
        }
        // setup.py is conventionally UTF-8; fall back to a
        // lossy conversion so a non-UTF-8 byte sequence (which
        // is itself suspicious) still gets scanned.
        let body = String::from_utf8(buf)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
        return Ok(Some(body));
    }
    Ok(None)
}

#[derive(Debug, Clone, Deserialize)]
pub struct PypiResponse {
    #[serde(default)]
    pub urls: Vec<PypiFile>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PypiFile {
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub packagetype: Option<String>,
    #[serde(default)]
    pub digests: Option<PypiDigests>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PypiDigests {
    #[serde(default)]
    pub sha256: Option<String>,
}

/// Re-export the shell-pattern scan so callers can compose with it
/// directly; included in the public API for testing parity.
pub use installguard_core::script_scan::scan as shell_scan;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn build_targz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut tar = tar::Builder::new(&mut gz);
            for (path, data) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                tar.append(&header, *data).unwrap();
            }
            tar.finish().unwrap();
        }
        gz.finish().unwrap()
    }

    #[test]
    fn pick_targz_picks_sdist_only() {
        let files = vec![
            PypiFile {
                filename: "demo-1.0-py3-none-any.whl".into(),
                url: "x".into(),
                packagetype: Some("bdist_wheel".into()),
                digests: None,
            },
            PypiFile {
                filename: "demo-1.0.tar.gz".into(),
                url: "y".into(),
                packagetype: Some("sdist".into()),
                digests: None,
            },
        ];
        assert_eq!(pick_targz_sdist(&files).map(|f| f.url.as_str()), Some("y"));
    }

    #[test]
    fn pick_targz_skips_zip_sdist() {
        let files = vec![PypiFile {
            filename: "demo-1.0.zip".into(),
            url: "z".into(),
            packagetype: Some("sdist".into()),
            digests: None,
        }];
        assert!(pick_targz_sdist(&files).is_none());
    }

    #[test]
    fn extract_setup_py_finds_at_top_level() {
        let body = b"from setuptools import setup\nsetup(name='demo')\n";
        let targz = build_targz(&[("demo-1.0/setup.py", body)]);
        let out = extract_setup_py(&targz, 1024).unwrap();
        assert_eq!(out.as_deref(), Some(std::str::from_utf8(body).unwrap()));
    }

    #[test]
    fn extract_setup_py_returns_none_when_absent() {
        let targz = build_targz(&[("demo-1.0/pyproject.toml", b"[build-system]")]);
        let out = extract_setup_py(&targz, 1024).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn extract_setup_py_caps_oversized_body() {
        let big = vec![b'a'; 4096];
        let targz = build_targz(&[("demo-1.0/setup.py", &big)]);
        let out = extract_setup_py(&targz, 1000).unwrap().unwrap();
        assert_eq!(out.len(), 1000);
    }

    #[test]
    fn extract_setup_py_handles_non_utf8_bytes() {
        let body: &[u8] = b"# pre\n\xff\xfe\n# post\n";
        let targz = build_targz(&[("demo-1.0/setup.py", body)]);
        let out = extract_setup_py(&targz, 1024).unwrap().unwrap();
        assert!(out.contains("# pre"));
        assert!(out.contains("# post"));
    }

    #[test]
    fn extract_setup_py_streams_first_match_only() {
        let first = b"# first\n";
        let second = b"# second\n";
        let targz = build_targz(&[
            ("a/setup.py", first as &[u8]),
            ("b/setup.py", second as &[u8]),
        ]);
        let out = extract_setup_py(&targz, 1024).unwrap().unwrap();
        assert!(out.contains("first"));
        assert!(!out.contains("second"));
    }

    // Defeat dead-code warning for the helper below.
    #[allow(dead_code)]
    fn _writer_is_used(w: &mut dyn Write) {
        let _ = w;
    }
}
