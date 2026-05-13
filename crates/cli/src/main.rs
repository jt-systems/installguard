//! `installguard` CLI entrypoint.
//!
//! Subcommands:
//! * `scan` — interactive developer use; pretty or JSON output.
//! * `ci`   — pipeline use; machine-readable summary, optional GitHub
//!   workflow annotations, configurable failure thresholds.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use futures::stream::{FuturesUnordered, StreamExt};
use installguard_adapter_npm::NpmAdapter;
use installguard_adapter_pnpm::PnpmAdapter;
use installguard_adapter_yarn::YarnAdapter;
use installguard_cache::{CachedProvider, SignalCache, Ttl};
use installguard_core::adapter::LockfileAdapter;
use installguard_core::attestation::Statement;
use installguard_core::decision::{Decision, Reason};
use installguard_core::dependency::ResolvedDependency;
use installguard_core::lockfile::{InstallguardLock, LockEntry};
use installguard_core::policy::{EvalContext, Policy};
use installguard_core::signal::{SignalProvider, SignalSet};
use installguard_signal_npm_registry::NpmRegistryProvider;

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

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
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
    let signal_sets = gather_signals(provider.as_ref(), &deps, args.concurrency).await;

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
                ecosystem: Ecosystem::Npm,
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
    // projects sometimes also ship a stale npm lockfile.
    let candidates = ["pnpm-lock.yaml", "yarn.lock", "package-lock.json"];
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
    let registry = NpmRegistryProvider::new().context("building http client")?;
    if args.no_cache {
        return Ok(Box::new(registry));
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
        registry,
        cache,
        Ttl::default(),
    )))
}

fn default_cache_dir() -> Result<PathBuf> {
    let base = dirs::cache_dir().ok_or_else(|| anyhow!("could not determine user cache dir"))?;
    Ok(base.join("installguard"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_property_escapes_specials() {
        assert_eq!(escape_workflow_property("a:b,c\nd%e"), "a%3Ab%2Cc%0Ad%25e");
    }

    #[test]
    fn workflow_data_keeps_colons_and_commas() {
        assert_eq!(escape_workflow_data("a:b,c\nd%e"), "a:b,c%0Ad%25e");
    }
}
