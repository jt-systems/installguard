# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is pre-1.0 the public Rust API (the `SignalProvider` trait,
`Signal`/`Reason` enums, and `Policy` schema) is treated as additive-only on
minor bumps; breaking changes are called out under a **Breaking** subsection.

## [Unreleased]

### Added

- New `installguard report --from <summary.json>` subcommand that
  renders a `ci --summary-file` JSON document as the canonical
  Markdown sticky-comment body (GitHub PR / GitLab MR / any GFM
  consumer). Output is deterministic, includes the
  `<!-- installguard-summary -->` HTML marker for sticky-comment
  idempotency, escapes `|` in reason cells, and truncates with
  `--max-rows`. Optional `--commit` and `--exit-code` flags surface
  context in the comment footer.
- `Reason::human_summary()` promoted from a private function in
  `vex.rs` to a public method on `Reason`. This is the single
  source of truth for English renderings of reason variants and is
  shared by VEX `action_statement`, audit logs, and the new
  `report` subcommand. Stability guarantee: existing variants'
  *meaning* will not change between minor versions; new variants
  add new arms only.

### Changed

- GitHub Action ([`.github/actions/installguard/action.yml`](.github/actions/installguard/action.yml))
  and GitLab CI template ([`ci/gitlab/installguard.gitlab-ci.yml`](ci/gitlab/installguard.gitlab-ci.yml))
  now shell out to `installguard report` for the PR/MR comment body.
  Previously each surface had its own renderer (JavaScript and
  Python respectively) covering only 6 of the ~20 `Reason` variants
  — every M3/M4 reason was rendered as an opaque kebab-case code.
  Both surfaces now describe every variant in plain English with no
  template-side maintenance.

### Fixed

- PR / MR sticky comments now describe `advisory_known`,
  `license_disallowed`, `scorecard_below_threshold`,
  `maintainer_new_account`, `name_squat`,
  `version_surface_change`, `dist_tag_anomaly`,
  `trust_score_below_threshold`, `provenance_missing`,
  `project_archived`, `license_missing`, `publisher_change`,
  `deprecated_version`, and `suspicious_script` properly. Previously
  these displayed only their kebab-case code on both GitHub and
  GitLab.

## [0.1.0] — 2026-05-13

First tagged alpha. Covers milestones M0 through M4 from
[`ROADMAP.md`](ROADMAP.md).

### Added — M0 / M1 (foundations)

- Project scaffolding, workspace layout, lint baseline, design docs, CI matrix,
  release workflow stub, deny.toml, pinned toolchain.
- npm/pnpm/yarn lockfile parsers and resolved-dependency model.
- `npm-registry` signal provider with on-disk caching.
- Core `Signal`, `Reason`, `Decision`, and `Policy` types with YAML + JSON
  schema and golden-file round-tripping.
- `lifecycle-scripts`, `published-at` (minimum release age), and
  `suspicious-script` heuristics.
- CLI `installguard eval` with allow/warn/block exit codes and human +
  machine-readable output.

### Added — M2 (evidence and offline mode)

- CycloneDX 1.5 SBOM export with per-component policy-decision properties.
- in-toto v1 attestation predicate (`policy-evaluation/v1`).
- OpenVEX 0.2.0 export, one document per blocked decision, with
  human-readable justifications.
- JSONL audit log sink for downstream SIEM ingestion.
- `--frozen-policy` mode that pins all signal inputs into the lockfile so
  later evaluations are reproducible without network.
- Cosign-compatible DSSE signing of attestations (ed25519 keys; keyless flow
  deferred until first tagged release proves the workflow end-to-end).

### Added — M3 (publisher and provenance signals)

- Publisher-change detection from npm packument history.
- Deprecated-version detection.
- Static analysis of install-script bodies (curl-pipe-to-shell, base64 exec,
  network egress in postinstall, etc.).
- Version-surface-change detector (file-list deltas between adjacent
  versions).
- Dist-tag anomaly detector (e.g. `latest` moved to an older version).
- Typosquat / homoglyph name-similarity detector against a curated
  high-value-target list.
- Maintainer-account-age detector with `minMaintainerAccountAgeDays` policy
  gate.
- Sigstore provenance attestation structural verification (bundle parsed,
  certificate chain validated against Fulcio root, identity/issuer matched).
- Trust-score capstone: per-signal contributions fold into a 0-100 score with
  a `minTrustScore` policy gate.

### Added — M4 (third-party intelligence and extensibility)

- `installguard-signal-osv` — OSV.dev advisory provider, severity bucketed
  from CVSS v3 base score, gated by `maxAdvisorySeverity`.
- `installguard-signal-depsdev` — deps.dev project-metadata provider feeding
  `requireLicense`, `licenseAllowlist`, and `blockArchived` policy gates.
- `installguard-signal-scorecard` — OpenSSF Scorecard provider with two-step
  npm→repo→score lookup, gated by `minScorecardScore`.
- `CompositeProvider` — fans signal collection out across multiple providers
  in parallel, materialising per-provider failures as `Signal::Unavailable`
  rather than aborting the run.
- CLI flags `--no-osv`, `--no-deps-dev`, `--no-scorecard` to opt out of
  individual external providers.
- Public `SignalProvider` trait stabilised with semver guarantees from 0.1
  onwards; worked example at
  [`crates/core/examples/minimal_provider.rs`](crates/core/examples/minimal_provider.rs).

### Deferred

- **Maintainer 2FA enforcement signal** — npm's public registry does not
  expose per-account 2FA status; revisit if/when a credible upstream source
  appears.
- **Socket / Snyk providers** — both require paid API keys; left as
  community-maintained out-of-tree crates against the now-public
  `SignalProvider` trait.
- **Plugin discovery + signature verification** — needs `dlopen`/wasm
  infrastructure and a signing trust root; tracked for M7+.
- **Sigstore keyless signing in CI** — the SLSA generator step in
  [`.github/workflows/release.yml`](.github/workflows/release.yml) is wired
  but commented out pending a real first-release dry run.

[Unreleased]: https://github.com/jt-systems/installguard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jt-systems/installguard/releases/tag/v0.1.0
