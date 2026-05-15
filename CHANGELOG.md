# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is pre-1.0 the public Rust API (the `SignalProvider` trait,
`Signal`/`Reason` enums, and `Policy` schema) is treated as additive-only on
minor bumps; breaking changes are called out under a **Breaking** subsection.

## [Unreleased]

## [0.1.16] — 2026-05-15

Type-system placeholders for PyPI: `Ecosystem::Pypi` and
`Source::Pypi { url }` now ship in the core crate. Neither variant
is emitted by any adapter today (the PyPI adapter lands in a
later slice — see ROADMAP M8); they exist so downstream `match`
arms over `Ecosystem` and `Source` are forced to handle PyPI
*before* the adapter starts producing them, eliminating a class
of "we shipped PyPI but `cargo build` started failing in third
crate X" cliff edges.

* `Source::Pypi` is treated as non-exotic alongside
  `Source::Registry` and `Source::Workspace` (PyPI is a
  first-party registry source).
* `ResolvedDependency::key()` for a PyPI dep now produces the
  expected `pypi/<name>@<version>` form.
* The OSV provider deliberately skips PyPI deps for now
  (returns `None` from `ecosystem_label`); the `"PyPI"` label
  will be wired in alongside the PyPI signal slice.
* The cache key generator no longer hardcodes `"npm"` — it
  derives the registry namespace from
  `Ecosystem::registry_family().as_str()`, picking up `pypi`
  for free.

No user-facing CLI behaviour changes in this release.

## [0.1.15] — 2026-05-15

Policy allowlists now accept an optional `family:` ecosystem
prefix. Bare entries (`gaxios`, `my-pkg`) keep working unchanged
and match a package of that name in any registry family —
preserving back-compat with every 0.1.x policy in the wild. New
prefixed entries scope the allow to one family: `npm:lodash`
matches only npm-family packages (npm/pnpm/yarn), and `pypi:requests`
parses today as forward-compat for the PyPI adapter (ROADMAP M8).
The grammar applies to `defaults.nameSquatAllow` and
`scripts.allow`; scoped npm names (`@scope/name`,
`npm:@scope/name`) are accepted in both forms. Unknown family
prefixes (`pypy:lodash`) fail policy load loudly rather than
silently allowing nothing.

Internally the dependency cache key now derives from
`Ecosystem::registry_family()` rather than a hardcoded `"npm"`
literal — paving the way for a `pypi/<name>@<version>` namespace
without further core changes when the PyPI adapter lands.

## [0.1.14] — 2026-05-15

New `installguard simulate <candidate.yaml>` subcommand. Runs the
same evaluation pipeline as `scan` once against the project's
current policy, then re-evaluates every dependency against the
candidate policy using the *same* signals (no second network
round-trip), and prints the per-package decision diff: which
packages would be newly blocked, newly warned, newly allowed, or
have their reasons change while staying in the same decision
class. Pretty output groups by class with a `+`/`-` reason-code
delta per package; `--format json` emits a stable
machine-readable shape (`schemaVersion: 1`) with per-change
before/after `details` and `reasonCodes`. Always exits 0 —
simulate is advisory; gating belongs in `scan` or `ci`.
Completes the `explain` (why was this blocked?) /
`doctor` (what should I add to my policy?) /
`simulate` (what would happen if I added this?) triad — the
"propose → preview → merge" loop for policy changes without
requiring a separate scratch repo or a network re-fetch.

`--frozen` is rejected for `simulate` with a clear error: the
lock stores decisions, not raw signals, so a candidate policy
cannot be re-evaluated against it.

## [0.1.13] — 2026-05-15

New `installguard explain <name>@<version>` subcommand. Runs the
same evaluation pipeline as `scan` / `doctor`, but for one
package coordinate already present in the lockfile, prints the
full per-package audit trail: every signal observed (rendered as
compact JSON, one per line, so every variant round-trips
losslessly), every reason produced (with stable kebab-case code,
human summary, and remediation hint), and the trust-score
breakdown with each weighted contribution and rationale. Pretty
output is the default; `--format json` emits a stable
machine-readable shape (`schemaVersion: 1`) suitable for piping
into tooling. Always exits 0 — explain is informational; gating
belongs in `scan` or `ci`. Closes the "scan flagged this — *why*?"
loop without requiring operators to dig through audit logs or
re-run with `RUST_LOG=debug`.

`dist-tag-anomaly` heuristic tightened with three new
suppressions, all driven by false positives observed on real
production lockfiles. (1) **Sentinel filter**: versions with
`major >= 999` are dropped from the `highest_published`
candidate set. The motivating case is `react-native`, which
publishes `1000.0.0` precisely to break `npm install
react-native@latest`; treating it as the highest produced a
guaranteed false positive for every RN lockfile. (2)
**User-bypass at-or-past max**: if the resolved dep version is
itself `>= highest_published`, the operator has pinned past
`latest` deliberately (e.g. `accepts@2.0.0` while `latest=1.3.8`
during a cautious 2.x rollout) and the tag drift is irrelevant
to *their* install. (3) **User-bypass below latest major**: if
the resolved dep version is on a major *older* than `latest`,
the operator has explicitly stepped off the `latest` train
(e.g. `@expo/cli@54.0.24` while Expo SDK 55 is `latest` and SDK
56 is published) — the tag drift is information about an
ecosystem they're not on. The structural cross-major case
(`latest.major < highest.major`, both within the user's major)
remains the high-precision pattern we still surface.

Default `scripts.allow` gains `core-js` and `protobufjs`. Both
are the postinstall-runs-helper-script pattern (same shape as
`esbuild`, `playwright`, `supabase`): the script genuinely needs
to run for the package to function (`core-js` prints its sponsor
banner; `protobufjs` rebuilds its bundled gRPC descriptors), and
both packages satisfy the existing inclusion criteria — tens of
millions of weekly downloads each, single well-understood
install purpose, no historical takeover advisory tied to the
install script. Defaults remain a curated list, not a
free-for-all: operators wanting different behaviour set
`scripts.allow: []` to opt out, or list specific packages to
override.

## [0.1.12] — 2026-05-14

New `installguard doctor` subcommand. Runs the same evaluation
pipeline as `scan`, but instead of printing a verdict it groups
the actionable findings by class and emits a ready-to-paste
`installguard.yaml` block that resolves the false positives we
have a known fix for: lifecycle-script blocks become a `scripts.
allow` list (one entry per package, commented with the scripts
seen so reviewers can vet before allowing), name-squat blocks
become a `defaults.nameSquatAllow` list (commented with the
package each one resembles, so operators verify they intended
the package they have), and `dist-tag-anomaly` /
`signal-unavailable` blocks become explicit `severity: warn`
overrides (their default since 0.1.6 / 0.1.7 — surfacing this
suggests the operator had locally promoted them and may want to
revert). Doctor is advisory only — it always exits 0; use `scan`
or `ci` to gate. Closes the "blocked → triage → write config"
loop into a single command for first-time adopters.

## [0.1.11] — 2026-05-14

Default `scripts.allow` gains `supabase`. The npm-distributed
Supabase CLI is the postinstall-downloads-platform-binary pattern
(same shape as `esbuild`, `playwright`, `@biomejs/biome`): the
script genuinely needs to run for the package to function, and
the package satisfies the existing inclusion criteria — well over
1M weekly downloads, single well-understood install purpose
(fetch the platform-appropriate CLI binary from GitHub Releases
and install it into `node_modules/.bin`), no historical
takeover advisory tied to the install script. User-supplied
`scripts.allow` continues to extend (not replace) the built-in
default.

## [0.1.10] — 2026-05-14

Policy: `defaults.nameSquatAllow` allowlist for the name-squat
detector. Levenshtein-1 against the popular-name list catches
typosquats but also produces false positives for legitimate
packages whose names happen to sit close to a popular one — most
visibly `gaxios` (Google's official HTTP client) being flagged
against `axios`. Operators can now suppress specific names
without disabling the detector globally:

```yaml
policyVersion: 1
defaults:
  nameSquatAllow: [gaxios]
```

Allowlist is exact-match only — typo-of-an-allowlisted-name still
fires.

## [0.1.9] — 2026-05-14

Registry lookup: tolerate `v`-prefixed lockfile versions. Some
lockfiles record dependency versions with a leading `v`
(e.g. `@upstash/redis@v1.35.1` when npm/yarn resolved against a
GitHub release tag). The npm registry stores bare semver per the
[npmjs.org docs](https://docs.npmjs.com/about-semantic-versioning),
so a literal lookup of `v1.35.1` against the packument's `time`
or `versions` map missed every time and surfaced as
`signal-unavailable`. The provider now retries with the leading
`v` stripped (only when followed by an ASCII digit, so package
names like `velocity` are unaffected). The dependency continues
to be recorded with its lockfile-fidelity version in
`installguard.lock` and audit output — only the lookup is
normalized.

## [0.1.8] — 2026-05-14

Workspace-aware policy. Real-world monorepos (npm workspaces,
where each member appears in `package-lock.json` at its on-disk
path with no `resolved` URL) were producing one
`signal-unavailable` finding per workspace member because the
public registry returned `HTTP 404` for the private name. The npm
adapter now classifies these entries as `Source::Workspace`, the
CLI skips signal gathering for them, and `Policy::evaluate`
short-circuits to `Allow`. First-party code is not something the
registry-shaped detectors have anything useful to say about. The
yarn adapter already classified workspace members correctly; pnpm
keeps workspace members out of its `packages:` map and so was
unaffected.

## [0.1.7] — 2026-05-14

Policy: `signal-unavailable` default severity demoted from
`block` to `warn`. A provider failing to answer ("the npm
registry timed out", "the OSV API returned 503", "the
package was 404 because it's a private workspace package") is
not evidence of compromise — absence of evidence is not
evidence of attack. Real-world scans against monorepos and
networks with flaky egress were producing dozens of blocks per
run for transient or structural reasons. Operators who want
strict-fail-closed semantics can promote with
`severity.signal-unavailable: block` in `installguard.yaml`.

## [0.1.6] — 2026-05-14

Policy: `dist-tag-anomaly` default severity demoted from `block`
to `warn`. A backwards-moving `latest` tag is structurally unusual
but most often indicates a maintainer running an LTS line as
`latest` while a newer major exists on a separate tag (e.g.
`error-stack-parser` keeping 2.x as `latest` while 3.x is
published) — not an active attack. Operators who treat every
backwards tag as suspect can promote with
`severity.dist-tag-anomaly: block` in `installguard.yaml`.

## [0.1.5] — 2026-05-14

Bugfix: the per-reason `↳` remediation hint promised in 0.1.4
was wired into `Reason::remediation()` but never rendered —
the call site in `write_pretty_entry` was lost in a rebase.
Restored, so each finding now actually prints its hint
immediately under the bullet. The "Next steps" footer was
unaffected and shipped correctly in 0.1.4.

## [0.1.4] — 2026-05-14

Scan UX: actionable next-steps. A blocked install is only useful
if the operator knows what to do about it. Each finding now
carries a one-line remediation hint specific to its signal class
(e.g. `name-squat` → "verify you meant this package, not the
popular one it resembles"; `suspicious-script` → "treat as
suspected supply-chain attack; do NOT install — report to npm
security"), and the pretty output ends with a generic four-bullet
"Next steps" footer pointing at investigation, allowlisting,
freezing, and reporting paths.

### Added

- `Reason::remediation()` returns an `Option<&'static str>` short
  hint per variant. Exhaustive `match` keeps the table honest:
  adding a new `Reason` is a compile error in
  `every_reason_variant_has_a_remediation_or_is_explicitly_none`
  until its remediation is considered. Hints are capped at ~100
  chars to fit one terminal line.
- Pretty CLI output (`scan`/`ci`/`lock`/`attest`) now renders a
  dim `↳ <hint>` line under each finding, plus a "Next steps"
  footer when blocks or warns are present. The footer carries a
  concrete registry URL for the first blocked package so the
  operator can click straight through to investigate.
- The footer is suppressed on clean scans and respects the same
  `NO_COLOR` / non-TTY rules as the rest of the pretty output.

## [0.1.3] — 2026-05-14

Scan UX: live progress indicator. The `evaluate` phase used to
sit silent for several seconds while it fanned out to the
registry, deps.dev, OSV and Scorecard for every dependency. On
real-world lockfiles (~1k packages, ~3 s) this read as a hang.
A small Braille spinner now ticks on stderr at 10 Hz with a
`done/total` counter, redrawn in place; on completion the line
is cleared so the regular pretty verdict starts on column 0.

### Added

- Live `\u{2802}\u{2823}\u{2807}` Braille spinner during the
  signal-gather phase of `installguard scan`, `ci`, `lock` and
  `attest`. Format: `  \u{2839} scanning 423/1276`. Ticks from a
  Tokio task so it keeps moving even when the network stalls
  between completions.
- Indicator is fully suppressed when stderr is not a TTY (CI,
  pipes, redirects) and when `NO_COLOR` is set, on the same
  reasoning as the rest of the CLI's decorative output. No new
  dependencies — the helper is ~90 lines of `std::io::stderr`
  and `tokio::time`.

## [0.1.2] — 2026-05-14

Second maintenance release. Cuts a further 21 false-positive
blocks from the same real-world 1276-package scan that v0.1.1
drove down from ~120 to ~21 — the dominant remaining noise was
intentional LTS dist-tag holds and well-known native-binary
install scripts. Also retires the on-disk cache schema so the
v0.1.1 npm-registry fixes actually take effect on machines that
had already populated their cache.

### Added

- Default `scripts.allow` now includes a curated set of
  well-known native-binary / asset-bootstrap packages: `bcrypt`,
  `cypress`, `electron`, `esbuild`, `fsevents`, `msw`,
  `node-gyp`, `node-pre-gyp`, `playwright`, `puppeteer`, `sharp`.
  Inclusion criteria documented inline next to the constant. Same
  pattern as the typo allow-list shipped in v0.1.1: sorted slice,
  `binary_search` lookup, sortedness enforced by a unit test. The
  user-supplied `scripts.allow` continues to extend (not replace)
  the built-in default.

### Changed

- `DistTagAnomaly` now only fires when `latest`'s major version
  is *strictly less than* the highest published non-prerelease
  major. Same-major patch / minor drift is overwhelmingly
  intentional LTS-line maintenance (e.g. Storybook holding
  `latest=8.6.14` while `8.6.18` is published and `9.x` rides
  `next`) and was the dominant remaining source of false-positive
  blocks. The cross-major case — the structural high-precision
  signal — is unchanged. A future history-aware re-introduction
  of the same-major case (firing only when `latest` regressed
  from a previously-higher value) is possible once we cache prior
  packument metadata.

### Fixed

- `installguard scan` no longer reports `DistTagAnomaly` for a
  dependency that is itself on the version `latest` advertises.
  In real lockfiles this surfaced as actionable-looking blocks
  for `attr-accept@2.2.5` and `get-intrinsic@1.3.0` whose
  `dist-tags.latest` deliberately points at the older release
  line; the user is on `latest` and is not actually affected by
  the gap. The signal itself is still emitted (and feeds the
  trust score / audit log) so a future history-aware variant can
  consume it.
- Bumped the on-disk signal cache `SCHEMA_VERSION` from 1 to 2 so
  caches written by v0.1.0 / v0.1.1 are invalidated automatically
  on first use under v0.1.2. Without this bump, the v0.1.1 binary
  still surfaced stale `prepare` lifecycle-script blocks and stale
  `signal provider "npm-registry" unavailable: decode: …` warnings
  for any package whose packument was fetched and cached under
  the pre-fix code paths. The schema-version check that drops
  mismatched entries was already in place; only the constant
  needed bumping.

## [0.1.1] — 2026-05-14

First maintenance release. Reduces noise from real-world scans,
fixes a packument decode regression that affected the React 19
family, and ships the new `installguard report` subcommand that
was already merged on `develop` after v0.1.0.

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
  shared by VEX `action_statement`, audit logs, the new `report`
  subcommand, and the new `scan --format pretty` renderer.
  Stability guarantee: existing variants' *meaning* will not
  change between minor versions; new variants add new arms only.
- `installguard scan` gains a new `pretty` output format (now the
  default) that groups results by severity, renders each reason
  via `Reason::human_summary()`, and ANSI-colours the verdict /
  counts. Honours the conventional `NO_COLOR` env var
  (https://no-color.org) and disables colour automatically when
  stdout is not a TTY. The previous `human` and `json` formats
  remain available.
- Curated allow-list inside `name_similarity::classify` for
  well-known packages whose names are exactly distance-1 from a
  popular target (`ulid`/`uuid`, `nuxt`/`next`, `preact`/`react`,
  plus `redis`, `vitest`, `fastly`). Allow-listed names short-
  circuit to `Classification::Ok` without being promoted to new
  typosquat targets themselves.

### Changed

- GitHub Action ([`.github/actions/installguard/action.yml`](.github/actions/installguard/action.yml))
  and GitLab CI template ([`ci/gitlab/installguard.gitlab-ci.yml`](ci/gitlab/installguard.gitlab-ci.yml))
  now shell out to `installguard report` for the PR/MR comment body.
  Previously each surface had its own renderer (JavaScript and
  Python respectively) covering only 6 of the ~20 `Reason` variants
  — every M3/M4 reason was rendered as an opaque kebab-case code.
  Both surfaces now describe every variant in plain English with no
  template-side maintenance.
- Default `--format` for `installguard scan` switches from `human`
  to `pretty`. Scripts that grep one-line-per-decision output
  should pass `--format human` explicitly.

### Fixed

- `installguard-signal-npm-registry` could fail to decode any
  packument whose per-version `deprecated` field arrived as a
  JSON boolean instead of the documented string — notably
  `react@19.x`, `react-dom@19.x`, `scheduler@0.25+`, `react-is`,
  and `react-reconciler`. Previously the entire packument decode
  errored with `invalid type: boolean`, which downgraded those
  packages to `signal_unavailable` and forced a BLOCK on policies
  requiring publish-time anomaly checks. The field now uses a
  custom deserialiser that preserves any string verbatim and
  coerces every other shape (boolean, null, number, array,
  object) to `None`.
- The npm registry adapter no longer reports `prepare` as a
  registry lifecycle script. `prepare` only runs on `npm install`
  from a git source, never from a registry tarball, so reporting
  it for registry packuments generated `DisallowedLifecycleScript`
  noise on every package whose maintainers declare a build-time
  `prepare` (Husky, TypeScript libraries, the React monorepo,
  etc.) without flagging anything that can actually execute on
  the consumer's machine. Git-source dependencies remain gated
  by the `Source::Git` rules in policy.rs.
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

[Unreleased]: https://github.com/jt-systems/installguard/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/jt-systems/installguard/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/jt-systems/installguard/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jt-systems/installguard/releases/tag/v0.1.0
