# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is pre-1.0 the public Rust API (the `SignalProvider` trait,
`Signal`/`Reason` enums, and `Policy` schema) is treated as additive-only on
minor bumps; breaking changes are called out under a **Breaking** subsection.

## [Unreleased]

## [0.3.0] — 2026-05-15

**Release-binary signing and SLSA Build Level 3 provenance.** The
release workflow now Cosign-signs every published binary plus
`checksums.txt`, and emits a SLSA v1.0 Build Level 3 provenance
attestation covering the same artefacts. This closes the
"known-pending" item from 0.2.9 and the long-standing
`v0.3 roadmap` Sigstore signing milestone.

* **Cosign keyless signing.** The release job runs
  [`cosign sign-blob`](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/)
  against every binary in the matrix and against
  `checksums.txt`, producing a `*.cosign.bundle` Sigstore bundle
  (DSSE envelope + Fulcio cert chain + Rekor inclusion proof) for
  each. Signing is *keyless*: cosign exchanges the ambient GitHub
  OIDC token for a 10-minute Fulcio code-signing certificate
  whose SAN is bound to this workflow file at the published tag,
  signs, submits to Rekor, and writes the bundle. There are no
  long-lived signing keys for an attacker to steal.

  Verifiers paste the published `cosign verify-blob` command into
  their shell after downloading the binary plus its
  `.cosign.bundle` sidecar — the install page documents the full
  command including the mandatory `--certificate-identity-regexp`
  and `--certificate-oidc-issuer` flags. The identity regex
  accepts any tag from this repo by default; consumers wanting
  stricter pinning swap `v.*` for the exact tag.

* **SLSA v1.0 Build Level 3 provenance.** A new `provenance` job
  invokes the
  [`slsa-github-generator`](https://github.com/slsa-framework/slsa-github-generator)
  reusable workflow on a hardened GitHub-hosted builder. The
  generator emits a SLSA v1.0 provenance attestation
  (`installguard-<TAG>.intoto.jsonl`) covering every binary plus
  `checksums.txt`, signed via the same Fulcio/Rekor path, and
  uploads it to the same release. Consumers verify with
  [`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier)
  pinned to the source repo + tag — the install page documents
  the command.

* **What this *does not* change:** the `requireProvenance`
  policy gate still validates *npm and PyPI* publisher
  attestations structurally (in-toto subject digest match against
  the tarball's `dist.integrity`, or a 200 from PyPI's Integrity
  API); cryptographic verification of those bundles against a
  pinned Sigstore Fulcio root is a separate piece of work
  tracked under ROADMAP M9. See the 0.2.6 entry for the current
  honest scope of `requireProvenance`.

  The `cosign verify-blob` command above verifies *InstallGuard's
  own release artefacts* — i.e. the binary you downloaded was
  built by this repo's release workflow at the published tag —
  not the dependencies it scans.

## [0.2.9] — 2026-05-15

**Honesty pass on the README and the public docs site.** No
behaviour change; this release closes three documentation
overclaims that an external review surfaced.

* **README's quick-start no longer says "alpha 0.1.0" or implies
  binaries don't exist yet.** Updated to reflect the current
  `0.2.x` series, the SHA-256 checksums file we publish per
  release, and the v0.3 roadmap item for Cosign-signed binaries.
  Network-provider defaults (registry metadata, OSV, deps.dev,
  Scorecard, PyPI Integrity API are on by default; each has a
  `--no-…` flag; `--frozen` runs entirely from the lockfile) are
  spelled out so users can size the network blast radius before
  they invoke us.

* **Site landing page no longer claims InstallGuard "never opens
  an outbound socket".** The card describing zero side-effects
  was correct on `--frozen` and incorrect everywhere else
  (registry metadata, advisory lookups, project metadata, and
  Scorecard pulls all open sockets in the default scan path).
  Replaced with the truthful description plus an explicit
  pointer to the `--frozen` mode for true zero-network runs. The
  full lockfile coverage list (`uv.lock`, `poetry.lock`, pinned
  `requirements.txt`) was added at the same time so the card
  doesn't accidentally undercount our PyPI support.

* **Site install page no longer says "signed binaries".**
  Releases ship SHA-256 checksums and SLSA L3 attestations are
  produced for the SBOM and policy-evaluation predicates today,
  but the binaries themselves are not yet Cosign-signed and the
  `checksums.txt` file is not yet attested. The page now
  documents the present state plus the v0.3 roadmap item.
  `start/what.md` carries the same correction.

**Known pending (tracked, not blocking this release):** the
release workflow itself does not yet Cosign-sign the published
binaries or attest the checksums file. That work is captured in
the ROADMAP under the v0.3 milestone alongside Sigstore Fulcio
verification of npm/PyPI provenance bundles.

## [0.2.8] — 2026-05-15

**Yarn workspace member `package.json` files are now walked for
direct-dep detection.** The Yarn Berry adapter previously only
read the root `package.json` to populate the direct-dep set. In
a typical monorepo the root has only `devDependencies` (or is
entirely empty under `private: true` with everything declared in
`packages/*/package.json`); every member dep was therefore
demoted to "transitive" and any `directOnly` policy rule
silently no-op'd against them.

The adapter now reads the root `package.json`'s `workspaces`
field (both shapes — bare array `["packages/*", "apps/web"]` and
the Yarn-1 nohoist-compatibility object form
`{ "packages": [...] }`), expands each pattern under the
lockfile's parent directory, and unions the direct-dep specs
across the root and every member it finds. Two glob shapes are
supported, covering the overwhelming majority of real
workspaces:

* literal segments (`packages/web`) — read that one `package.json`
  directly,
* trailing single-star (`packages/*`) — list the parent dir and
  read each immediate-child `package.json`.

`**` and other exotic globs are deliberately not supported (they
are vanishingly rare in `workspaces` arrays). A member
`package.json` that fails to read or parse is silently skipped,
matching the rest of this adapter's "best-effort enrichment,
never load-bearing for correctness" stance.

`installguard-adapter-pnpm` and `installguard-adapter-npm` are
unaffected: pnpm's `pnpm-lock.yaml` records the workspace member
graph in its `importers` map (already handled), and npm's
`package-lock.json` v3 stores the workspace tree under
`packages` (also already handled). This release brings yarn to
parity.

## [0.2.7] — 2026-05-15

**purl is now ecosystem-aware, and the lock format records each
entry's ecosystem.** Two related correctness fixes that an external
review surfaced.

* **`purl_for` distinguishes PyPI from npm.** Until this release,
  every component in a CycloneDX SBOM and every product reference
  in a generated VEX document was emitted as `pkg:npm/<name>@…`,
  including PyPI deps. Downstream tooling (Dependency-Track,
  GUAC, OSV-Scanner ingestion of our SBOMs) couldn't tell a
  Python `requests` from an npm `requests` and would either
  match the wrong advisory set or skip the dep entirely.
  `purl_for` now produces `pkg:pypi/<name>@<version>` for any
  `Ecosystem::Pypi` dep, with the name normalised per [PEP 503]
  (lowercased; runs of `_`, `-`, and `.` collapsed to a single
  `-`) as the purl spec requires for the `pypi` type. `npm` /
  `pnpm` / `yarn` deps still emit `pkg:npm/…` (they share the npm
  registry, so the purl spec keeps the type the same). Smoke:
  `pyyaml@6.0.1` now appears in the SBOM as
  `pkg:pypi/pyyaml@6.0.1` instead of `pkg:npm/pyyaml@6.0.1`.

* **`installguard.lock` schema bumped to v2 with a per-entry
  `ecosystem` field.** The frozen-policy rebuild (`installguard
  scan --frozen` and friends) used to hardcode every reconstructed
  dependency to `Ecosystem::Npm`, so an offline run replayed PyPI
  decisions against the wrong policy family and could mis-attribute
  reasons in the audit log. Each `LockDecision` now carries an
  `ecosystem` field; frozen rebuilds use it directly. v1 locks
  (written by ≤0.2.6) still load — the field defaults to absent,
  which the rebuild treats as `Npm` (the only ecosystem v1 locks
  could have contained), then re-emits as v2 on the next
  `installguard lock`. Forward-incompatible schema versions still
  abort with exit 2.

[PEP 503]: https://peps.python.org/pep-0503/#normalized-names

## [0.2.6] — 2026-05-15

**Honesty pass on the provenance gate, fail-loud on catalogue
outages, and a freshness window on the trust-score `published_at`
penalty.** No new providers; this release closes three correctness
issues that an external review surfaced.

* **`requireProvenance` no longer overclaims.** The doc-comment
  said "verified npm provenance" but the gate has only ever
  checked that the bundle's in-toto subject digest matches the
  tarball's `dist.integrity` (and, since 0.2.4, that PyPI's
  Integrity API returned 200 for the file). Both are *claimed*
  attestations, not *cryptographically verified* ones — we never
  walk the DSSE signature against a pinned Sigstore Fulcio root,
  and we never verify the Rekor inclusion proof. The
  `requireProvenance` doc, the `Reason::ProvenanceMissing` doc,
  and the policy-gate comment all now say so explicitly. The
  schema regenerates with the corrected text. A
  `TODO(M9)` marks where the verified-peer signal will land
  alongside Sigstore Fulcio verification; when it does, this
  gate will require the verified signal and the present
  behaviour will move behind a separate, weaker
  `requireProvenanceClaim` toggle. **No behaviour change** —
  every gate that fired before still fires; we only owned what
  we ship.

* **deps.dev and Scorecard now distinguish "not indexed" from
  "outage".** Both providers used to collapse network failures,
  5xx responses, and decode errors to a silent `None`, then
  return an empty signal set. The policy layer's existing
  `signal-unavailable` reason therefore never fired and a clean
  scan could hide a deps.dev outage or a Scorecard interference.
  Both providers now return `Result<Option<T>, String>` from
  their fetch helpers: `Ok(Some(_))` is a hit, `Ok(None)` is a
  404/410 (legitimate absence — the package isn't indexed yet,
  cached as a soft miss), and `Err(reason)` covers every other
  failure mode (network, 5xx, decode, both not cached). The
  `signals()` impls lift the `Err` arm to a
  `Signal::Unavailable { provider, reason }`. Operators who want
  hard failure on catalogue outages can now use
  `severity: signal-unavailable: block`; the default stays at
  `warn` so transient 5xxs don't break CI.

* **The trust-score `published_at` penalty now respects a
  freshness window.** The matrix in the `trust_score` doc said
  the −10 was for "very recent publish", but the rule actually
  applied to every package — every dependency carries a
  `published_at`, so the steady-state trust score was silently
  capped at 90 and `minTrustScore: 90+` would block healthy
  packages for the wrong reason. The penalty now only applies
  when the publish time is within
  `trust_score::FRESHNESS_WINDOW_DAYS` (14 days, aligned with
  the docs' default `minimumReleaseAge` recommendation). Outside
  the window the contribution is zero and the signal is omitted
  from the breakdown — it still appears in the audit signal set
  for explainability. Future-dated publishes (clock skew or
  forged metadata) are also treated as outside the window
  rather than counting as "fresh". `TrustScore::compute` keeps
  its current signature for backwards compatibility; a new
  `TrustScore::compute_at(set, now)` is added for deterministic
  callers (the policy gate now uses it, threading the same
  `now` it uses for every other time-relative check).

  Smoke-validated: `pyyaml@6.0.1` (a 2023 release) now scores
  100/100 on a default policy instead of 90/100.

## [0.2.5] — 2026-05-15

**PyPI sdists are now scanned for install-time RCE patterns.**
A new provider crate (`installguard-signal-pypi-sdist`) closes
the last two cells in the PyPI coverage matrix that had a viable
path: `lifecycle_scripts` and `suspicious_script`.

For every resolved PyPI dependency the provider:

* downloads the canonical `.tar.gz` sdist from PyPI (subject to
  a 25 MiB hard cap; oversized releases are skipped with a
  `pypi-sdist unavailable` reason rather than scanned);
* HEAD-probes the file first so a pathological size never costs
  bandwidth;
* verifies the tarball's SHA-256 against the digest PyPI
  publishes for that file, when available — a mismatch logs a
  `tracing::warn` and emits no signal (registry-integrity is
  separately handled by lockfile-hash verification);
* extracts `setup.py` (1 MiB cap on the body, UTF-8 lossy
  fallback so a non-UTF-8 byte sequence still gets scanned)
  and emits `Signal::LifecycleScripts { scripts: ["setup.py"] }`
  whenever the file is present — `setup.py` runs during
  `pip install`, full stop;
* runs the body through both the existing shell-pattern
  detector (`curl … | sh`, `wget … | bash`, `/dev/tcp`,
  base64-decoded shell, …) and a new Python-aware ruleset
  covering `os.system`/`subprocess` calls that fetch over the
  network, `exec`/`eval` of `urlopen`/`requests.get`/
  `b64decode` payloads, the canonical `socket.socket(…) +
  os.dup2 / pty.spawn / sh -i` reverse-shell layout, and
  `__import__('os').system(…)` obfuscation. Each rule fires at
  most once per body and emits `Signal::SuspiciousScript`.

The provider fails soft on every kind of network or parse
error: anything other than "the file was scanned and we found
findings" produces zero signals (or a single
`Signal::Unavailable` when the failure is informative).
PEP 517-only sdists (no `setup.py`, just a `pyproject.toml`)
correctly produce no lifecycle signal — that is the safe shape
and we want users moving toward it.

A new `--no-pypi-sdist` flag matches the existing
`--no-pypi-registry` / `--no-osv` / `--no-deps-dev` /
`--no-scorecard` opt-out family for offline / air-gapped CI
runs or bandwidth-constrained environments.

Smoke-validated against `pyyaml@6.0.1` (classic `setup.py`
sdist): `lifecycle_scripts: ["setup.py"]` is emitted, the
default policy blocks the install, and `--no-pypi-sdist`
correctly suppresses the signal.

## [0.2.4] — 2026-05-15

**PEP 740 publisher attestations are now surfaced as
`provenance_claimed` on PyPI deps.** The pypi-registry provider
gains a second probe — after fetching `/pypi/<name>/<version>/json`
to derive `published_at` and yanked status, it also asks PyPI's
[Integrity API](https://docs.pypi.org/api/integrity/)
(`GET /integrity/<name>/<version>/<filename>/provenance`) about
the canonical sdist (or first wheel as fallback) for the release.
A `200` response means the file was uploaded with a Trusted
Publisher attestation that PyPI cryptographically verified at
upload time; we surface that as `Signal::ProvenanceClaimed` with
`bundle_url` set to the integrity URL itself, ready for callers
who want to re-fetch and verify.

* Same signal shape as npm provenance (`Signal::ProvenanceClaimed
  { bundle_url }`), so the `+10` trust-score boost applies
  identically across ecosystems and `policy.requireProvenance`
  now works for PyPI deps too.
* Probe is silent on absence: a clean `404` (the common case
  today — Trusted Publishers are still rolling out across the
  index) emits no signal. Network errors on the probe are
  swallowed so the metadata signals remain authoritative.
* `pick_attestation_filename` is a pure helper, unit-tested
  against `.tar.gz`, `.zip`-only sdists, and wheel-only
  releases. Sdists are preferred because publishers attest every
  artifact in a release with the same identity, so probing one
  file is enough to detect provenance for the version.
* Smoke-tested live: `sigstore@3.6.1` now surfaces
  `provenance_claimed` against
  `pypi.org/integrity/sigstore/3.6.1/sigstore-3.6.1.tar.gz/provenance`,
  lifting its trust score to 98/100.

This closes the `provenance_claimed` deferral on the PyPI side
of the ecosystems coverage matrix. `publisher_change` and
`maintainer_new_account` remain deferred — PyPI still does not
expose a stable per-version publisher identity outside of the
attestation envelope, and tracking *change* across versions
needs that to be queryable cheaply.

## [0.2.3] — 2026-05-15

**Poetry lockfiles are now first-class.** The PyPI adapter grows
a third format alongside `uv.lock` and hash-pinned
`requirements.txt`: `poetry.lock`, the TOML lockfile written by
[Poetry](https://python-poetry.org/).

* New `parse_poetry_lock` reader. Lock-version `1.x` and `2.x`
  are accepted; the per-package shape is stable across them.
  Future major versions are rejected with
  `AdapterError::UnsupportedVersion` so a schema change can't
  silently slip through.
* Direct vs transitive: poetry stores the project's direct
  dependency set in `pyproject.toml`, not the lockfile. The
  adapter peeks at the sibling `pyproject.toml` (when present)
  and reads three shapes:
  - `[tool.poetry.dependencies]` (poetry classic)
  - `[tool.poetry.group.<name>.dependencies]` (any group, dev included)
  - `[project.dependencies]` (PEP 621, used by poetry 2.x in modern mode)
  PEP 508 markers and extras (`requests[security]>=2; python_version>='3.8'`)
  are stripped to recover the bare distribution name. The `python`
  pin is excluded.
* When no sibling `pyproject.toml` exists every entry is
  conservatively flagged transitive — better than lying about
  provenance when we genuinely don't know.
* Source classification mirrors the other PyPI shapes:
  `[package.source]` with `type = "git"` → `Source::Git` (with
  `resolved_reference` preferred over `reference`),
  `type = "url"` → `Source::Tarball`, `type = "file"` /
  `"directory"` → `Source::File`, `"legacy"` and registry-default
  → `Source::Pypi`.
* Integrity preference: any non-`.whl` file (typically the
  sdist) over the first wheel hash, mirroring `uv.lock`.
* CLI auto-discovery extended: `installguard explain` /
  `evaluate` now finds `poetry.lock` in `--path` directories
  alongside the other supported lockfiles.

Smoke-tested against a real `requests@2.31.0` `poetry.lock` +
`pyproject.toml` pair — all six PyPI signals
(published_at, three OSV advisories, project_metadata,
scorecard_score) emit identically to the `uv.lock` path.

## [0.2.2] — 2026-05-15

**OpenSSF Scorecard now scores PyPI dependencies.** The Scorecard
provider previously skipped Python deps because it discovered the
upstream source-repo URL via the npm packument. This release
teaches it to read PyPI's `info.project_urls` map (with
`info.home_page` as a last-resort fallback) so any PyPI package
that points its `Source` / `Repository` / `Source Code` URL at a
GitHub repo gets a `scorecard_score` signal.

* Scorecard provider: ecosystem-aware repo lookup. npm-family
  deps still hit the npm packument; PyPI deps hit
  `https://pypi.org/pypi/<name>/<version>/json` and walk
  `project_urls` in preference order — `Source`, `Repository`,
  `Source Code`, `Code` (case- and separator-insensitive),
  then any value containing `github.com`, then `home_page`.
* `supports()` extended to `Ecosystem::Pypi`.
* New pure helper `pick_pypi_repo_url`, unit-tested against the
  inconsistent labelling PyPI maintainers use in the wild
  (`Source-Code`, `repository`, `Tracker → /issues`, etc).
* GitHub-hosting requirement is unchanged: non-github source URLs
  resolve to no signal (Scorecard's gitlab.com / bitbucket.org
  coverage is too sparse to be useful today).
* Smoke-tested live: `requests@2.31.0` now surfaces
  `scorecard_score: 8` against `github.com/psf/requests`.

Trust scoring on PyPI deps with linked GitHub repos now reflects
their Scorecard posture the same way npm-family deps do.

## [0.2.1] — 2026-05-15

**PyPI dependencies are now scored and gated.** The 0.2.0 adapter
made PyPI deps visible; this release wires three signal providers
to them so they actually participate in policy decisions.

* New crate `installguard-signal-pypi-registry` calling the PyPI
  JSON API (`https://pypi.org/pypi/<name>/<version>/json`) and
  emitting:
  * `published_at` — earliest `upload_time_iso_8601` across the
    sdist + wheel files for the resolved version. Drives
    `min-release-age` gating for PyPI deps.
  * `deprecated_version` — when `info.yanked == true`
    ([PEP 592](https://peps.python.org/pep-0592/)). The
    maintainer's `yanked_reason` becomes the deprecation message.
* OSV advisory provider now speaks PyPI: `Ecosystem::Pypi` maps
  to the OSV `"PyPI"` ecosystem label, so GHSA / PyPA advisories
  land on Python deps the same way they do on npm-family deps.
  This is the headline value of the slice — `cryptography@<X`,
  `requests@2.31.0`, `urllib3@<1.26.18` etc. now block / warn
  per the same severity policy as their npm equivalents.
* deps.dev provider: system selector parameterised; PyPI version
  records now fetch from `/v3alpha/systems/pypi/...` and the
  in-process cache is keyed by `(system, name@version)` so npm
  and PyPI never alias.
* New CLI flag `--no-pypi-registry` for fully offline / air-gapped
  CI runs (mirrors `--no-osv` / `--no-deps-dev` / `--no-scorecard`).

Out of scope for this slice (deferred):

* Maintainer / publisher signals — PyPI's JSON API does not
  expose per-version publisher identity, so `PublisherChange`
  and `MaintainerNewAccount` are not derivable from this
  endpoint.
* OpenSSF Scorecard for PyPI deps — needs `info.project_urls`
  plumbed into the Scorecard provider; tracked as a follow-up.
* `setup.py` static analysis for sdists — requires download +
  extract, a different provider shape; tracked separately.

## [0.2.0] — 2026-05-15

**First non-npm ecosystem.** PyPI lockfiles now parse, evaluate, and
report alongside npm / pnpm / yarn projects. The signal providers
will follow in 0.2.x; this release ships the adapter so users can
immediately see PyPI dependencies in `scan` / `ci` / `lock` /
`sbom` / `vex` output, and so policy authors can start writing
forward-compatible `pypi:`-prefixed allowlists today.

* New crate `installguard-adapter-pypi` recognising two formats:
  * **`uv.lock`** — TOML schema version 1, the canonical lockfile
    for [uv](https://docs.astral.sh/uv/). Pulls per-package
    sdist/wheel URLs and `sha256` hashes; root virtual package is
    suppressed; transitive vs direct is computed from the root's
    `dependencies` list.
  * **`requirements.txt`** — only when generated with hashes
    (`uv pip compile --generate-hashes` or
    `pip-compile --generate-hashes`). Hash-less files are rejected
    with a clear actionable error: a wishlist is not a lockfile,
    and shipping a lockfile-shaped adapter against one would
    silently lower the bar.
* PEP 503 name normalisation throughout (`Re_quests` →
  `requests`); ecosystem matchers and cache keys all see the
  normalised form.
* `pip-compile`'s `# via -r requirements.in` annotation classifies
  direct deps; everything else is transitive.
* `locate_lockfile` priority order is now `pnpm-lock.yaml` →
  `yarn.lock` → `package-lock.json` → `uv.lock` →
  `requirements.txt`. npm-family lockfiles still win when both are
  present (a polyglot repo running InstallGuard from the JS root
  keeps its existing behaviour).
* PyPI deps with no signal provider currently resolve to `allow`
  with empty signals — visible in `scan` output and `sbom`
  components, but not gated until 0.2.x ships the PyPI providers.

This is the first release on the `0.2.x` line. Existing 0.1.x
policies, locks, and audit logs are forward-compatible without
changes.

## [0.1.19] — 2026-05-15

Documentation catch-up release. No binary changes.

The Usage section of <https://installguard.dev> grew from 9 to 18
pages, covering every subcommand that ships in the binary.
Previously undocumented and now landed:

* `cache` — inspect & manage the on-disk signal cache (new in 0.1.17).
* `schema` — print the policy JSON Schema for editor integration.
* `lock` — deterministic policy-evaluation snapshot.
* `verify` — re-evaluate and check against a lock or signed bundle
  (online, frozen, or signature-verifying modes).
* `attest` — unsigned in-toto v1 statement wrapping the verdict.
* `sbom` — CycloneDX 1.5 SBOM with `installguard:*` decision
  properties per component.
* `vex` — OpenVEX 0.2.0 mapping decisions to VEX statements.
* `key` — generate Sigstore-compatible Ed25519 keypairs.
* `sign` — DSSE v1 envelope cosign can verify.

The attestation chain (`lock` → `attest` → `sign` →
`verify --bundle`) is cross-linked end-to-end so the SLSA L3 /
cosign story is finally walkable from the docs alone.

## [0.1.18] — 2026-05-15

Documentation & examples release. No binary changes; same gate, more
places to plug it in.

* New recipe **Dependency bots (Dependabot & Renovate)** at
  <https://installguard.dev/recipes/dependency-bots/>: how to scope
  an InstallGuard workflow to bot-authored bump PRs, gate Dependabot
  automerge on a clean verdict, and configure Renovate to defer
  automerge to required status checks.
* New drop-in workflow `examples/workflows/installguard-bot-prs.yml`
  with a scoped scan job + an optional automerge job for clean
  patch/minor Dependabot bumps. Includes the security rationale for
  keeping the gate in a target-branch workflow file so bots can't
  silently weaken it via a PR-branch edit.

## [0.1.17] — 2026-05-15

Cache invalidation, finally automatic. The on-disk signal cache
(`~/Library/Caches/installguard` on macOS, `~/.cache/installguard`
on Linux, `%LOCALAPPDATA%\installguard\Cache` on Windows) now
stamps every entry with the producing tool's `CARGO_PKG_VERSION`
on write. On read, any entry whose stored `tool_version` differs
from the running build is treated as stale and dropped — exactly
as a `SCHEMA_VERSION` mismatch already was. Closes the historical
foot-gun where signal-shape changes shipped between schema bumps
left users hand-running `rm -rf ~/Library/Caches/installguard`
after every release.

Legacy entries written by 0.1.16 and earlier (which had no
`tool_version` field) deserialise with the default empty string
and are dropped on first read under 0.1.17 — guaranteeing a clean
slate on the upgrade.

New `installguard cache` subcommand for inspecting and managing
the cache without reaching for `rm`:

* `installguard cache path` — prints the resolved cache directory
  and exits.
* `installguard cache info` — per-status breakdown (fresh / stale
  by version / stale by schema / unreadable) plus the running
  tool version.
* `installguard cache clear` — drops every entry; the next `scan`
  re-fetches signals from the network. Both subcommands honour
  `--cache-dir` for parity with `scan`.

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
