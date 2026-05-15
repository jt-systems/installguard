# InstallGuard

> **Dependency freshness & install-script governance for modern package ecosystems.**
> Reduce exposure to short-lived malicious releases without disrupting developer workflow.

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-alpha-yellow.svg)](ROADMAP.md)
[![Whitepaper](https://img.shields.io/badge/docs-whitepaper-informational.svg)](whitepaper.md)
[![Website](https://img.shields.io/badge/web-installguard.dev-blue.svg)](https://installguard.dev)

---

## Why

Modern supply-chain attacks against npm, PyPI and friends increasingly rely on the gap between **publication** and **detection**: a maintainer is compromised, a poisoned patch ships, CI installs it within minutes, secrets exfiltrate, and the version is withdrawn before traditional scanners notice.

CVE databases and malware signatures are necessary but reactive. They detect *known* compromise — they don't reduce exposure to *emerging* compromise.

InstallGuard takes a different angle:

- **Wait** before adopting brand-new package versions.
- **Approve** which packages may run install-time scripts.
- **Block** dependencies from exotic sources (Git URLs, tarballs, GitHub shortcuts).
- **See** dependency risk at PR time, not after a breach.
- **Prove** which policy a build was governed by, via signed attestation.

> Sometimes the best supply-chain defence is simply **waiting 24 hours** before installing something.

Read the full argument in the [whitepaper](whitepaper.md).

---

## What it does

Status legend: ☑ shipped · ◐ partial · ☐ planned

| Capability | Status |
| ---------- | :----: |
| Lockfile adapters: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `uv.lock`, `poetry.lock`, hashed `requirements.txt` | ☑ |
| Minimum release-age enforcement (per environment, with direct-dep overrides) | ☑ |
| Lifecycle script approval lists (`preinstall` / `install` / `postinstall`) | ☑ |
| Exotic-source blocking (Git, tarball, GitHub shortcut) | ☑ |
| Multi-signal detection: publisher change, deprecation, dist-tag churn, file-set diff, account age, typosquat / homoglyph, suspicious-script static analysis | ☑ |
| Trust-score computation with per-signal contribution breakdown | ☑ |
| External signal providers: OSV/GHSA advisories, deps.dev project metadata, OpenSSF Scorecard | ☑ |
| Public `SignalProvider` trait for third-party providers (see [`crates/core/examples/minimal_provider.rs`](crates/core/examples/minimal_provider.rs)) | ☑ |
| PR annotations (GitHub Action, GitLab MR widget) + per-PR risk summary | ☑ |
| Deterministic `installguard.lock` + in-toto attestation (`policy-evaluation/v1`) | ☑ |
| CycloneDX SBOM export with policy-decision properties + per-package VEX | ☑ |
| `--frozen` offline re-verification against a recorded snapshot | ☑ |
| PyPI install-time scanning (`setup.py` in canonical `.tar.gz` sdists) | ◐ |
| Maintainer 2FA status check | ◐ deferred (registry doesn't expose it unauthenticated) |
| Sigstore signing (cosign keyless / KMS) for attestations | ◐ structural provenance match shipped; full Fulcio/Rekor verification deferred |
| Sandboxed install-script execution | ☐ planned (M5) |
| Registry-proxy enforcement (Verdaccio / Artifactory / Nexus) | ☐ planned (M6) |
| Additional ecosystems beyond PyPI (crates.io, Go, RubyGems, …) | ☐ planned (M8+) |

See the [roadmap](ROADMAP.md) for milestones and the [design document](DESIGN.md) for the technical scope.

---

## How it fits in

InstallGuard is **complementary**, not a replacement, for:

- `npm audit`, Snyk, osv-scanner — keep them; they catch *known* vulnerabilities.
- Dependabot / Renovate — keep them; InstallGuard makes their PRs safer to merge.
- pnpm built-ins (`minimumReleaseAge`, `onlyBuiltDependencies`) — InstallGuard *operationalises* these across an organisation: central policy, audit, attestation, and cross-ecosystem evidence.

Comparison table in [whitepaper §17](whitepaper.md#17-comparison-with-existing-tools).

---

## Quick start

> **Alpha — `0.3.x`.** Pre-built binaries are published per
> tagged release, signed by [Sigstore cosign keyless](https://docs.sigstore.dev/cosign/signing/overview/)
> and shipped with [SLSA v1.0 Build Level 3 provenance](https://slsa.dev/spec/v1.0/levels#build-l3).
> Network providers (registry metadata, OSV, deps.dev, Scorecard,
> PyPI Integrity API) are on by default and individually opt-out;
> `--frozen` runs entirely from `installguard.lock` with zero
> sockets.

```bash
# Homebrew (macOS, Linux)
brew install jt-systems/installguard/installguard

# Or build from source (Rust 1.86+):
cargo install --path crates/cli

# Scan the current project (auto-detects npm / pnpm / yarn / uv / poetry / hashed requirements)
installguard scan

# Triage findings and print a paste-ready installguard.yaml block
installguard doctor

# In CI: hard-fail on policy violations
installguard ci --summary-file installguard-summary.json

# Emit an unsigned in-toto attestation of the evaluation
installguard attest --out installguard.intoto.json

# Air-gapped CI: re-verify offline against a recorded snapshot
installguard ci --frozen
```

External signal providers (OSV, deps.dev, OpenSSF Scorecard) are on by default and individually opt-out for offline runs:

```bash
installguard scan --no-osv --no-deps-dev --no-scorecard
```

Example policy (`installguard.yaml`):

```yaml
policyVersion: 1

defaults:
  minimumReleaseAge: 1440        # minutes (24h)
  blockExoticSubdeps: true
  detectPublisherChange: true
  flagDeprecated: true
  detectVersionSurfaceChange: true
  minMaintainerAccountAgeDays: 30
  requireProvenance: false        # opt-in once your supply chain emits it
  maxAdvisorySeverity: high       # OSV / GHSA gate
  requireLicense: true            # deps.dev gate
  licenseAllowlist: [MIT, Apache-2.0, BSD-3-Clause, ISC]
  blockArchived: true
  minScorecardScore: 5            # OpenSSF Scorecard 0-10
  minTrustScore: 60

scripts:
  policy: deny-by-default
  allow: [esbuild, sharp, playwright]

direct:
  minimumReleaseAge: 4320         # stricter for direct deps
  detectPublisherChange: true
```

Full DSL in [DESIGN.md §4](DESIGN.md#4-policy-dsl). More examples live in `examples/policies/`.

---

## Safe install workflow

InstallGuard separates dependency acquisition from script execution:

```bash
# npm
npm ci --ignore-scripts && installguard scan && npm rebuild

# pnpm
pnpm install --ignore-scripts && installguard scan && pnpm rebuild

# yarn (Berry)
yarn install --mode=skip-build && installguard scan && yarn rebuild
```

If anything fails policy, scripts never run.

---

## Project status

InstallGuard is in **alpha**. Milestones 0–4 are shipped, plus the first "Beyond npm" slice: PyPI support for `uv.lock`, `poetry.lock`, hashed `requirements.txt`, PyPI registry signals, Scorecard wiring, PEP 740 claimed provenance, and `setup.py`-based sdist scanning. The next focus areas are sandboxed script execution (M5) and registry-proxy enforcement (M6) — see [ROADMAP.md](ROADMAP.md).

If you're interested in early adoption, threat-model review, real-world lockfiles for adapter testing, or contributing rule ideas, please open an issue.

---

## Documentation

- [Whitepaper](whitepaper.md) — the conceptual model, threat model, and standards mapping.
- [DESIGN.md](DESIGN.md) — the technical design (architecture, policy DSL, attestation format, performance targets).
- [ROADMAP.md](ROADMAP.md) — prioritised milestones from foundations through compliance reporting.

---

## Principles

1. **Preventative over reactive.** Reduce exposure; don't only chase known IOCs.
2. **Deterministic and auditable.** Every decision is recorded, hashable, and signable.
3. **Offline-capable.** No telemetry or hidden phone-home path. Air-gapped deployments are first-class.
4. **Boring distribution.** Single static binary. No `node_modules`. No install scripts of our own.
5. **Operationalise existing controls.** Don't reinvent pnpm, Sigstore, or OSV — orchestrate them.
6. **Honest about limits.** See [whitepaper §20](whitepaper.md#20-limitations--trade-offs).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

- Issues and discussion are welcome.
- Sanitised real-world lockfiles for adapter golden tests are particularly useful.
- Third-party signal providers: implement the [`SignalProvider`](crates/core/src/signal.rs) trait — see [`crates/core/examples/minimal_provider.rs`](crates/core/examples/minimal_provider.rs) for a ~30-line worked example.
- Security-relevant reports: please follow [SECURITY.md](SECURITY.md) rather than opening a public issue.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE). The Apache-2.0 licence was chosen specifically for its explicit patent grant — important for a security tool intended for enterprise adoption.
