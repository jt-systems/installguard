# InstallGuard — Roadmap

> Companion to [whitepaper.md](whitepaper.md) and [DESIGN.md](DESIGN.md). Priorities reflect maximum risk reduction per unit of effort, not chronological dates.

Status legend: ☐ planned · ◐ in progress · ☑ shipped

---

## Milestone 0 — Foundations

The smallest useful tool: read a lockfile, evaluate freshness, print a verdict.

- ◐ Rust workspace skeleton, CI, release pipeline with SLSA provenance _(skeleton + CI + release workflow shipped; SLSA generator step prepared but commented out pending first tagged release)_
- ☑ `pnpm-lock.yaml` adapter (most policy-aligned ecosystem first)
- ☑ `package-lock.json` adapter
- ☑ npm registry signal provider (publish time, scripts, integrity, maintainers)
- ☑ Persistent on-disk cache (`sled`)
- ☑ Built-in policy DSL (subset: `minimumReleaseAge`, `allowBuildScripts`, `blockExoticSubdeps`)
- ☑ `installguard scan` CLI, human and JSON output
- ☑ Non-zero exit on `block` decisions
- ☑ Unit + golden-file tests for adapters

**Exit criteria:** a developer can run `installguard scan` against a real repo and get accurate, fast freshness/script verdicts offline (after warm cache).

---

## Milestone 1 — CI & Visibility

Make the tool useful in pipelines and PRs without yet enforcing org-wide.

- ☑ `installguard ci` mode (JSON summary, GitHub Actions annotations, `--max-warn`, `--summary-file`)
- ☑ GitHub Action with PR annotations
- ☑ GitLab CI template with MR widget
- ☑ Risk summary comment per PR (per-package one-liners, totals, links)
- ☑ `--ignore-scripts` aware: separate `scan` from rebuild guidance
- ☑ Pre-commit hook
- ☑ `yarn.lock` (Berry) adapter
- ☑ Configurable severity thresholds (`warn-on`, `block-on`)
- ☑ JSON Schema for the policy file; editor completions

**Exit criteria:** a team can adopt InstallGuard in warn-only mode across all PRs in under a day.

---

## Milestone 2 — Determinism & Attestation

Make decisions reproducible and provable.

- ☑ `installguard.lock` writer/reader with stable, deterministic JSON
- ☑ `--frozen-policy` mode (re-verify offline against a recorded snapshot)
- ☑ in-toto v1 attestation predicate `policy-evaluation/v1`
- ☐ Sigstore signing (cosign keyless and KMS)
- ◐ `installguard verify` against a signed attestation _(unsigned-lock verify shipped; signed-attestation path depends on Sigstore wiring)_
- ☑ CycloneDX SBOM export with policy-decision properties
- ☑ VEX statement export per package decision
- ☑ Audit log sink (JSONL) with stable schema

**Exit criteria:** a downstream consumer can verify "this build was governed by policy X with these decisions" without contacting any registry.

---

## Milestone 3 — Stronger Detection

Move beyond age into the multi-signal model from the whitepaper §7.

- ☑ Publisher-change detection (`vN` vs `vN-1` maintainers)
- ☑ Deprecated-version detection (registry-side post-publish trust signal; pairs with publisher-change)
- ☐ Maintainer 2FA status check
- ☐ Maintainer account-age check
- ☐ Dist-tag churn detection
- ☐ File-set diff between versions (new `bin`, `.node`, `.wasm`, postinstall)
- ☑ Static analysis of install scripts (high-risk patterns: `curl|sh`, base64 `eval`, env-var exfil to non-registry hosts)
- ☐ Typosquat / homoglyph proximity check at PR time (direct deps only)
- ☐ Provenance attestation lookup via Rekor and verification
- ☐ Trust-score computation with documented weights and explanation output

**Exit criteria:** policies can express and enforce "block on publisher change for direct deps" and "warn on new postinstall" without scripting.

---

## Milestone 4 — External Signal Providers

Plug into the wider ecosystem.

- ☐ OSV / GHSA provider (consume, do not produce, advisory data)
- ☐ deps.dev provider
- ☐ OpenSSF Scorecard provider
- ☐ Optional Socket / Snyk Advisor providers (gated by API key)
- ☐ Public plugin trait for third-party signal providers
- ☐ Plugin discovery and signature verification

**Exit criteria:** a team can add an internal threat-intel provider in a single crate without forking InstallGuard.

---

## Milestone 5 — Install-Time Hardening

Close the install-time execution attack surface where the OS allows.

- ☐ `installguard-sandbox` binary (Linux: `bubblewrap`)
- ☐ macOS `sandbox-exec` backend
- ☐ Container-per-script backend (CI default)
- ☐ Egress allowlisting during install (registry-only proxy)
- ☐ `--scrub-env` wrapper around `npm` / `pnpm` / `yarn`
- ☐ Per-script CPU and wall-clock limits
- ☐ Decision sink event for every script execution (success/fail/violation)

**Exit criteria:** approved install scripts can run without network, with scrubbed env, and any deviation is logged and blockable.

---

## Milestone 6 — Registry Proxy Plugin

Make policy unbypassable at the network layer.

- ☐ Verdaccio plugin
- ☐ Artifactory plugin
- ☐ Nexus plugin
- ☐ Reuse core engine and cache
- ☐ Structured rejection responses (HTTP 403/451 + JSON body)
- ☐ Operator metrics (Prometheus)
- ☐ Documentation for HA / clustered deployments

**Exit criteria:** an org can centrally enforce policy for all consumers of the proxy, regardless of whether they run InstallGuard locally.

---

## Milestone 7 — Control Plane (Optional)

For organisations that want central management.

- ☐ Self-hostable control plane (Rust + Postgres)
- ☐ Policy distribution to CLIs and proxies
- ☐ Centralised waiver and allowlist management with workflow approvals
- ☐ Dashboards: dependency posture, policy drift, waiver expiry
- ☐ Fleet-wide metadata cache server
- ☐ SSO / OIDC, RBAC, audit log
- ☐ Webhooks (Slack, Teams, generic)

**Exit criteria:** a security team can manage policy and waivers for hundreds of repos from one place, with audit and approvals.

---

## Milestone 8 — Beyond npm

Apply the model to other ecosystems.

- ☐ PyPI adapter + signal provider (`requirements.txt`, `poetry.lock`, `uv.lock`)
- ☐ crates.io adapter
- ☐ Go modules adapter (`go.sum`)
- ☐ RubyGems adapter (`Gemfile.lock`)
- ☐ Maven Central adapter (`pom.xml`, `gradle.lockfile`)
- ☐ NuGet adapter
- ☐ Hex adapter

Each adds: lockfile adapter, registry signal provider, ecosystem-tuned defaults, integration tests.

---

## Milestone 9 — Developer Experience

Polish that drives adoption.

- ☐ VS Code extension: hover risk on `package.json`, code-lens for upgrades blocked by policy
- ☐ JetBrains plugin
- ☐ `installguard explain <package>@<version>` — full signal report and policy trace
- ☐ `installguard simulate --policy new.yaml` — preview a policy change against current repo
- ☐ Renovate / Dependabot integration: emit policy-aware update preferences (`installguard.policy.json`) so bots skip updates that would violate policy
- ☐ Web-based decision viewer (static HTML report)

---

## Milestone 10 — Compliance & Reporting

For security/compliance buyers.

- ☐ Standards-mapping report (SLSA, SSDF, CRA) generated from a scan
- ☐ Trend reporting over time (requires control plane)
- ☐ Exportable evidence packs (SBOM + VEX + attestation + audit log)
- ☐ Air-gapped metadata-snapshot tooling
- ☐ FIPS-mode crypto build

---

## Cross-Cutting Concerns (continuous)

- Performance budgets enforced in CI (see DESIGN.md §11).
- Fuzzing of all parsers (lockfile, registry response, policy DSL).
- Threat-model document maintained alongside features.
- Documentation: every policy key has an example and a rationale.
- Backwards compatibility: policy schema versioned; breaking changes only at major releases.
- Reproducible release builds verified on every tag.

---

## Explicit Non-Roadmap (for now)

To preserve focus, these are deliberately deferred:

- Building our own CVE database.
- Runtime application protection (RASP).
- Auto-PR remediation (creating dependency-update PRs).
- Hosted SaaS control plane (self-hosted only initially).
- IDE-based binary execution / dynamic analysis.
- Browser-extension consumer-side checks.

These may return after Milestone 7 if there is clear demand.

---

## Asks for the Community

- Real-world lockfiles (sanitised) for adapter golden tests.
- Reports of false positives and false negatives from early adopters.
- Policy templates from regulated industries (finance, health, public sector).
- Translation of detection signals to non-npm ecosystems.
