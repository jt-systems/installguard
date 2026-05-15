# InstallGuard

## Dependency Freshness & Install Script Governance
### A Practical Approach to Modern JavaScript Supply Chain Risk

---

## Executive Summary

Recent npm supply-chain attacks have highlighted a recurring pattern:

- compromised maintainer accounts
- malicious patch releases
- short-lived poisoned package versions
- abuse of `preinstall` / `install` / `postinstall` lifecycle scripts
- rapid propagation through CI/CD systems
- self-replicating worms (e.g. Shai-Hulud, 2024–2025) that weaponise developer credentials to republish trojanised versions of victim-owned packages

Traditional dependency security tooling focuses heavily on:

- known CVEs
- malware signatures
- static vulnerability databases

However, modern attacks increasingly exploit the window between publication and detection.

This paper proposes a complementary defensive model:

> **Dependency Freshness Governance**

Rather than attempting to perfectly identify malware, organisations reduce exposure by controlling:

- how quickly newly published packages can enter production
- which packages may execute install-time code
- where dependencies may resolve from
- how dependency risk is surfaced during code review
- how install-time execution is governed across CI and developer environments

The approach is intentionally pragmatic:

- low friction
- explainable
- CI-friendly
- compatible with existing npm / pnpm / yarn workflows
- suitable for gradual enterprise adoption

This paper covers the model, an explicit threat model, the proposed architecture and deployment topologies, the limitations and trade-offs, and how InstallGuard maps onto existing standards (SLSA, SSDF, CRA, OpenSSF Scorecard).

---

## 1. The Modern npm Threat Landscape

The JavaScript ecosystem is uniquely exposed to supply-chain attacks due to:

- extremely high transitive dependency counts
- automatic install-time execution
- rapid publishing velocity
- implicit trust in maintainers
- widespread CI automation
- automated dependency update tooling (Dependabot, Renovate, etc.)

Recent attack campaigns have demonstrated:

- malicious versions published briefly then unpublished or patched over
- credential theft via lifecycle scripts
- CI token and cloud credential exfiltration
- poisoned transitive dependencies
- rapid maintainer-compromise propagation
- dependency confusion against private scopes
- self-propagating worms that republish trojanised versions of packages owned by each victim
- dist-tag manipulation (e.g. flipping `latest` back-and-forth to evade detection)

The challenge is not simply "bad packages".

The challenge is:

> trusted ecosystems moving faster than humans can safely review.

---

## 2. Threat Model

InstallGuard is designed against a specific class of adversaries and attacks. Being explicit about scope is essential — both to set expectations and to make clear which **other** controls remain necessary.

### 2.1 In scope

- **Short-lived malicious releases.** A trojanised version published, exploited, then withdrawn within hours.
- **Compromised maintainer credentials** that publish a patch release laced with install-time code.
- **Dependency-confusion / typosquat introductions** at PR time.
- **Abuse of lifecycle scripts** (`preinstall`, `install`, `postinstall`) for credential theft, lateral movement, or persistence.
- **Exotic source injection** (Git URLs, tarballs, GitHub shortcuts) bypassing registry controls.
- **Self-propagating worms** that rely on rapid, automated installation across many victims.
- **Automated dependency-bot poisoning** where a Dependabot/Renovate PR merges a poisoned version before humans review.

### 2.2 Out of scope (acknowledged limitations)

InstallGuard does **not** defend against, and is not a substitute for, controls addressing:

- **Long-dormant backdoors** planted months or years before activation (xz-utils style).
- **Runtime supply-chain attacks** where benign-looking code activates only at application runtime.
- **Compromise of build tools and their plugins** (bundler plugins, transpilers, linters) executed during build rather than install.
- **Compromised registry mirrors** serving altered metadata or tarballs.
- **Plausible-name typosquats** that pass age and script checks.
- **Insider risk** at maintainer or registry-operator level.
- **Malicious transitive dependencies introduced by an allowlisted package** at a later date.

These require complementary controls: runtime sandboxing, EDR on build agents, registry integrity verification, code review, and CVE/malware scanning.

### 2.3 Assumptions

- The package registry returns truthful publication metadata (publish timestamp, maintainers, integrity hashes).
- Lockfiles are committed and respected (`npm ci`, `pnpm install --frozen-lockfile`).
- CI runners have outbound network restrictions broadly aligned with the policy (so policy bypass via direct registry calls is at least detectable).

---

## 3. Definitions

To avoid ambiguity, the following terms are used precisely throughout this document.

| Term | Definition |
| ---- | ---------- |
| **Release age** | Time elapsed since the version's `time[<version>]` entry in registry metadata, evaluated at policy-evaluation time. |
| **Dist-tag age** | Time elapsed since the relevant dist-tag (e.g. `latest`) was last reassigned. |
| **Direct dependency** | A package listed in the project's `package.json` `dependencies`, `devDependencies`, `optionalDependencies`, or `peerDependencies`. |
| **Transitive dependency** | Any package present in the lockfile that is not a direct dependency. |
| **Lifecycle script** | Any of `preinstall`, `install`, `postinstall` declared in the package's `scripts` block, plus equivalents enabled by package-manager hooks. |
| **Exotic source** | A dependency resolving from anything other than a registry on the configured allowlist — including Git URLs, tarball URLs, local file paths, and GitHub shortcuts. |
| **Quarantine** | A policy state in which a package version is known but blocked from installation pending age, signal, or human approval. |
| **Allowlist** | A named set of packages (optionally pinned to versions) that bypass selected policy checks, with attribution and optional expiry. |
| **Waiver** | A time-bounded, attributed override of a specific policy decision for a specific package version. |

---

## 4. Why Traditional Vulnerability Scanning Is Insufficient

Conventional scanners are reactive. They depend on:

- CVE publication
- advisory database updates
- malware signature recognition
- external reporting
- ecosystem detection latency

This creates a dangerous gap:

| Timeline   | Reality                            |
| ---------- | ---------------------------------- |
| T+0        | Malicious package published        |
| T+5 mins   | CI installs package                |
| T+15 mins  | Secrets exfiltrated                |
| T+6 hrs    | Community notices anomalies        |
| T+24 hrs   | Advisory published                 |
| T+48 hrs   | Scanner detects issue              |

By the time detection occurs:

- pipelines may already be compromised
- secrets may already be leaked
- artefacts may already be deployed
- build environments may already be persistent attack footholds

Traditional scanners remain valuable. However:

> they are primarily designed to identify known compromise, not reduce exposure to emerging compromise.

---

## 5. The Freshness Governance Model

Freshness governance accepts a key reality:

> Most legitimate package updates do not require immediate adoption.

Therefore:

- delaying adoption of newly published versions
- especially those with install-time execution
- dramatically reduces exposure to short-lived malicious releases

The objective is not perfect detection. The objective is:

- reducing blast radius
- increasing review opportunity
- slowing automated compromise
- improving dependency visibility
- creating operational friction for attackers

This model shifts dependency security from:

| Traditional Model | Governance Model         |
| ----------------- | ------------------------ |
| Detect malware    | Reduce exposure          |
| Reactive scanning | Preventative controls    |
| Signature-based   | Behaviour / policy-based |
| Trust by default  | Trust maturation         |

Freshness alone is necessary but not sufficient. Section 7 describes the additional signals InstallGuard combines with age to make decisions.

---

## 6. Core Security Principles

### 6.1 Minimum Release Age

Block installation of versions whose `time[<version>]` is younger than a configurable threshold.

```yaml
minimumReleaseAge: 1440   # minutes (24 hours)
```

Recommended defaults:

| Environment                | Recommended Delay |
| -------------------------- | ----------------- |
| Local development          | 24 hours          |
| CI staging                 | 48 hours          |
| Production pipelines       | 72 hours          |
| High-security environments | 7 days            |

#### Emergency override

Critical security patches must be able to bypass age controls. InstallGuard supports a **fast-track waiver**:

```yaml
waivers:
  - package: axios
    version: 1.7.9
    reason: "CVE-2026-1234 RCE fix"
    approvedBy: "@alice"
    expires: 2026-06-01
```

All overrides are recorded in the audit log and embedded in the build attestation.

### 6.2 Lifecycle Script Governance

Install-time execution is one of the highest-risk surfaces in the JavaScript ecosystem. Packages declaring `preinstall` / `install` / `postinstall` must be explicitly approved:

```yaml
allowBuildScripts:
  - esbuild
  - sharp
  - playwright
```

All other install-time execution becomes opt-in. This creates clear trust boundaries, auditable script execution, and explicit governance over what may run during dependency installation.

Where supported, install scripts run in a **sandbox** (see §10.3): no network, restricted filesystem, scrubbed environment.

### 6.3 Exotic Dependency Restrictions

Dependencies resolving from sources outside the configured registry allowlist — Git URLs, arbitrary tarballs, local paths, GitHub shortcuts — bypass many ecosystem protections (provenance, registry signing, standard publication metadata).

```yaml
registryAllowlist:
  - https://registry.npmjs.org/
  - https://npm.internal.example.com/
blockExoticSubdeps: true
```

### 6.4 Dependency Introduction Visibility

New dependency introduction should be treated similarly to infrastructure change. Every PR introducing packages should surface:

- package age and dist-tag age
- lifecycle scripts
- maintainer set, account ages, 2FA status, and any change vs the previous version
- dependency source type
- transitive expansion impact (count, depth, new exotic sources)
- provenance availability and verification status
- file-set diff highlights (new `bin`, native binaries, `.node` / `.wasm`, postinstall additions)

Security posture improves dramatically when risk becomes visible during review.

### 6.5 Trust Maturity

Dependency trust matures over time and across signals. InstallGuard computes a per-version **trust score** combining:

- release age
- dist-tag age
- maintainer-set stability vs prior versions
- maintainer account age and 2FA enforcement
- presence of provenance attestations (claimed today; cryptographic verification against a pinned Sigstore Fulcio root tracked under ROADMAP M9)
- historical release cadence (regular vs anomalous)
- file-set delta (new scripts, new binaries, new network-capable code)
- OpenSSF Scorecard signals (where available)
- deprecation / unpublish history

A package published five minutes ago by a recently rotated maintainer with new install scripts does not carry the same trust as a version with years of stable maintenance, consistent cadence, and a publisher provenance claim.

> Trust matures; it is not an instant property of a version number.

### 6.6 Direct vs Transitive Policy

Policies apply differently to direct and transitive dependencies, because what is reasonable for one is operationally infeasible for the other.

| Dimension              | Direct deps                        | Transitive deps                          |
| ---------------------- | ---------------------------------- | ---------------------------------------- |
| Allowlists             | Required for high-security mode    | Impractical at scale                     |
| Lifecycle scripts      | Explicit per-package approval      | Approval inherited via direct dep        |
| Release age            | Strictest threshold                | Same threshold; waivers more common      |
| Provenance             | Required (high-security)           | Recorded; missing tolerated initially    |
| New introduction gate  | PR review + risk annotation        | Surface in PR, not gated individually    |

---

## 7. Detection Signals

In addition to release age, InstallGuard combines the following signals into its policy decisions. Each signal can be configured to **inform**, **warn**, or **block**.

### 7.1 Publisher / maintainer signals

- Publisher of `vN` differs from `vN-1` (highest-value signal in modern attacks).
- Maintainer added or removed within the last 30 days.
- Maintainer account age below threshold.
- Maintainer without 2FA enforcement.

### 7.2 Content signals

- File-set diff vs previous version: new `bin` entries, new `.node` / `.wasm`, new postinstall.
- Static analysis of install scripts for high-risk patterns (`curl | sh`, base64-decoded `eval`, dynamic `require`, env-var exfiltration to known sinks).
- Sudden growth in package size or number of files.

### 7.3 Distribution signals

- Dist-tag churn (e.g. `latest` reassigned multiple times in 24h).
- Unpublish history for the package or maintainer.
- Provenance attestation present and verifiable via Sigstore / Rekor.

### 7.4 Naming signals

- Levenshtein / homoglyph proximity to popular packages (typosquat detection) at PR time.
- New scope mismatched against organisational scope allowlist.

### 7.5 External signals (pluggable)

- OSV / GHSA advisories
- OpenSSF Scorecard results
- deps.dev metadata
- Internal allow / deny lists

---

## 8. InstallGuard Architecture

### 8.1 Core philosophy

InstallGuard is not intended to replace `npm audit`, Snyk, Dependabot/Renovate, osv-scanner, or vulnerability databases. It complements them by introducing preventative governance, install-time policy enforcement, dependency-freshness controls, and risk visibility during adoption.

### 8.2 High-level workflow

```text
Developer / CI / Registry Proxy
              │
              ▼
   Dependency Resolution
              │
              ▼
   ┌─────────────────────────┐
   │  InstallGuard Engine    │
   │                         │
   │  Signal Providers ──┐   │
   │   (registry, OSV,   │   │
   │    deps.dev, ...)   │   │
   │                     ▼   │
   │  ┌──────────────────┐   │
   │  │  Policy Engine   │   │
   │  │  (rules / Rego)  │   │
   │  └──────────────────┘   │
   │           │             │
   │           ▼             │
   │  Risk Scoring & Audit   │
   └─────────────────────────┘
              │
   ┌──────────┼──────────┐
   ▼          ▼          ▼
 Allow      Warn       Block
              │
              ▼
        Sinks (PR comment,
        SIEM, OTel, Slack,
        attestation file)
```

### 8.3 Components

- **Signal providers** — pluggable sources of metadata about a package version.
- **Policy engine** — evaluates signals against rules. Supports a built-in DSL and an optional **OPA / Rego** back-end for organisations standardised on it.
- **Decision recorder** — writes decisions to `installguard.lock` (see §11) and to the audit sink.
- **Sinks** — PR/MR annotations, Slack, SIEM, OpenTelemetry, attestation output (in-toto / SLSA-style).

### 8.4 Plugin / extension model

A clean interface for third-party extensions across three planes:

1. **Signal providers** — implement a fetch interface for `(package, version) → metadata`.
2. **Policy rules** — author rules in the built-in DSL or Rego.
3. **Sinks** — receive structured decision events for delivery to external systems.

This avoids the tool becoming a monolith and allows enterprises to integrate existing reputation services (Socket, Snyk Advisor, internal threat intel) without forking.

---

## 9. Deployment Topologies

InstallGuard is designed to run in multiple modes. Most organisations will use more than one.

| Mode | Where it runs | Purpose |
| ---- | ------------- | ------- |
| **CLI / dev** | Developer workstation | Warn during `install`, fast feedback, pre-commit integration. |
| **CI gate** | CI pipeline | Hard-block on policy fail; emit attestation and SBOM. |
| **Registry proxy plugin** | Verdaccio / Artifactory / Nexus | Org-wide enforcement at the network layer; nothing in violation reaches a lockfile. Highest leverage. |
| **Control plane (optional)** | Central service | Policy distribution, audit log, dashboards, allowlist/waiver management, fleet-wide cache. |

The **registry proxy** placement is particularly powerful: it removes the need to run InstallGuard in every CI pipeline and prevents shadow-IT projects from bypassing policy.

---

## 10. Build & Install Hardening

### 10.1 Safe installation workflow

#### npm

```bash
npm ci --ignore-scripts
installguard scan
npm rebuild
```

#### pnpm

```bash
pnpm install --ignore-scripts
installguard scan
pnpm rebuild
```

#### yarn (Berry)

```bash
yarn install --mode=skip-build
installguard scan
yarn rebuild
```

This separates dependency acquisition, policy evaluation, and script execution.

### 10.2 Egress allowlisting during install

Install-time network egress should be restricted to the configured registry allowlist. Anything else — calls to attacker-controlled hosts, public paste sites, IP-address endpoints — is blocked and logged.

### 10.3 Sandboxed install execution

Where the host platform supports it, approved install scripts run inside a sandbox:

- no network (or registry-only)
- read-only filesystem outside the build directory
- scrubbed environment (drop `NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_*`, `GCP_*`, `KUBECONFIG`, etc.)
- CPU / wall-clock limits

Backends: `bubblewrap` (Linux), `nsjail`, ephemeral Docker containers, or macOS `sandbox-exec`.

### 10.4 Secret hygiene

Even outside the sandbox, the InstallGuard CLI provides a `--scrub-env` mode that wraps the package manager and strips known-sensitive variables before invoking install scripts.

---

## 11. Determinism & Auditability

InstallGuard emits an `installguard.lock` (or extends the package-manager lockfile via a sidecar) recording:

- the policy hash applied
- the metadata snapshot timestamp
- per-package decision: `allow`, `warn`, `waived-by`, `expires`
- signal values that drove each decision
- the resolved integrity hash for each package version

This enables:

- **Reproducible verification** — re-run the same evaluation later without registry access, using `--frozen-policy`.
- **Build attestation** — emit an in-toto / SLSA-style statement asserting "this build was produced under policy X with these decisions", which downstream consumers can verify.
- **Forensics** — when a package is later found to be malicious, query historical decisions to identify exposed builds.

---

## 12. Performance & Scale

Scanning a `pnpm-lock.yaml` with thousands of packages is a real performance problem. InstallGuard addresses this through:

- **Persistent on-disk metadata cache** keyed by `(package, version)` storing `time`, `maintainers`, `dist`, integrity hash, and script presence.
- **ETag-aware revalidation** to minimise registry traffic.
- **Concurrency-bounded fetcher** with backoff that respects registry rate limits.
- **Incremental mode** — diff the lockfile against the last successful run; check only the delta.
- **Optional shared cache server** for CI fleets, avoiding duplicate fetches across thousands of pipelines.

For air-gapped environments, a **metadata snapshot** can be pre-computed and consumed offline.

---

## 13. Securing InstallGuard Itself

A security tool must not become a supply-chain risk. InstallGuard's distribution model is therefore deliberately conservative:

- **Implementation language: Rust (or Go).** Single static binary; no `node_modules`; nothing for an npm attack to compromise.
- **No install-time scripts** of its own.
- **Reproducible builds** with published build instructions.
- **Signed releases** with SLSA Build Level 3 provenance attestations.
- **Distribution** via Homebrew, apt, scoop, container images, and GitHub Releases — each verifiable against the same provenance.
- **Pinned, vendored dependencies** for the build itself.
- **Offline-capable by design** — the CLI never phones home.

---

## 14. Standards & Compliance Mapping

InstallGuard is designed to support, not replace, established frameworks.

| Framework | InstallGuard contribution |
| --------- | ------------------------- |
| **SLSA**  | Helps reach Build L2/L3 by producing signed provenance about which dependency policy was applied; consumes upstream provenance as a signal. |
| **NIST SSDF** | Supports PW.4 (reuse secure code), PO.5 (secure environments), and RV.1 (vulnerability identification) via policy enforcement and audit logs. |
| **EU CRA** | Contributes to vulnerability handling and SBOM obligations through CycloneDX export and per-decision audit trails. |
| **OpenSSF Scorecard** | Consumed as a signal provider; not produced by InstallGuard. |
| **SBOM (CycloneDX / SPDX)** | Emitted with freshness and policy-decision metadata as component properties. |
| **VEX** | Per-package decisions exportable as VEX statements ("not affected: waived because…"). |

---

## 15. pnpm & Ecosystem Alignment

Modern package managers are already moving toward stronger governance. Recent pnpm releases include:

- minimum release age (`minimumReleaseAge`)
- lifecycle script restrictions (`onlyBuiltDependencies`)
- exotic dependency blocking
- stronger lockfile enforcement

npm and yarn are following similar trajectories with provenance, trusted publishers, and tighter default script handling.

InstallGuard complements these capabilities by adding centralised reporting, policy visibility, enterprise governance, risk scoring, PR-level review visibility, and organisation-wide auditing.

The objective is not to replace package-manager protections — it is to **operationalise** them across an organisation.

---

## 16. Ecosystem Reach Beyond npm

While this paper focuses on JavaScript, the freshness-governance principles apply to every package ecosystem. InstallGuard's core is designed to be language-agnostic, with adapters for:

- **PyPI** (already targeted by ctx, phpass-style attacks)
- **RubyGems**
- **Maven Central**
- **crates.io**
- **Go modules**
- **NuGet**
- **Hex**

The signal model (publisher change, install hooks, source type, age, provenance) translates directly; only the metadata adapters change.

---

## 17. Comparison With Existing Tools

InstallGuard is **complementary** to, not a replacement for, the tools below.

| Capability                          | InstallGuard | Socket | Snyk | npm audit | pnpm built-ins |
| ----------------------------------- | :----------: | :----: | :--: | :-------: | :------------: |
| Known-CVE scanning                  |      ✗*      |   ◐    |  ✓   |     ✓     |       ◐        |
| Behaviour / install-script analysis |      ✓       |   ✓    |  ◐   |     ✗     |       ◐        |
| Release-age governance              |      ✓       |   ◐    |  ✗   |     ✗     |       ✓        |
| Lifecycle-script approval           |      ✓       |   ✓    |  ✗   |     ✗     |       ✓        |
| Exotic-source blocking              |      ✓       |   ◐    |  ✗   |     ✗     |       ◐        |
| Org-wide policy & audit             |      ✓       |   ✓    |  ✓   |     ✗     |       ✗        |
| Build attestation of policy         |      ✓       |   ✗    |  ✗   |     ✗     |       ✗        |
| Registry-proxy enforcement          |      ✓       |   ✗    |  ✗   |     ✗     |       ✗        |
| Open source                         |      ✓       |   ◐    |  ✗   |     ✓     |       ✓        |

`*` InstallGuard *consumes* OSV/GHSA as a signal but does not maintain its own CVE database.

Legend: ✓ supported, ◐ partial, ✗ not supported.

---

## 18. Enterprise Adoption Strategy

### Phase 1 — Visibility

- warn only
- generate reports
- annotate pull requests
- measure dependency risk posture

No installs are blocked. This allows organisations to understand current dependency behaviour, install-script prevalence, and freshness exposure.

### Phase 2 — Policy Enforcement

- release-age enforcement
- install script approval lists
- Git / exotic dependency restrictions
- CI gating on policy violations

### Phase 3 — Mature Governance

- registry-proxy enforcement (org-wide)
- organisation-wide policy baselines
- package allowlists with attribution and expiry
- provenance enforcement
- mandatory review workflows for new dependencies

---

## 19. Recommended Policies

### Baseline

```yaml
minimumReleaseAge: 1440        # 24h
blockExoticSubdeps: true
```

### Stronger CI Policy

```yaml
minimumReleaseAge: 4320        # 72h
strictBuildScriptApproval: true
requireReviewForNewDependencies: true
flagPublisherChange: warn
```

### High-Security Environments

```yaml
minimumReleaseAge: 10080       # 7d
registryAllowlistOnly: true
noInstallScriptsByDefault: true
manualDependencyApproval: true
requireProvenance: true
flagPublisherChange: block
require2FAForDirectDeps: true
sandboxInstallScripts: true
```

---

## 20. Limitations & Trade-offs

A defence based on freshness has predictable trade-offs that adopters must understand and design around.

- **Delayed security patches.** A 72h quarantine also defers urgent fixes. Mitigation: explicit fast-track waivers (§6.1) tied to advisory IDs.
- **Patient attackers.** A malicious version that sits dormant for longer than the quarantine window will pass through. Mitigation: combine age with publisher-change and content-diff signals (§7).
- **False positives on legitimate fast-moving packages.** Frameworks with frequent legitimate releases (e.g. cutting-edge SDKs) will hit thresholds often. Mitigation: per-package age overrides on the allowlist.
- **Lockfile-time vs evaluation-time drift.** A lockfile committed today may be evaluated weeks later. InstallGuard re-evaluates against current metadata at CI time, with `--frozen-policy` for reproducible builds.
- **Registry trust assumption.** All decisions are only as truthful as the registry metadata. Signed integrity hashes pinned in `installguard.lock` mitigate substitution attacks.
- **Air-gapped environments.** Require pre-computed metadata snapshots; signal freshness is bounded by snapshot age.
- **Operational cost.** Quarantines, waivers, and approvals require humans. This is a deliberate trade — it is the human review attackers seek to bypass.

---

## 21. Open Questions & Roadmap

This is an evolving design and several questions are deliberately left open:

- What is the right default trust-score weighting across signals, and how should it adapt by ecosystem?
- How should InstallGuard interoperate with confidential / private registries that intentionally lack public metadata?
- Should the control plane be self-hostable only, or also offered as a managed service (with the obvious trust implications)?
- What is the most useful UX for surfacing trust-score deltas in PR reviews — numeric, badge-based, narrative?
- How can community-maintained allowlists (similar to ad-block lists) be safely shared without becoming attack vectors themselves?

A detailed technical design lives in [DESIGN.md](DESIGN.md) and the prioritised feature roadmap in [ROADMAP.md](ROADMAP.md).

---

## 22. Why This Matters

Modern supply-chain attacks increasingly exploit automation, speed, implicit trust, install-time execution, and developer convenience.

The JavaScript ecosystem does not necessarily need more scanners. It needs better dependency hygiene, slower trust propagation, clearer governance, improved visibility, and stronger install-time boundaries.

Freshness governance provides a practical, low-friction method for reducing exposure to modern npm supply-chain attacks without fundamentally disrupting developer workflows.

The future of dependency security is unlikely to rely solely on malware detection. Instead, it will increasingly depend on policy, provenance, execution control, trust maturity, and operational governance.

And sometimes:

> simply waiting 24 hours before installing something.

---

## References

- JFrog Research — "Shai-Hulud: Here We Go Again" (2024–2025)
- npm Lifecycle Scripts Documentation
- npm Provenance & Trusted Publishers Documentation
- OWASP npm Security Cheat Sheet
- pnpm Release Documentation (`minimumReleaseAge`, `onlyBuiltDependencies`)
- OpenSSF Supply Chain Security Guidance
- OpenSSF Scorecard
- Sigstore Documentation
- SLSA Framework
- NIST SP 800-218 — Secure Software Development Framework (SSDF)
- EU Cyber Resilience Act (CRA)
- CycloneDX & SPDX SBOM specifications
- VEX (Vulnerability Exploitability eXchange) specification
