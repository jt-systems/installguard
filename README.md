# InstallGuard

> **Dependency freshness & install-script governance for modern package ecosystems.**
> Reduce exposure to short-lived malicious releases without disrupting developer workflow.

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--alpha-orange.svg)](ROADMAP.md)
[![Whitepaper](https://img.shields.io/badge/docs-whitepaper-informational.svg)](whitepaper.md)

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

| Capability | Status |
| ---------- | :----: |
| Minimum release-age enforcement (per environment) | planned |
| Lifecycle script approval lists (`preinstall` / `install` / `postinstall`) | planned |
| Exotic-source blocking (Git, tarball, GitHub shortcut) | planned |
| Multi-signal risk scoring (publisher change, 2FA, file-set diff, dist-tag churn) | planned |
| PR annotations (GitHub & GitLab) | planned |
| Deterministic decision lockfile + signed in-toto attestation | planned |
| Sandboxed install-script execution | planned |
| Registry-proxy enforcement (Verdaccio / Artifactory / Nexus) | planned |
| Multi-ecosystem support (npm first, then PyPI, crates.io, Go, RubyGems, …) | planned |

See the [roadmap](ROADMAP.md) for milestones and the [design document](DESIGN.md) for the technical scope.

---

## How it fits in

InstallGuard is **complementary**, not a replacement, for:

- `npm audit`, Snyk, osv-scanner — keep them; they catch *known* vulnerabilities.
- Dependabot / Renovate — keep them; InstallGuard makes their PRs safer to merge.
- pnpm built-ins (`minimumReleaseAge`, `onlyBuiltDependencies`) — InstallGuard *operationalises* these across an organisation: central policy, audit, attestation, registry-proxy enforcement.

Comparison table in [whitepaper §17](whitepaper.md#17-comparison-with-existing-tools).

---

## Quick start

> **Pre-alpha — no releases yet.** This section describes the intended UX.

```bash
# Install (planned)
brew install installguard

# Initialise a baseline policy
installguard init

# Scan the current project (uses package-lock.json / pnpm-lock.yaml / yarn.lock)
installguard scan

# In CI: hard-fail on policy violations and emit an attestation
installguard ci --attestation installguard.intoto.jsonl
```

Example policy (`installguard.yaml`):

```yaml
policyVersion: 1

defaults:
  minimumReleaseAge: 1440        # minutes (24h)
  blockExoticSubdeps: true

scripts:
  policy: deny-by-default
  allow: [esbuild, sharp, playwright]

direct:
  minimumReleaseAge: 4320         # stricter for direct deps
  flagPublisherChange: warn
```

Full DSL in [DESIGN.md §4](DESIGN.md#4-policy-dsl). More examples in `examples/policies/` (coming soon).

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

InstallGuard is in **pre-alpha**. The whitepaper, design and roadmap are stable enough to build against; the implementation is just getting underway. Milestone 0 (foundations) is the current focus — see [ROADMAP.md](ROADMAP.md#milestone-0--foundations).

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
3. **Offline-capable by default.** No phone-home. Air-gapped deployments are first-class.
4. **Boring distribution.** Single static binary. No `node_modules`. No install scripts of our own.
5. **Operationalise existing controls.** Don't reinvent pnpm, Sigstore, or OSV — orchestrate them.
6. **Honest about limits.** See [whitepaper §20](whitepaper.md#20-limitations--trade-offs).

---

## Contributing

Contribution guidelines and a `CONTRIBUTING.md` will land alongside the Milestone 0 scaffold. In the meantime:

- Issues and discussion are welcome.
- Sanitised real-world lockfiles for adapter golden tests are particularly useful.
- Security-relevant reports: please follow the (forthcoming) `SECURITY.md` rather than opening a public issue.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE). The Apache-2.0 licence was chosen specifically for its explicit patent grant — important for a security tool intended for enterprise adoption.
