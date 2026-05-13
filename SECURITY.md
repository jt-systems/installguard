# Security Policy

InstallGuard is a security tool. Vulnerabilities in InstallGuard itself can directly weaken the supply-chain posture of every project that relies on it. We treat reports accordingly.

---

## Scope

In scope for security reporting:

- The InstallGuard CLI, sandbox helper, and registry-proxy plugins
- The policy engine, lockfile adapters, and signal providers shipped in this repository
- The release-distribution pipeline (signing, provenance, container images)
- Documented APIs and on-disk formats (`installguard.lock`, attestation predicate)

Out of scope:

- Vulnerabilities in third-party packages that InstallGuard scans (those belong to the affected upstream)
- Issues in the underlying package managers (`npm`, `pnpm`, `yarn`, etc.) — please report to them directly
- Denial-of-service requiring an attacker who already controls the policy file or build environment
- Theoretical attacks without a demonstrated impact path
- Missing best-practice headers / hardening on documentation sites

---

## Reporting a vulnerability

**Please do not open a public GitHub issue for security reports.**

Use one of the following private channels:

1. **GitHub Security Advisories** (preferred) — open a draft advisory on this repository.
2. **Email** — `security@installguard.dev` (PGP key fingerprint will be published here once releases begin).

Please include:

- a clear description of the issue and its impact
- a minimal reproduction (commands, lockfile excerpt, policy file)
- the InstallGuard version (or commit SHA) and platform
- any suggested mitigation, if known

We acknowledge new reports within **3 working days** and aim to provide a triage decision within **10 working days**.

---

## Disclosure process

We follow **coordinated disclosure**:

1. We confirm and triage the report.
2. We develop and test a fix in a private branch.
3. We agree a disclosure date with the reporter.
4. We release a patched version with an advisory.
5. We credit the reporter (unless they prefer to remain anonymous).

Default embargo target: **90 days** from confirmation, shortened if a fix is ready earlier or if the issue is being actively exploited.

---

## Supported versions

While InstallGuard is pre-1.0, only the latest released version receives security fixes. Once 1.0 ships, the security-support policy will be:

- Latest minor: full support
- Previous minor: critical fixes for 6 months after the next minor releases
- Older versions: no support

---

## Security expectations of InstallGuard itself

These are the properties we commit to maintaining (see [DESIGN.md §10](DESIGN.md#10-security-of-installguard-itself) for detail):

- Single static binary; no install-time scripts of our own.
- All releases are signed and ship with SLSA Build Level 3 provenance.
- All registry / network responses are schema-validated; unknown fields are ignored, type mismatches rejected.
- The CLI never executes code from the packages it inspects. All analysis is metadata-based or static.
- The sandbox helper (`installguard-sandbox`) is a separate binary with minimal surface area.
- Reproducible builds; the build environment is documented and pinned.

If you find behaviour that contradicts any of the above, that is itself a security issue and we want to hear about it.

---

## Hall of fame

Reporters who responsibly disclose vulnerabilities will be credited here (with permission) once releases begin.
