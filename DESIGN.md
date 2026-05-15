# InstallGuard — Technical Design

> Companion to [whitepaper.md](whitepaper.md). The whitepaper covers the background, threat model, and limits; this document covers the *how*.

---

## 1. Goals & Non-Goals

### Goals

- Operate as a **single static binary** with no install-time scripts of its own.
- Make policy decisions deterministic, reproducible, and attestable.
- Run unchanged in three modes: developer CLI, CI gate, registry-proxy plugin.
- Be language-agnostic at the core; ship npm first, others later.
- Be fast enough for lockfiles with 10k+ entries on a developer laptop.
- Never require phoning home; offline / air-gapped deployments are first-class.

### Non-Goals

- Maintaining a CVE / advisory database (consume OSV/GHSA instead).
- Replacing package managers; InstallGuard wraps and observes them.
- Runtime application protection (out of scope; complementary to RASP/EDR).
- Automatic remediation (PR creation) in v1; only decisions and annotations.

---

## 2. Implementation Language & Distribution

- **Language: Rust.** Static binary, strong type system, mature crypto and HTTP, no runtime install hooks.
- **Distribution channels:** Homebrew, apt/deb, scoop, container images (`distroless`), GitHub Releases.
- **Provenance:** SLSA Build Level 3 attestations published with each release; verifiable via `slsa-verifier`.
- **Reproducible builds:** documented build environment, locked toolchain, vendored dependencies.
- **Versioning:** SemVer. Policy schema versioned independently (`policyVersion: 1`).

---

## 3. Component Architecture

```
                 ┌────────────────────────────────────────────────┐
                 │                  installguard                  │
                 │                                                │
  Lockfile ───▶  │  ┌────────────┐    ┌─────────────────────┐   │
                 │  │ Resolver / │───▶│  Signal Aggregator  │   │
                 │  │ Lockfile   │    │  (parallel fetch)   │   │
                 │  │ Adapter    │    └──────────┬──────────┘   │
                 │  └────────────┘               │               │
                 │                               ▼               │
                 │                       ┌──────────────┐        │
                 │                       │   Cache      │        │
                 │                       │ (sled/sqlite)│        │
                 │                       └──────┬───────┘        │
                 │                              ▼                │
                 │                    ┌──────────────────┐       │
                 │                    │  Policy Engine   │       │
                 │                    │ (DSL + Rego opt) │       │
                 │                    └────────┬─────────┘       │
                 │                             ▼                 │
                 │                    ┌──────────────────┐       │
                 │                    │ Decision Recorder│       │
                 │                    └────────┬─────────┘       │
                 │           ┌─────────────────┼──────────────┐  │
                 │           ▼                 ▼              ▼  │
                 │    installguard.lock  Sinks (PR/SIEM)  Attestation
                 └────────────────────────────────────────────────┘
```

### 3.1 Lockfile adapters

Pluggable; one per ecosystem. v1 ships:

- `package-lock.json` (npm v7+)
- `pnpm-lock.yaml` (v6, v7, v9)
- `yarn.lock` (Berry)

Each adapter normalises to a common `ResolvedDependency` struct:

```rust
struct ResolvedDependency {
    ecosystem: Ecosystem,         // Npm, PyPi, ...
    name: String,
    version: String,
    integrity: Integrity,         // sha512:..., sha256:...
    source: Source,               // Registry { url } | Git | Tarball | File | GithubShortcut
    direct: bool,
    requested_by: Vec<String>,    // path through the dep tree
}
```

### 3.2 Signal providers

Trait-based. Each provider returns one or more `Signal` values for a `(name, version)` pair.

```rust
trait SignalProvider: Send + Sync {
    fn id(&self) -> &'static str;
    fn supports(&self, eco: Ecosystem) -> bool;
    async fn signals(&self, dep: &ResolvedDependency) -> Result<Vec<Signal>>;
}
```

v1 providers:

- `npm-registry` — publish time, maintainers, dist-tags, scripts, file list, integrity.
- `npm-provenance` — Sigstore attestation lookup via Rekor.
- `osv` — GHSA / OSV advisories.
- `deps-dev` — cross-ecosystem metadata.
- `local-allowlist` — org-defined files.
- `scorecard` (optional) — OpenSSF Scorecard.
- `socket` / `snyk-advisor` (optional, gated by API key).

### 3.3 Policy engine

Two backends:

1. **Built-in DSL** — declarative YAML for the 95% case (the examples live in the README and docs site).
2. **Rego (OPA)** — for orgs that already standardise on Rego; embedded via `regorus`.

A policy evaluation produces a `Decision`:

```rust
enum Decision {
    Allow,
    Warn { reasons: Vec<Reason> },
    Block { reasons: Vec<Reason> },
    Waived { waiver_id: String, expires: DateTime<Utc> },
}
```

### 3.4 Cache

- Backend: `sled` (default) or SQLite (for shared cache server mode).
- Key: `(ecosystem, name, version)` → cached metadata blob + ETag + fetch timestamp.
- TTL: configurable per signal type (registry metadata: 6h; provenance: 24h; OSV: 1h).
- Atomic writes; safe for concurrent processes (file lock).

### 3.5 Decision recorder

Writes:

- `installguard.lock` (sidecar to package-manager lockfile, JSON, sorted, deterministic).
- Audit log (JSONL) for SIEM ingestion.
- in-toto v1 statement (`installguard.intoto.jsonl`) for build attestation.

---

## 4. Policy DSL

```yaml
policyVersion: 1

defaults:
  minimumReleaseAge: 1440        # minutes
  blockExoticSubdeps: true
  flagPublisherChange: warn
  requireProvenance: false

scripts:
  policy: deny-by-default
  allow:
    - esbuild
    - sharp
    - playwright

registries:
  allowlist:
    - https://registry.npmjs.org/
    - https://npm.internal.example.com/

direct:
  minimumReleaseAge: 4320        # stricter for direct deps
  requireProvenance: true
  require2FAForMaintainers: true

waivers:
  - package: axios
    version: 1.7.9
    reason: "CVE-2026-1234 RCE fix"
    approvedBy: "@alice"
    expires: 2026-06-01

sandbox:
  installScripts: true
  scrubEnv:
    - NPM_TOKEN
    - GITHUB_TOKEN
    - AWS_*
    - GCP_*
    - KUBECONFIG

sinks:
  - type: github-pr
  - type: otel
    endpoint: https://otel-collector.example.com
  - type: file
    path: .installguard/audit.jsonl
```

The schema is versioned and validated; unknown keys are an error.

---

## 5. Trust Score

A scalar in `[0.0, 1.0]` per `(name, version)` derived from weighted signals:

```
score = w_age   * f_age(release_age)
      + w_pub   * f_pub(publisher_continuity)
      + w_2fa   * f_2fa(maintainer_2fa_ratio)
      + w_prov  * f_prov(provenance_present_and_valid)
      + w_cad   * f_cad(historical_release_cadence)
      + w_diff  * f_diff(file_set_delta_risk)
      + w_scope * f_scope(openssf_scorecard)
```

- Weights default-tuned per ecosystem; overridable in policy.
- Each `f_*` is a bounded transform documented in the source.
- The score is **explanatory**, not authoritative; policy decisions cite the underlying signals, not the score alone.

---

## 6. `installguard.lock` Format

Deterministic, sorted JSON. Example excerpt:

```json
{
  "schemaVersion": 1,
  "policyHash": "sha256:9af...",
  "evaluatedAt": "2026-05-13T10:14:22Z",
  "ecosystem": "npm",
  "decisions": [
    {
      "name": "axios",
      "version": "1.7.9",
      "integrity": "sha512:...",
      "decision": "allow",
      "signals": {
        "releaseAgeMinutes": 14400,
        "publisherChange": false,
        "provenance": "verified",
        "scripts": []
      }
    },
    {
      "name": "left-pad",
      "version": "9.9.9",
      "integrity": "sha512:...",
      "decision": "block",
      "reasons": ["release_age_below_threshold", "publisher_change"]
    }
  ]
}
```

`--frozen-policy` mode re-verifies an existing lockfile without contacting the registry.

---

## 7. Attestation

InstallGuard emits an in-toto v1 Statement:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://installguard.dev/policy-evaluation/v1",
  "subject": [
    { "name": "pnpm-lock.yaml", "digest": { "sha256": "..." } }
  ],
  "predicate": {
    "policyHash": "sha256:...",
    "evaluatedAt": "2026-05-13T10:14:22Z",
    "summary": { "allow": 412, "warn": 3, "block": 0, "waived": 1 },
    "decisionsRef": "installguard.lock"
  }
}
```

Signed via Sigstore (cosign keyless or KMS). Downstream consumers verify via `cosign verify-attestation`.

---

## 8. Sandbox Backends

| Platform | Backend                          |
| -------- | -------------------------------- |
| Linux    | `bubblewrap` (preferred), `nsjail` |
| macOS    | `sandbox-exec`                    |
| Windows  | Job Object + AppContainer (best-effort) |
| CI       | Ephemeral container per script    |

Restrictions applied uniformly:

- Network: deny-all, or registry-only egress proxy.
- Filesystem: read-only outside build dir; `/etc` denied; secrets dirs denied.
- Env: scrubbed against allowlist.
- CPU/wallclock limits per script.

---

## 9. Registry-Proxy Plugin

A thin process that sits in front of Verdaccio / Artifactory / Nexus and rejects tarball requests for versions blocked by policy.

- Reuses the same policy engine and cache as the CLI.
- Returns HTTP `451 Unavailable For Legal Reasons` (or `403`) with a structured JSON body explaining the decision.
- Emits the same audit and OTel events as CLI mode.

This is the highest-leverage placement: it makes policy unbypassable for any project consuming the proxy.

---

## 10. Security of InstallGuard Itself

- Single static binary; no `node_modules`; no install scripts.
- All HTTP via `rustls`; no system OpenSSL dependency.
- All registry responses validated against expected JSON schema; unknown fields ignored, type mismatches rejected.
- Rate-limit and timeout on every outbound call.
- CLI never executes code from packages it inspects; all analysis is metadata-based or static.
- Sandbox process is a separate binary (`installguard-sandbox`) with minimal surface area.
- Releases signed; provenance verifiable.
- Threat-modelled with STRIDE; document maintained in `docs/threat-model.md` (TBD).

---

## 11. Performance Targets

| Workload                                | Target                  |
| --------------------------------------- | ----------------------- |
| Cold scan, 1k packages, warm registry   | < 10s                   |
| Warm scan (full cache hit)              | < 1s                    |
| Incremental scan (10 changed packages)  | < 500ms                 |
| Memory peak, 10k packages               | < 200 MB                |
| Registry requests per cold scan         | ≤ 1 per (name, version) |

Achieved via concurrent fetcher, persistent cache, ETag revalidation, and zero-copy lockfile parsing.

---

## 12. Repository Layout (proposed)

```
installguard/
├── crates/
│   ├── core/                # types, traits, policy engine
│   ├── cli/                 # binary entrypoint
│   ├── sandbox/             # installguard-sandbox binary
│   ├── proxy/               # registry-proxy plugin
│   ├── adapters/
│   │   ├── npm/
│   │   ├── pnpm/
│   │   └── yarn/
│   ├── signals/
│   │   ├── npm-registry/
│   │   ├── npm-provenance/
│   │   ├── osv/
│   │   ├── deps-dev/
│   │   └── scorecard/
│   ├── sinks/
│   │   ├── github/
│   │   ├── otel/
│   │   └── file/
│   └── attestation/
├── docs/
│   ├── whitepaper.md
│   ├── DESIGN.md
│   ├── ROADMAP.md
│   └── threat-model.md
├── examples/
│   └── policies/
└── .github/workflows/
```

---

## 13. Testing Strategy

- **Unit tests** per crate.
- **Golden-file tests** for lockfile adapters against real public lockfiles.
- **Policy fixtures** — every documented policy example must round-trip and evaluate against a fixture lockfile to a documented decision set.
- **Property tests** (`proptest`) for the policy engine: e.g. "increasing release age never decreases trust score".
- **Integration tests** against a mock npm registry.
- **End-to-end tests** in containers exercising npm/pnpm/yarn workflows.
- **Fuzz tests** on lockfile parsers and registry-response parsers.

---

## 14. Open Design Questions

- Should waivers live in-policy, in a separate signed `waivers.yaml`, or in a control-plane database?
- Should the trust score be exposed in PR annotations as a number, a band (low/medium/high), or hidden behind reasons?
- Is there value in a `dry-run --against-policy <hash>` mode for evaluating policy changes before rollout?
- For monorepos: per-workspace policy files, or single root policy with overrides?
- Should we ship a built-in metadata-snapshot exporter for air-gapped sites, or treat it as an external tool?
