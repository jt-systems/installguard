# Contributing to InstallGuard

Thanks for considering a contribution. InstallGuard is a security tool, so we hold the bar deliberately high on review, testing, and supply-chain hygiene of the project itself.

This guide covers what to expect. The technical scope lives in [DESIGN.md](DESIGN.md) and the prioritised work in [ROADMAP.md](ROADMAP.md).

---

## Code of Conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). By contributing, you agree to abide by its terms.

---

## Before you start

- **Open an issue first** for anything beyond a small fix. We'd rather discuss approach early than ask you to redo work.
- **Check the roadmap.** Work that aligns with the current milestone is far more likely to land quickly.
- **For new policy rules or signal providers**, please include a short rationale: what attack class does it address, what is the false-positive risk, what is the runtime cost.

---

## Development

### Prerequisites

- Rust (stable toolchain pinned in `rust-toolchain.toml` once it lands)
- A real package-manager lockfile to test against (`pnpm-lock.yaml` is the primary target)

### Building & testing

```bash
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt   --all -- --check
```

All four must pass before a PR is merged. CI enforces this.

### Adding a lockfile adapter

Implement the `LockfileAdapter` trait in `crates/adapters/<eco>/`. Provide:

- a parser
- a normaliser to `ResolvedDependency`
- at least one **golden-file test** against a real (sanitised) lockfile in `crates/adapters/<eco>/tests/fixtures/`

### Adding a signal provider

Implement the `SignalProvider` trait in `crates/signals/<name>/`. Required:

- offline behaviour: never panic if the upstream is unreachable; return a typed `Unavailable` signal
- ETag-aware caching where the upstream supports it
- unit tests against a recorded mock response

### Adding a policy rule

Built-in DSL rules live in `crates/core/src/policy/`. Each rule:

- has a stable name (used in `installguard.lock` decisions)
- emits a structured `Reason` enum variant — never a free-form string
- has fixture-based tests covering allow / warn / block paths

---

## Pull requests

- One concern per PR. Refactors and feature work in the same PR will be asked to split.
- Keep diffs reviewable. If a PR exceeds ~500 lines of non-generated change, expect to be asked for a design note.
- Update tests **and** documentation in the same PR. Behaviour changes that don't update [DESIGN.md](DESIGN.md) or relevant `docs/` are not complete.
- New dependencies require justification. We prefer fewer, audited crates over many small ones — InstallGuard's own supply chain is part of its threat model (see [DESIGN.md §10](DESIGN.md#10-security-of-installguard-itself)).

### Commit style

- Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
- Imperative mood, present tense (`add foo`, not `added foo`).
- Reference issues with `Fixes #123` / `Refs #123` in the body, not the title.

### DCO

All commits must be signed off:

```bash
git commit -s -m "feat(core): add publisher-change signal"
```

By signing off, you certify the contents of the [Developer Certificate of Origin](https://developercertificate.org/).

---

## Reporting bugs

Open a GitHub issue with:

- InstallGuard version (`installguard --version`)
- OS and architecture
- Minimal reproduction (lockfile excerpt + policy file is ideal)
- Expected vs actual behaviour

If the bug has security implications, **do not file a public issue** — see [SECURITY.md](SECURITY.md).

---

## Proposing new features

Open a GitHub issue using the (forthcoming) feature-request template. Please include:

- the attack class or operational pain it addresses
- which whitepaper/design section it relates to
- expected impact on false-positive rate and performance
- whether it belongs in core, in a signal provider, or as an external plugin

Speculative features without an attack-class rationale are unlikely to be accepted.

---

## Documentation

Documentation changes are first-class contributions. Particularly welcome:

- clarifications to ambiguous policy semantics
- additional realistic policy examples in `examples/policies/`
- corrections to the threat model
- translations (once we have a stable English baseline)

---

## Release process

Releases are tagged from `main` after CI passes. Each release ships:

- a single static binary per supported platform
- SHA-256 checksums
- SLSA Build Level 3 provenance attestation
- container image to a public registry

Maintainers handle releases; contributors should not push tags.

---

## Questions

Open a GitHub Discussion (once enabled) or issue. We aim to triage within a working week.
