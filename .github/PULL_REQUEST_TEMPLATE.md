## Summary

<!-- One paragraph: what does this PR do and why? -->

## Motivation

<!-- Link to the issue or roadmap item this addresses, e.g. "Closes #123". -->

## Changes

<!-- Bullet list of the main changes. Be specific about crate / module. -->

- 

## Testing

<!-- How was this tested? What new tests were added? -->

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo fmt --all -- --check` passes
- [ ] New or updated golden-file / fixture tests for adapter or policy changes
- [ ] Manual smoke test against a real lockfile (attach output if relevant)

## Documentation

- [ ] Relevant sections of [DESIGN.md](../DESIGN.md) updated (if behaviour changed)
- [ ] `ROADMAP.md` checkbox ticked (if this closes a milestone item)
- [ ] Policy DSL or output schema documented (if new fields added)

## Checklist

- [ ] Commits are signed off (`git commit -s`) per the DCO
- [ ] New dependencies are justified in the PR description
- [ ] No `unwrap()` / `expect()` in non-test code without a documented invariant
- [ ] PR is focused on a single concern (see [CONTRIBUTING.md](../CONTRIBUTING.md))
