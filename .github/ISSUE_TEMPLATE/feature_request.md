---
name: Feature request
about: Propose new behaviour, a signal provider, policy rule, or ecosystem support
labels: enhancement
---

## Problem / motivation

<!-- What attack class, operational pain, or gap in coverage does this address?
     Link to the relevant whitepaper threat-model section or DESIGN.md section if applicable. -->

## Proposed solution

<!-- Describe the change. Be specific about the interface (CLI flag, policy DSL
     key, output field) and the expected behaviour. -->

## Attack class addressed

<!-- Which threat-model pattern from the whitepaper does this mitigate?
     If none, explain the operational value. -->

## False-positive risk

<!-- Will legitimate packages trip this check? How often, and for how long? -->

## Performance / latency impact

<!-- Any new network calls, disk I/O, or significant CPU cost? -->

## Scope

- [ ] Core policy engine (`crates/core/`)
- [ ] Lockfile adapter (`crates/adapters/<eco>/`)
- [ ] Signal provider (`crates/signals/<name>/`)
- [ ] CLI (`crates/cli/`)
- [ ] CI / GitHub Action
- [ ] Documentation only

## Alternatives considered

<!-- What else could address this? Why is this approach preferred? -->
