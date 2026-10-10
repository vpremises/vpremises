# crowsi-incident-coordinator

Track an incident through containment, recovery, monitoring and closure using explicit evidence.

## What you can do

- Validate a requested incident transition.
- Produce a reviewable coordination plan.

## Current scope

The coordinator models transitions. External containment and recovery actions require separately authorized adapters.

Package distribution is not activated by this documentation. Use the owning product workspace and declared dependency versions. Registry availability is a separate release gate.

## Getting started

Install Rust 1.97 or newer. Run from the owning product workspace:

```sh
cargo test --locked -p crowsi-incident-coordinator
```

## Documentation and source

[Interface reference](docs/interface-reference.md)

[Usage guide](docs/getting-started.md)

[Schemas](schemas) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)

## Product responsibility

This component is maintained in [vpremises/vpremises-security](https://github.com/vpremises/vpremises-security). Use the [product README](../../README.md) for composition, use cases and trust boundaries.
