# crowsi-boundary-monitor

Assess isolation boundaries from a supplied environment observation.

## What you can do

- Evaluate Linux, container, WSL, Incus or cloud boundary metadata.
- Review coverage and missing boundary evidence.

## Current scope

Collectors supply sanitized observations. The monitor evaluates them without provisioning or changing a boundary.

Package distribution is not activated by this documentation. Use the owning product workspace and declared dependency versions. Registry availability is a separate release gate.

## Getting started

Install Rust 1.97 or newer. Run from the owning product workspace:

```sh
cargo test --locked -p crowsi-boundary-monitor
```

## Documentation and source

[Usage guide](docs/getting-started.md)

[Examples](examples) · [Schemas](schemas) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)

## Product responsibility

This component is maintained in [vpremises/vpremises-security](https://github.com/vpremises/vpremises-security). Use the [product README](../../README.md) for composition, use cases and trust boundaries.
