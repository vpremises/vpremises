# crowsi-production-assurance

Check whether deployment evidence meets the declared prerequisites for production control.

## What you can do

- Review key, release and recovery evidence.
- Report missing assurance requirements before activation.

## Current scope

This library evaluates supplied evidence. Its presence or passing unit tests do not certify a production deployment.

Package distribution is not activated by this documentation. Use the owning product workspace and declared dependency versions. Registry availability is a separate release gate.

## Getting started

Install Rust 1.97 or newer. Run from the owning product workspace:

```sh
cargo test --locked -p crowsi-production-assurance
```

## Documentation and source

[Usage guide](docs/getting-started.md)

[Schemas](schemas) · [Detailed documentation](docs) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)

## Product responsibility

This component is maintained in [vpremises/vpremises-security](https://github.com/vpremises/vpremises-security). Use the [product README](../../README.md) for composition, use cases and trust boundaries.
