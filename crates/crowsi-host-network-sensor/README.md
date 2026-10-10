# crowsi-host-network-sensor

Observe Linux host networking and compare it with an explicit baseline.

## What you can do

- Capture bounded host-network metadata.
- Evaluate differences against a supplied baseline.

## Current scope

The sensor observes the host; it does not reconfigure interfaces or infer an approved baseline.

Package distribution is not activated by this documentation. Use the owning product workspace and declared dependency versions. Registry availability is a separate release gate.

## Getting started

Install Rust 1.97 or newer. Run from the owning product workspace:

```sh
cargo test --locked -p crowsi-host-network-sensor
```

## Examples and interface details

## Commands

```bash
cargo run --locked --offline -- sample
cargo run --locked --offline -- sample baseline
cargo run --locked --offline -- observe
cargo run --locked --offline -- evaluate < examples/baseline.sample.json
```

`sample` emits a deterministic snapshot; `sample baseline` emits a matching
baseline. `observe` reads the six fixed procfs sources. `evaluate` reads one
closed Baseline v1 JSON value from bounded stdin, observes locally, and applies
the pure drift evaluator. No command changes host or network state.

The evaluator reports unexpected or missing listener metadata and changed
default-route presence. It preserves `unknown` rather than comparing incomplete
data. Baseline, Snapshot, and Finding JSON Schemas reject unknown fields and
incompatible v1 values.

## Documentation and source

[Interface reference](docs/interface-reference.md)

[Usage guide](docs/getting-started.md)

[Examples](examples) · [Schemas](schemas) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)

## Product responsibility

This component is maintained in [vpremises/vpremises-security](https://github.com/vpremises/vpremises-security). Use the [product README](../../README.md) for composition, use cases and trust boundaries.
