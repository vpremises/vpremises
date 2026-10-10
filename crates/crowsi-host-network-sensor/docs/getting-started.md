# Using crowsi-host-network-sensor

Observe Linux host networking and compare it with an explicit baseline.

## Before you start

The sensor observes the host; it does not reconfigure interfaces or infer an approved baseline.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Capture bounded host-network metadata.
- Evaluate differences against a supplied baseline.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
