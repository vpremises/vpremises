# Using crowsi-boundary-monitor

Assess isolation boundaries from a supplied environment observation.

## Before you start

Collectors supply sanitized observations. The monitor evaluates them without provisioning or changing a boundary.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Evaluate Linux, container, WSL, Incus or cloud boundary metadata.
- Review coverage and missing boundary evidence.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
