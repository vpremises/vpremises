# Using crowsi-incident-coordinator

Track an incident through containment, recovery, monitoring and closure using explicit evidence.

## Before you start

The coordinator models transitions. External containment and recovery actions require separately authorized adapters.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Validate a requested incident transition.
- Produce a reviewable coordination plan.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
