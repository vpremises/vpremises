# Using vpremises

Inspect metadata in an explicitly selected local area without collecting file contents.

## Before you start

The caller chooses the permitted roots. Observation does not deploy workloads or change host configuration.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Check observer configuration.
- Produce a bounded observation for a management application.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
