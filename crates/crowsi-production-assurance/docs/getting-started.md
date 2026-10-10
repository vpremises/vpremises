# Using crowsi-production-assurance

Check whether deployment evidence meets the declared prerequisites for production control.

## Before you start

This library evaluates supplied evidence. Its presence or passing unit tests do not certify a production deployment.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Review key, release and recovery evidence.
- Report missing assurance requirements before activation.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
