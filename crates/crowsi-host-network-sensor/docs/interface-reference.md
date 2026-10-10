# crowsi-host-network-sensor interface reference

Use the [usage guide](getting-started.md) for the first steps. This reference preserves the current interface details and operational limits. Run command examples from the repository root, after preparing the exact declared dependencies and registered configuration.

## Observed metadata

The production sensor has no configurable source path. It performs bounded
reads of exactly:

- `/proc/net/tcp`
- `/proc/net/tcp6`
- `/proc/net/udp`
- `/proc/net/udp6`
- `/proc/net/route`
- `/proc/net/ipv6_route`

TCP rows are retained only in LISTEN state. UDP rows with a nonzero local port
are treated as bound sockets because UDP has no TCP-style LISTEN state. Each
address is immediately reduced to `loopback`, `specific`, or `wildcard`; the
address value is discarded. Routes are reduced to IPv4/IPv6 default-route
presence.

Output never contains packets, payloads, local or remote addresses, remote
endpoints, interface names, PIDs, UIDs, inodes, process data, hostnames, or
credentials. Each procfs file is capped at 1 MiB, tables at 8192 rows, and
listener results at 4096 unique metadata records. Any unavailable, oversized,
non-UTF-8, or malformed source discards partial results and emits `unknown`.

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

## Trust and coverage boundary

Every output declares `external_actions: false` and
`signal_trust: "unsigned-local"`. The sensor is not an IDS, a PIP authority, a
PEP, an isolation verifier, or proof that a host is uncompromised. It sees only
the caller's current Linux network namespace and can be evaded or falsified by
software with sufficient local privilege.

This signal must never promote standard Coela coverage, Crowsi control coverage,
or any asset state to `controlled`. A consumer may display it only as
supplemental unsigned local evidence. Signed authorization, independent
coverage, provider-specific enforcement, and verified receipts remain separate
requirements.
