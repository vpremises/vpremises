# Security policy

## Read boundary

The production sensor may open only the six fixed `/proc/net` files documented
in the README. It must not accept an alternate telemetry path, traverse procfs,
open sockets, capture packets, resolve names, call a provider, inspect
`/proc/<pid>`, or mutate routes, firewall rules, namespaces, or processes.
Baseline input is separate bounded JSON read from stdin and is never a telemetry
source or authorization.

Opened procfs descriptors must report a regular file type. Every read, row set,
listener set, JSON input, and output vocabulary is bounded. Raw I/O and parser
errors must collapse to the closed `source-unavailable` or
`source-parse-failure` code. Never serialize source lines or operating-system
error text.

## Data minimization

Local and remote addresses are validated only while parsing and then discarded.
Remote ports are also discarded. The only retained socket fields are protocol,
address family, local port, and reduced bind scope. Route rows retain only
default-route presence by address family. Packet data, interface names, user
and process identifiers, inodes, counters, credentials, and hostnames are
forbidden output.

## Detection limitations

This is a point-in-time, unsigned view of one Linux network namespace. It does
not attest the kernel, clock, procfs mount, namespace selection, parser caller,
or baseline. A privileged attacker can hide or race state; short-lived sockets
can appear between reads. Reused ports collapse into one metadata record.
IPv6 wildcard behavior may also accept IPv4 traffic depending on socket options,
which procfs does not expose here. UDP includes connected client sockets because
they are locally bound, so ephemeral-port drift is possible.

Default-route presence does not prove reachability, route preference, DNS,
firewall behavior, or packet flow. Absence of a reported listener does not prove
absence of eBPF, raw sockets, another namespace, another host, proxying, or
compromise. This package is not a complete IDS and must not trigger automatic
containment or restoration.

## Coverage and response

`external_actions` is permanently false. Findings are supplemental unsigned
local signals only. They must never upgrade standard Coela coverage or Crowsi
control coverage to `controlled`, satisfy independent-verification obligations,
or authorize a PEP. Unknown source state must remain visible and fail closed.

Report vulnerabilities using synthetic metadata. Do not attach live procfs
tables, addresses, process details, topology, tokens, or credentials.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
