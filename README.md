# vpremises-security

A Rust CLI for read-only inspection of selected directories mounted in Linux/WSL.
Reports are local JSON or JSONL; no account, dashboard or remote upload is required.

## Capabilities

- Bound metadata traversal of explicitly selected mounted roots.
- Inspect file contents, names and archives through a pinned local Zixcel/Gitleaks adapter.
- Include ignored, hidden and non-Git files in directory content inspection.
- Connect Crowsi's Linux network sensor to an explicit baseline.
- Evaluate a pinned, fresh operator-supplied isolation observation with Crowsi.
- Emit only aggregate counters, stable reason codes and evidence hashes.
- Preserve incomplete checks, unsupported files and collector failures.

Run the Linux executable inside WSL. A mount such as `/mnt/c/Inspection/Selected`
exposes files, not the Windows host's firewall, processes or credential store.
Network checks cover only the current Linux network namespace. Boundary checks
use supplied evidence; they do not discover or enforce host isolation.

## Run

Copy [the audit configuration example](examples/audit.mounted.json) to a private
configuration directory. Set selected roots, executable hashes, external detector
settings, network baseline and boundary evidence explicitly. Build or obtain the
local collector executables separately; missing collectors cannot receive a pass.

```sh
./vpremises-security audit /private/audit.json workstation --jsonl
```

Exit codes: 0 for passed configured scope, 1 for invalid input, 2 for incomplete
coverage, 3 for findings. Capture stdout even when the exit code is nonzero.
A scoped pass is not whole-device security certification.

`doctor`, `observe` and `report` remain available without external collectors.
`report` records missing content/network/boundary checks as unsupported.
Scheduling belongs to the operator's systemd timer or cron; nothing is installed
or enabled implicitly. Selected mounted files are never changed or deleted.

## Build and distribution

```sh
CARGO_TARGET_DIR=/path/to/build cargo build --locked --release
```

CI targets Linux x64 only. Download and extract the approved release ZIP; no Rust
installation or container runtime is needed. Run `init` beside the verified bundle
to create private detector settings for a selected mount. Full audit
uses the bundled pinned Linux collectors with externally configured runtime inputs.
No native Windows executable is built or distributed. Linux requires glibc
compatible with Ubuntu 24.04. Preserve license notices when redistributing.

[Audit setup](docs/audit.md) · [Usage](docs/getting-started.md) ·
[Report format](docs/report-format.md) · [Distribution](docs/distribution.md) ·
[Library interfaces](docs/interface-reference.md) · [Contributing](CONTRIBUTING.md) ·
[Security](SECURITY.md) · [License](LICENSE) · [Notices](NOTICE)

See [Security model and coverage](docs/security-model.md) before interpreting a
passing audit as evidence. It documents trust boundaries, implemented controls,
resource limits and checks requiring separate tools or evidence.
