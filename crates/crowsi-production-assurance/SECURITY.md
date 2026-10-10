# Security policy

- Private keys and provider credentials are never accepted by this package.
- Every evidence item is signed, role-bound, target-bound, time-bounded, and closed.
- Simulation evidence is rejected by the production evaluator.
- One signing key cannot satisfy two independent evidence roles.
- Missing, stale, conflicting, or unverifiable evidence is blocked.

Production approval additionally requires the physical device, independent network
path, provider adapter, and drill referenced by the evidence to be inspected.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
