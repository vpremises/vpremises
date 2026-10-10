# Security boundary

- Inputs are regular, size-bounded JSON files with closed fields.
- Outputs contain environment identifiers and counts, never addresses, packet
  content, credentials, customer data, or Incus certificates.
- The repository has no mutation adapter and always reports
  `external_actions: false`.
- A live collector must run separately with least-privilege read access and
  provide only the common input contract.
- Control coverage is evidence of reachability and readiness, not a claim that
  every intrusion can be detected. Missing or stale sensors fail honestly.
- A production adapter must authenticate and sign observations; this crate
  deliberately performs no trust establishment or network enforcement.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
