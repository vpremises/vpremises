# crowsi-incident-coordinator interface reference

Use the [usage guide](getting-started.md) for the first steps. This reference preserves the current interface details and operational limits. Run command examples from the repository root, after preparing the exact declared dependencies and registered configuration.

## Trust boundaries

- Events bind to the incident's pinned owner authority, deployment, incident, epoch, and short validity interval.
- Identity, intent, policy decision, and grant signatures are verified with exact subject/device/workload/proof-key/revocation/resource/action/channel matching.
- Production construction requires an externally pinned canonical trust-bundle digest with deployment and revision.
- PEP, verifier, recovery authority, incident owner, IdP, Policy Administrator, checkpoint authority, and anchor authority have separate roles and scopes.
- Production uses the internal system clock; simulation and production clock APIs are separate.
- Replay JTIs, authorization reservations, approval IDs, evidence JTIs, and restore attempts are retained in durable state.

## Production persistence

`IncidentCoordinator::new` requires a checkpoint commit before use. Production `apply` stages a complete `pending_outbox` and blocks the next event. The caller then:

1. Reads `export_state`.
2. Obtains a checkpoint-authority signature over `CoordinatorCheckpointV1`, including state digest, sorted unique command digests, trust pin/revision, and previous checkpoint digest.
3. Obtains a short-lived independent monotonic-authority signature over `ExternalMonotonicAnchorV1`, bound to the coordinator's one-use OS-CSPRNG challenge.
4. Updates the deployment/incident durable head through linearizable CAS.
5. Calls `confirm_checkpoint_commit` with an authenticated exact-current-head reader.

Only step 5 releases `CommandReleaseV1`. Consumers verify checkpoint membership for each canonical command digest. Rollback, divergent branches/deployments, trust substitution, stale challenges, and signing-role confusion are rejected.

`MonotonicHeadReaderV1` must read the exact durable head. Restore additionally requires an external trust pin, fresh challenge, signed checkpoint/anchor, and exact current head. `restore_simulation` is not a production restore path.

## Command release integration

`CoordinatorCommandV1` and `CommandReleaseV1` require `AtomicReleaseConsumerV1` to reserve `(head, command_digest)` exactly once in a linearizable transaction/lease. The Policy Administrator then revalidates the authorization ledger and binds reservation, deployment/security domain, incident, head sequence/digest, fence, grant JTI, expiry, and expected resource version into a signed downstream command. The effect owner rechecks fence, revocation, expiry, one-use, and resource-version CAS at mutation and returns a signed receipt.

The current `crowsi-control-contracts` `IsolationCommandV1` lacks this release/fence binding. Production isolation remains blocked until the v2 contract, PA ledger, and PEP/provider adapter are connected. Source publication does not close this deployment gate.

## State and schemas

Persist complete `CoordinatorStateV1`, including replay sets, authorization reservations, used approval/evidence, pending recovery, monitoring evidence, and pending outbox. Schemas are closed Draft 2020-12 documents; tests check IDs, required/property agreement, serialization shapes, and event tags.

```bash
cargo test --locked --offline
```

Configure the declared private Cargo registries before running offline verification. See [SECURITY.md](../SECURITY.md) for operational requirements and remaining risks.
