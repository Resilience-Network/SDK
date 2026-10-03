# Disposable native session example

[Executable source](../../examples/session-localnet.mjs) uses actual SDK APIs
with a funded, independently initialized pinned native four-validator network.
It creates fresh test keys/state and requires native Go/Rust/CGO; existing wallet,
node, validator signing and database state is outside the run's ownership.

```sh
npm ci
RSC_CHAIN_DIR=/absolute/path/to/pinned-chain npm run example:session
RSC_CHAIN_DIR=/absolute/path/to/pinned-chain npm run test:lifecycle-native
RSC_CHAIN_DIR=/absolute/path/to/pinned-chain npm run test:session-e2e
```

The example activates DIRECT Ed25519 ownership into a selected ROOT config and
reserve, creates a bounded grant, waits for the authoritative validity height,
transfers through a raw session signer, observes finalized receipt/current state
and revokes the grant through ROOT. It repeats for Ed25519 and raw prehashed P-256.
An application must replace test key generation/closures with its own external
signer and explicit user review; the example's automatic approval is test-only.
The SDK does not custody keys or turn a passkey assertion into a native signature.

`SessionLifecycle` requires explicit fees, credential, reservation ID and frozen
canonical review approval. No nonce/context refresh or re-sign is automatic.
Simulation is advisory and must leave authority, counters and balances unchanged.
Fresh post-finalized reads report observed state; receipts/authority are trusted
node reports, with canonical commitments checked locally and no independent
consensus proof. Finalized action failure still consumes its authorized nonce
and actual fee. SESSION failure additionally consumes an attempt, with no value
or success consumption. ROOT nonce is distinct from the account nonce.

The [adversity suite](../../scripts/check_session_end_to_end.mjs) deliberately
uses a maximum-balance test recipient to induce supported transfer execution
failure. It checks both session schemes, DIRECT/ROOT settlement, exact replay,
expiry, revoke-all/old-root epoch, explicit unsupported P-256 DIRECT/ROOT bytes,
wrong identity/key/grant/policy/nonce, rejected recipients/limits, simulation
rollback and SESSION_CANCEL semantics. Cancel consumes an attempt/fee without
removing the grant; ROOT revocation/epoch changes remove authority.

A held signer serializes two actual lifecycle attempts through one memory store:
the loser receives the lifecycle's sanitized FLOW_FAILED wrapper around contention
and signs/sends nothing. The slot remains owned by the first flow. This guarantees
one process sharing that adapter; other tabs/processes require a linearizable,
durable application adapter as described in [coordination](../reference/coordinator.md).

A real loopback proxy forwards one signed write then drops its HTTP response and
keeps read responses unavailable for initial reconciliation. Recovery uses a
healthy endpoint; this test does not rely on a millisecond timeout race.
Submission is unknown; the signed reservation remains uncertain, and a competing
flow cannot reuse it. Explicit coordinator reconciliation uses persisted bytes
and reads only, observes the same finalized ID and marks consumption. It never
signs/resends to infer what happened. Missing/pruned receipts remain uncertain.

[Owned harness evidence](native-localnet.md) records exact SDK/Chain revisions,
toolchains, public generated genesis, commands/checks, redacted log sizes/hashes
and closed owned handles. Successful runtimes are removed only through verified
ownership checks; failed/interrupted runtimes, keys/DB/signing records remain
restricted and retained. Known generated test-key/closure-secret strings are
checked against public log evidence. Never reuse disposable keys/genesis for
valuable assets. Browser/device/security-review/publication gates remain separate.
