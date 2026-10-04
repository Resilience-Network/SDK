# Account and session lifecycle

`SessionLifecycle` composes canonical actions, validated state reads, an explicit
canonical review, external raw signers, `NonceCoordinator`, one submission and
bounded same-ID reconciliation. It owns no private keys and creates no custody
service. All state/finality assertions are trusted-node observations.

Construct it with `{context, client, coordinator}`. `context` is exactly
`{chainId, genesisHash}` from trusted deployment configuration; configure the
`ChainRpcClient` with the same identity and authorization capability. Supply a
linearizable durable reservation adapter for production. The memory adapter is
limited to a single shared instance/process and does not survive crashes.

Call `execute({owner, operation, gasLimit, maxFeePerGas,
maxPriorityFeePerGas, reservationId, approve, signal?, timeoutMs?,
reconciliation?})`. Required `approve` receives the frozen canonical signing
review; only literal `true` approves it. Use the canonical review fields in the
UI, including action data, thresholds, validity, policy, fees and reserve.
Approval occurs before reserving/signing, so rejection cannot strand a nonce.
After approval the helper reads the same authority before reservation, signing
and sending. It never silently refreshes a reviewed nonce, epoch, key or policy.

Whole-flow timeout is 1–300000 ms (default 30000), including approval, reads,
signing, reconciliation and the post-read. Reconciliation budgets have the
[submission API](submission.md) bounds. Callbacks that ignore cancellation do not
extend the overall budget. Mutating inputs or callbacks across an await aborts
the flow. Once signing may have started, cancellation/failure preserves the
coordinator's signing/signed/uncertain record; use explicit read-only recovery.
A failed or uncertain write never makes the nonce reusable automatically.

## Operations

- `activate`: `config`, `securityReserve`, external Ed25519 `signer`. Starts with
  a funded DIRECT account, matches the signer-derived owner, and irreversibly
  activates ROOT authority. Rereads initial epoch/nonce/sequence/count/config and
  the consumed DIRECT account nonce after reported finalization.
- `create-grant`: exact `grant: GrantSpec`, selected ROOT `signers`. Checks
  validity against candidate height, lifetime, protocol minimum reserve, active
  slot/sequence bounds, root/session key separation and the exact deposit.
- `transfer`: exact `credential: SessionSigningCredential`, `signer`,
  `destination`, `value`, optional `recipientProof`. Both native Ed25519 and raw
  prehashed P-256 adapters are supported. `sessionCredentialFromGrant(observation)`
  copies the public credential; a changed cached credential requires fresh review.
  Checks observed activation/epoch/expiry, key/policy/nonce, attempts, per-action
  and lifetime value/fee limits, checked buckets, recipient membership, zero/self
  transfer flags and maximum debit above the reserve before review/signing.
- `revoke-grant`: `grantId`, ROOT `signers`. Requires current-epoch grant state.
- `replace-grant`: `oldGrantId`, exact `newGrant`, ROOT `signers`. Binds the old
  grant and refunded/new deposits; returns the new derived grant ID and rereads
  its canonical fields. Same-key replacement is valid; sequence changes its ID.
- `revoke-all`: ROOT `signers`. Advances epoch and root nonce, resets active
  count, and leaves old records/deposits available for bounded cleanup.
- `rotate-root`: `config`, `reserveMode`, `replacementReserve`, old ROOT
  `signers`. Advances epoch, resets root nonce and active count, and checks the
  selected reserve. Preserve mode requires replacement reserve zero. Removing
  an adapter/key locally does not revoke on-chain authority.
- `set-reserve`: `securityReserve`, ROOT `signers`. With active grants, rejects
  below the protocol minimum; checks balance after maximum fee.
- `cleanup-grant`: `grantOwner`, `grantId`, `authority` selected as either
  `{mode:0, signer}` or `{mode:1, signers}` for the cleaner account. Requires an
  observed expired/current grant or old epoch. Rechecks cleaner and target within
  a common finalized context with at most four attempts. This does not reset the
  owner or delete local safety state.

ROOT selections contain exactly the configured threshold of distinct current
keys. Sponsored transactions and policy actions beyond the implemented
transfer-only grammar are unsupported. SESSION_CANCEL is a separately available
canonical action for consuming a nonce/fee attempt; it does not revoke a grant.
Use ROOT revocation to remove authority.

`requiredGrantStorageDeposit(parameters)` implements the pinned stored-grant,
usage and trie/index byte-size formula and minimum. Supply the exact resulting
value explicitly in `GrantSpec`. `MINIMUM_SECURITY_RESERVE` is 10^17 base units;
`MAX_SESSION_LIFETIME_BLOCKS` is 432000. `refilledBucketAvailable` checks u64/u256
inputs and rejects multiplication/addition overflow before capacity capping.
The native execution result remains authoritative. The public RPC has no complete
active-key/stored-record census; duplicate active session keys and the total
stored-record cap can still cause an included action failure.

## Outcomes and recovery

Every returned result retains `flow` (reservation, submission, reconciliation),
the exact `review` and `verification:"node-observation"`:

- `postcondition:"reported-state"`: reported finalized success plus a fresh
  authority/grant read matching the operation's expected semantic changes.
  Creation/replacement additionally returns `createdGrantId` and `grant`.
- `"included-failure"`: reported finalized action failure; nonce/attempt/fees
  remain consumed as specified by the receipt. No successful state is claimed.
- `"not-finalized"`: reconciliation remains unknown. Preserve bytes/reservation
  and recover the same ID through the coordinator without signing/resending.
- `"unknown"`: receipt reports finalized success but a subsequent observation
  fails, exceeds the remaining budget or differs (including concurrent controls).
  The result still retains the receipt and consumed reservation.

These results do not prove finality, noninclusion, remote honesty or absence of a
pruned/revoked credential. Revoke/cleanup postchecks validate the changed authority;
a missing-grant RPC error alone is never proof of removal. Missing or revoked
grants fail reads before signing. Long-delayed transfer reconciliation after
another actor removes a grant can remain unknown; retain the signed record.

`LifecycleError` exposes fixed codes only. Initial invalid options, denied state,
stale authority, mutation, approval failure/rejection and bounded cancellation
never include raw adapter/node text. A read/coordinator failure can throw after
signing has started: inspect persisted reservations before attempting another flow.

Use `client.simulateAuthorizedTransaction(canonicalSignedBytes)` for optional
advisory simulation. It requires an actual signature and may report an authorized
failed action. Simulation is read-only and advisory; it is not approval, inclusion,
reconciliation or permission to discard a signed reservation.

Source: [lifecycle](../../src/session/lifecycle.ts),
[policy screening](../../src/session/lifecycle-policy.ts),
[stateful tests](../../tests/lifecycle.test.mjs),
[funded native runner](../../scripts/check_lifecycle.mjs),
[immutable source pin](../../protocol-source.json).

## Native verification

```sh
RSC_CHAIN_DIR=/absolute/pinned/chain npm run test:lifecycle-native
```

The owned four-node native network starts from funded DIRECT genesis, then runs
activation; grant/transfer/revoke for both schemes; same-key replacement;
reserve changes; revoke-all; bounded cleanup; root rotation and use of the new
root. It checks finalized typed receipts, post-state, session usage and denial of
revoked keys before their signer is invoked. This is distinct from mocked
stateful unit tests. The wider replay/expiry/failure/concurrency qualification
remains tracked by [SDK #29](https://github.com/Resilience-Network/sdk/issues/29).
See the [native harness guide](../guides/native-localnet.md) for ownership,
retained failure evidence and exact source/runtime requirements.

External adapter/callback failures are reconstructed with bounded supported codes
and fixed messages. Modified SDK error instances, invalid codes, throwing code
getters and prototype traps do not forward caller messages, causes or objects.
Constructor inspection failures produce `INVALID_ARGUMENT`. This normalization
does not release signing/signed/uncertain reservations or imply safe resubmission.
