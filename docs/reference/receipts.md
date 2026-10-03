# Receipt commitments and typed lookups

The [pinned source](protocol-sources.md), [canonical models](../../src/session/receipts.ts)
and [RPC validators](../../src/rpc/receipts.ts) define this implemented API.
All quantities are checked bigint; discriminants, status and failure codes are
bounded integer numbers. Buffers are detached copies. Fixed diagnostics contain
no remote payloads or secrets.

## Canonical commitments

`@resilience-network/sdk/session` and the root entry export:

- `receiptCounterDeltaCodec`: exactly 74 bytes, V1. u16 version, seven u8 fields
  (mode, action, nonce/attempt/success/claim deltas, value category), two u256
  amounts (value, fee), one canonical boolean (succeeded). Non-session deltas
  consume one or two nonces and fees with zero session counters. SESSION consumes
  one attempt even on failed execution; failed/cancelled actions consume no success
  or value. Successful claim-rewards consumes a claim. Categories mirror native
  transfer/call/create, stake, delegate, unstake and reward accounting. The model
  accepts all pinned native action codes; it does not extend the supported intent
  or policy grammar. `receiptCounterDeltaHash` hashes the canonical bytes under
  `RESILIENCE_RECEIPT_COUNTER_DELTA_V1`, without a chain-domain prefix.
- `authorizationEventCodec`: exactly 303 bytes, V1. Includes its u16 type, owner,
  actor, grant/related/config/policy identities, epoch/nonces/height, transaction
  ID, two u256 amounts, status and failure code. All 14 native event types and
  source identity/status rules are covered. `authorizationEventsRoot` accepts
  0–2 ordered events. Empty is zero, singleton is Keccak(event bytes), pair is
  Keccak(left hash || right hash). A pair must be linked attempt/cancel events;
  a standalone cancel is invalid. This checks a commitment, not a receipt proof.
- `sessionDecisionCommitmentCodec`: exactly 387 bytes, with no version/wrapper.
  Mirrors the internal Go `sessionDecisionSeal` preimage: sender/intent/grant,
  epoch/session nonce/policy/action, maximum fee/debit/reserved value/category,
  both presence-tagged bucket states, matched-rule presence/index, runtime code
  limit/constraint count/inspected bytes/proof-node count, target-code
  presence/address/hash and evaluation height. Absent buckets still encode their
  fixed 40-byte state. `sessionDecisionCommitmentHash` uses
  `RESILIENCE_SESSION_DECISION_V1`, with no extra chain-domain prefix. Structural
  checks mirror native decision action/identity rules. This is a commitment
  inspection API: Chain has no public decision decoder/RPC decision projection.
  Computing this hash does not evaluate policy, verify grant/signature/state,
  or create a node-authorized reservation/seal. Real decision authority requires
  native `EvaluateSessionPolicy` and processor verification.

Unknown enumerable fields, unsupported versions, invalid identities/discriminants,
noncanonical booleans, truncations and trailing bytes fail closed as `CodecError`.
No golden values or wire compatibility fallbacks are introduced.

## Typed transaction and receipt reads

`ChainRpcClient.getTransactionByHash(id, options?)` returns
`TransactionObservation`. `getTransactionReceipt(id, options?)` returns
`ReceiptObservation` and fetches both receipt and transaction in the same bounded
identity bracket. Each requires a nonzero 32-byte transaction ID and trusted
expected chain/genesis/capability in the constructor. Options accept AbortSignal
and optional `canonicalTransaction` bytes; these are copied and locally decoded,
then their canonical ID must equal the requested ID before network dispatch.
With those bytes, returned projections must also match sender/destination,
action/data/value/gas/bids, nonce/sponsor and envelope authority fields.

```ts
const observation = await client.getTransactionReceipt(transactionId, {
  canonicalTransaction: signedCanonicalBytes,
  signal,
});
if (observation.status === "reported-included") {
  const { actionStatus, actualFee, counterDelta } = observation.receipt;
  // actionStatus=0 still retains consumed nonce, fee and SESSION attempt.
}
```

A null transaction gives `status:"unknown"`, `transaction:null`. A present
transaction with all three block-position fields null gives
`status:"reported-pending"`. A complete position gives `reported-included`.
A null receipt always gives `status:"unknown"`, `receipt:null`, retaining any
transaction projection. Node lookups scan a bounded recent window (up to 1,001
heights, including both endpoints); null cannot prove an old transaction never
existed, was rejected or can safely be resubmitted. No automatic send occurs.

Included receipts retain successful/failed action status separately from their
presence. Validators check exact required/optional fields, fixed widths/quantity
encodings, receipt/transaction IDs and positions, observed head bounds, sender,
destination, authorization mode/credential/epoch/nonce/policy, sponsorship, gas
and fee relations, failure classification and logs. Native event bytes/types,
transaction/height/status links, action-to-event sequence and computed event root
must agree. SESSION attempt fee/value and post-consumption session nonce are
cross-checked; the reconstructed exact counter delta must match `counterDeltaHash`.
Sponsorship consumes two nonces; native SESSION+sponsor is rejected. Some event
owners differ from senders (cleanup/recovery); the actor binds those senders.

Limits: 4,096 logs/receipt, 4 topics/log, 65,536 data bytes/log or transaction input,
2 native events, 303 bytes/event. Transport response-byte/depth/item limits also
apply. These are bounded SDK observation limits, not new consensus rules. Pinned
RPC emits a zero-filled 256-byte bloom placeholder; the model retains/checks that
format and does not claim Ethereum bloom verification.

Moving finalized context refreshes the entire observation under the same deadline
and bounded constructor refresh count. Malformed results still fail before refresh.
The final accepted bracket requires consistent chain identity/state and valid
positions. Errors are sanitized `RpcContractError`/`RpcClientError`. Stable older
receipt positions are cross-checked with transaction observations, without
independent block-header authentication. Every observation explicitly reports
`verification:"node-observation"`. A malicious node can forge mutually consistent
responses. This API does not verify inclusion/state proofs, validator certificates
or independently authenticated finality. [Submission/reconciliation](submission.md) adds explicit same-ID outcomes and
bounded polling; node-observation trust still applies.

## Independent evidence

[Native commitment producer](../../tests/go-receipt-reference/commitments_test.go)
uses production counter/event codecs and internal decision seal/shape validation.
Its test-only decision decoder is explicitly a commitment oracle. Independent
[fixtures](../../tests/fixtures/receipt-commitments.json) and
[native checker](../../scripts/check_receipts.mjs) cover every truncated length,
canonical hashes and seeded mutations. [RPC fixture producer](../../tests/go-rpc-reference/receipts_test.go)
uses actual Handler/API against owned constructed receipt/state fixtures, including
success/failure, DIRECT/ROOT, both SESSION schemes, sponsorship and cancellation.
It proves projection behavior; it does not prove funded execution. The structural
cancellation test signature is declared in fixture provenance. [Tests](../../tests/receipts.test.mjs)
add schema deletions/mutations, actual Node HTTP concurrency, context refresh,
input snapshots and abort/deadline checks. Funded native lifecycle remains a
separate [testing gate](../guides/testing.md).
