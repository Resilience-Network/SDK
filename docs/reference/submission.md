# Submission and bounded reconciliation

[ChainRpcClient](../../src/rpc/methods.ts) provides implemented submission and
same-ID reconciliation. [Outcome types](../../src/rpc/submission.ts),
[block projection checks](../../src/rpc/blocks.ts) and
[tests](../../tests/submission.test.mjs) define the contracts. These APIs observe
an explicitly trusted node; they do not authenticate validator certificates,
receipt/state proofs or native block-header hashes independently.

## Single send

`submitTransaction(canonicalTransaction, { signal? })` copies and validates
canonical Transaction V2 bytes and computes their ID using the constructor's
trusted expected chain/genesis before any await. It checks identity/capability
in a bounded read bracket, then sends exactly one `rsc_sendRawTransaction` request.
One overall constructor timeout covers preflight and send. No signing, replacement,
redirect following or write retry occurs. Read retries remain separately bounded.
The returned hash is always the locally computed ID; the node's successful result
must be an exact matching 32-byte hash.

`SubmissionOutcome.status` distinguishes:

- `reported-accepted`: node returned the expected ID; this is not inclusion,
  action success, durable pool acceptance or independently verified finality.
- `reported-rejected`: that attempt received a valid node error. A duplicate-pool
  rejection can coexist with an earlier accepted transaction. The error does not
  prove this ID never existed or that the nonce can be reused.
- `unknown`: an attempted send lost/failed/malformed its response, returned a
  conflicting hash or exceeded its budget. Treat acceptance/consumption as uncertain.
- `not-sent`: this SDK invocation failed/aborted preflight or rejected the request
  before dispatch. It says nothing about earlier invocations or external sends.

`sendAttempts` is 0 or 1 for the write, excluding preflight reads. `verification`
is always `node-observation`. Optional diagnostics retain only fixed sanitized
SDK codes, a numeric RPC code and known authorization-family token. URLs, remote
messages/data, payloads, private abort reasons and causes are discarded. Invalid
canonical arguments throw `RpcContractError("INVALID_ARGUMENT")` before RPC.
Caller-initiated separate calls can send the same bytes again; the SDK does not
silently deduplicate authorized explicit invocations or turn a retry into a new
signature. Higher-level nonce coordination owns exclusive flow management.

## Caller-controlled reconciliation

`reconcileTransaction(canonicalTransaction, options?)` recomputes/copies the same
canonical bytes/ID and performs reads only. Defaults: 30,000 ms overall budget,
10 polls and 250 ms between polls. Limits: timeout 1–300,000 ms, polls 1–1,000,
interval 1–60,000 ms. Constructor per-read HTTP retry/context-refresh bounds also
apply. Cancellation/deadline covers all reads and delays, even if injected fetch
ignores its signal. Late promises have rejection handlers; timers/listeners are
cleaned up. Invalid options fail before dispatch.

Each poll reads a [bound receipt/transaction observation](receipts.md), followed
by a separately consistent finalized authority/nonce bracket. DIRECT reads its
account nonce and current mode; ROOT checks epoch/config and root nonce; SESSION
checks current root epoch plus exact grant/key scheme/policy, generation,
canonical usage and session nonce. Expiry/stale epoch is explicit in
`authorityMatches:false` / `comparison:"authority-changed"`. Other comparisons
are `unchanged`, `advanced`, or `behind`; they are observations, never a reusable
nonce permission. Sponsored flows also observe the sponsor account nonce.
Missing/cleaned/unsupported grant observations conservatively yield unknown with
an observation diagnostic. No legacy credential fallback occurs.

For included receipts, reconciliation obtains the matching pinned block projection
by number with transaction hashes, checks full field shapes/bounds and exact hash,
position, transaction ID and state context. The node's finalized head must cover
that block. Success returns `reported-finalized-success`; failed included execution
returns `reported-finalized-failure`, retaining the complete receipt/counter delta.
Current matching authority must show nonce advancement; sponsor nonce advancement
is also checked. A legitimately changed authority domain is preserved explicitly.
Finalized observations cannot move backward; equal-height state tuples must agree.
Each logical bracket may refresh within the existing bound on a moving head.

These are node-reported finality outcomes, not independent proof verification.
Block projection fields such as nonce, bloom, difficulty/size and decimal
slot/round/epoch follow the [immutable baseline](protocol-sources.md). The SDK
checks those projections without inventing omitted native-header/certificate data.

Budget exhaustion, abort or unavailable/pruned history returns `status:"unknown"`
with reason `poll-limit`, `deadline`, `aborted` or `observation-error`, poll count,
last receipt observation (if any), authority observation (if any) and sanitized
diagnostic. Missing block lookup can leave a reported included receipt without
terminal confirmation. An advanced nonce alone cannot identify which transaction
consumed it. Unknown lookup cannot prove non-inclusion, permit automatic nonce
reuse, or authorize a new signature. The historical receipt/transaction window
remains bounded; see [receipt contracts](receipts.md).

```ts
const sent = await client.submitTransaction(signedCanonicalBytes, { signal });
// Preserve the same signed bytes and locally known ID across ambiguous results.
const result = await client.reconcileTransaction(signedCanonicalBytes, {
  signal,
  timeoutMs: 30_000,
  maxPolls: 20,
  pollIntervalMs: 500,
});
if (result.status === "reported-finalized-failure") {
  // Fee/nonce and SESSION attempt consumption remain in result.receipt.counterDelta.
}
```

For unknown results, retain the same canonical bytes/ID and reconcile again with
an explicit new caller budget, inspect the trusted node and authority state, or
escalate through the application. Never blindly re-sign/reuse the nonce or erase
wallet/node/signing evidence. This method itself never invokes submit or a signer.

## Native and transport evidence

[Native reconciliation producer](../../tests/go-rpc-reference/reconciliation_test.go)
and [fixtures](../../tests/fixtures/rpc-reconciliation.json) extend the native RPC
gate with real rooted/grant state, cryptographic policy evaluation and session
usage settlement for Ed25519/P-256 and cancellation. DIRECT/sponsor nonces and
receipts/blocks are explicitly constructed. Cancellation is signed with the
pinned reference test-only seed and checked by native evaluation. This is native
state/projection evidence, not a running node, block-processor transfer/fee
execution, pool acceptance or independent finality proof. Original receipt and
commitment fixtures are unchanged. [Feature tests](../../tests/submission.test.mjs)
cover response loss/rejection/pending/pruning, canonical snapshots, no hidden
resends, failed consumption, state/nonce/block contradictions, bounds and
cancellation. Actual Node HTTP drops the write response after recording the bytes,
then reconciles the same ID with one write total. Funded native lifecycle remains
separate in [the testing guide](../guides/testing.md).
