# Typed Chain RPC methods

`ChainRpcClient`, `AUTHORIZATION_CAPABILITY`, `RpcContractError` and their types
are exported by `@resilience-network/sdk/rpc` and the root entry. It uses the
[bounded transport](http-rpc.md) and immutable [source pin](protocol-sources.md).
[Methods](../../src/rpc/methods.ts), [validators](../../src/rpc/validate.ts),
[types](../../src/rpc/contracts.ts), [contract tests](../../tests/rpc-methods.test.mjs)
and [HTTP tests](../../tests/rpc-methods-http.test.mjs) define the API.

```ts
import {
  ChainRpcClient,
  AUTHORIZATION_CAPABILITY,
  hexToBytes,
} from "@resilience-network/sdk";

// deployment comes from trusted application configuration, not this RPC node.
const client = new ChainRpcClient({
  url: deployment.rpcUrl,
  expected: {
    chainId: deployment.chainId, // bigint
    genesisHash: hexToBytes(deployment.genesisHash), // exactly 32 bytes
    authorizationCapability: AUTHORIZATION_CAPABILITY,
  },
});
const snapshot = await client.getAuthorizationSnapshot(ownerBytes, grantIdBytes, {
  signal: controller.signal,
});
console.log(snapshot.identity.state.height, snapshot.grant.usableAtObservedBlock);
```

## Identity, contexts and bounds

Every operation requires app-supplied chain ID (u64 bigint), genesis hash and
capability `resilience/tx-auth/2`. Configuration is copied at construction; no
trust-on-first-use or cached identity exemption exists. Each logical read batches
identity, requested method(s), then identity again. Both identities must match
trusted configuration. Their finalized block hash, height and state root must
agree; state-bearing results must report the same tuple. Node observations are
not independently authenticated proofs. Returned buffers are owned copies;
readonly types do not prevent an app from modifying its own buffers.

Batches do not provide node-level atomic snapshots. Changing contexts cause
whole-read refreshes: `maxContextRefreshes` defaults to 1, accepting 0–3 extra
batches. Malformed data and identity mismatches fail without refresh. Refreshes
use fresh IDs and current finalized reads, with no unsupported historical
authorization selectors. Transport retries remain limited to allowlisted reads.
One overall logical `timeoutMs` spans batches, bodies and backoff. The largest
batch has six calls; typed-client `maxBatchSize` must be 6–32. Other transport
bounds apply. Estimation/simulation get one logical batch with no automatic
refresh or transport retry; a changed head requires explicit app reevaluation.

Estimation, simulation and fees carry `advisory: true`. They establish neither
admission, inclusion, finalized action success nor authority at a future block.

## Methods and pinned handlers

Inputs use `Uint8Array` bytes and `bigint` integers. `options?` contains the caller
AbortSignal. Wire spelling is always `rsc_`, including registered `eth_` aliases.

- `getAuthorizationFinalityStatus(options?)` calls
  `rsc_getAuthorizationFinalityStatus([])`: identity/capability and finalized state.
  [Handler](https://github.com/Resilience-Network/Chain/blob/773d20810e46a67e2cc68a3e58df7c08e5ac3784/internal/rpc/authorization_api.go#L302).
- `getRootAuthority(owner20, options?)` calls `rsc_getRootAuthority([ownerHex])`:
  DIRECT/mode 0 requires null authority; ROOT/mode 1 returns epoch, root nonce,
  grant sequence/count, reserve, config/hash and canonical stored authority.
  Ed25519 points, key ordering/IDs, config hash and full bytes are cross-checked.
  [Handler](https://github.com/Resilience-Network/Chain/blob/773d20810e46a67e2cc68a3e58df7c08e5ac3784/internal/rpc/authorization_api.go#L68).
- `getSessionGrant(owner20, grantId32, options?)` calls
  `rsc_getSessionGrant([ownerHex, grantIdHex])`: canonical grant/policy, scheme/key,
  validity, nonce/usage, deposit and index/usability. Ed25519/32-byte and P-256/
  64-byte X||Y keys are supported. Derives grant ID with expected chain/genesis,
  owner, epoch, generation and key; checks policy hash, full stored bytes, exact
  deposit, validity and usage/bucket invariants.
  A standalone grant read cannot cross-check the current root epoch; use the snapshot.
  [Handler](https://github.com/Resilience-Network/Chain/blob/773d20810e46a67e2cc68a3e58df7c08e5ac3784/internal/rpc/authorization_api.go#L112).
- `getSessionNonce(owner20, grantId32, options?)` calls
  `rsc_getSessionNonce([ownerHex, grantIdHex])`: state, owner/ID, exact nonce and
  usability. This subset cannot check root epoch or canonical grant.
  [Handler](https://github.com/Resilience-Network/Chain/blob/773d20810e46a67e2cc68a3e58df7c08e5ac3784/internal/rpc/authorization_api.go#L169).
- `getSessionUsage(owner20, grantId32, options?)` calls
  `rsc_getSessionUsage([ownerHex, grantIdHex])`: state, owner/ID, policy hash and
  usage. Checks supported counter shapes/widths; policy limits and bucket
  configuration require full grant or snapshot.
  [Handler](https://github.com/Resilience-Network/Chain/blob/773d20810e46a67e2cc68a3e58df7c08e5ac3784/internal/rpc/authorization_api.go#L181).
- `decodePolicy(canonicalPolicy, options?)` calls `rsc_decodePolicy([canonicalHex])`:
  bytes, policy view and computed hash must match the requested bytes.
  [Handler](https://github.com/Resilience-Network/Chain/blob/773d20810e46a67e2cc68a3e58df7c08e5ac3784/internal/rpc/authorization_api.go#L35).
- `previewPolicy(canonicalPolicy, options?)` calls `rsc_previewPolicy([canonicalHex])`:
  also checks exact derived action (`TRANSFER`), warnings and security notice.
  Reachable warnings describe maximum u64 attempts and required Merkle proofs.
  Zero lifetime fee limits are rejected by the codec.
  [Handler](https://github.com/Resilience-Network/Chain/blob/773d20810e46a67e2cc68a3e58df7c08e5ac3784/internal/rpc/authorization_api.go#L45).
- `getFeeSuggestions(options?)` batches `rsc_gasPrice([])` and
  `rsc_maxPriorityFeePerGas([])`: bigint suggestions and bracketed identity.
  These handlers report no state; that context does not prove fee provenance.
  [Handlers](https://github.com/Resilience-Network/Chain/blob/773d20810e46a67e2cc68a3e58df7c08e5ac3784/internal/rpc/api.go#L1024).
- `getFeeHistory({blockCount, newestBlock, rewardPercentiles?}, options?)` calls
  `rsc_feeHistory([countHex, newestHexOrLatest, percentiles])`: count 1–64; newest
  u64 bigint or `"latest"`; SDK cap of 64 finite percentiles in [0,100], preserving
  order. Checks clamped range/oldest block, count+1 base fees, count gas ratios
  in [0,1] and reward matrix dimensions. Fees/rewards are bigint; ratios are
  approximate numbers. Identity brackets the advisory query.
  [Handler](https://github.com/Resilience-Network/Chain/blob/773d20810e46a67e2cc68a3e58df7c08e5ac3784/internal/rpc/api.go#L1082).
- `estimateAuthorizationGas(canonicalTransaction, options?)` calls
  `rsc_estimateAuthorizationGas([signedV2Hex])`: supported canonical V2 transaction
  with expected chain ID; positive authorization gas within declared gas limit;
  candidate height = observed height+1 and exact stale-state warning. This is
  authorization gas, not total gas or SDK signing.
  [Handler](https://github.com/Resilience-Network/Chain/blob/773d20810e46a67e2cc68a3e58df7c08e5ac3784/internal/rpc/authorization_api.go#L232).
- `simulateAuthorizedTransaction(canonicalTransaction, options?)` calls
  `rsc_simulateAuthorizedTransaction([signedV2Hex])`: also binds transaction ID/
  sponsor to request, checks status/failure codes, gas, fee arithmetic, widths,
  event count ≤2 and version/type/303-byte framing. `authorized: true` can have
  action status 0/failed. Counter-delta/event-root hashes and full event semantics
  remain observations pending independent receipt verification in #16.
  [Handler](https://github.com/Resilience-Network/Chain/blob/773d20810e46a67e2cc68a3e58df7c08e5ac3784/internal/rpc/authorization_api.go#L252).

`getAuthorizationSnapshot(owner20, grantId32, options?)` composes root/grant/nonce/
usage in one logical batch. Compares contexts, nonce/usability, policy hash and
all counters, then derives usability from root epoch and validity. Revoke-all
keeps old grant/index records readable, with usability false when epochs differ.
Existence or `activeIndexPresent: true` alone never establishes current authority.
Validity is `validAfter <= observed < validUntil`. Missing credentials throw the
node error; they are not converted to null.

## Encodings, scope and errors

Quantities are lowercase minimal `0x0` or `0x[1-9a-f][0-9a-f]*`, checked for u64/
u256 width before bigint conversion. Complete byte hex accepts either letter
case and requires exact widths where specified. Fixed 32-byte amounts decode big
endian; interpreting them as minimal quantities fails. JSON enums/counts must be
safe integers within pinned bounds; booleans remain booleans. Byte sizes follow
pinned codec bounds.

Transfer-only policies, inline/Merkle recipients and value/fee buckets match the
[canonical scope](canonical-api.md). Other policy sections/actions, recovery,
proofs, EVM calls, submission, receipts, polling and browser signing are outside
this typed API. Every nested unknown field fails closed. Unknown methods remain
available through `HttpRpcClient` with `unknown` results and its fixed retry rules.
No legacy fallback or unsupported selector is added.

Transport/node failures retain `RpcClientError`. For node code -32000, only fixed
`data.family` tokens survive as `authorizationFamily`: `AUTH_MALFORMED`,
`AUTH_UNKNOWN_CREDENTIAL`, `AUTH_UNSUPPORTED_VERSION`, `AUTH_LIMIT_EXCEEDED`,
`AUTH_ACTION_DENIED`, `AUTH_BAD_SIGNATURE`. Unknown families are omitted; all other
remote text/data is discarded. A node classification is not proof of its diagnosis.
`RpcContractError.code` separates `INVALID_ARGUMENT`, `INVALID_RESULT`,
`UNSUPPORTED_RESULT`, `CHAIN_IDENTITY_MISMATCH`, `STATE_CONTEXT_MISMATCH`,
`OBSERVATION_ABORTED`, `OBSERVATION_TIMEOUT`. Fixed messages contain no payload,
URL, node text or cause. Whole-read abort/timeout errors have no misleading HTTP
attempt count. Abort/deadline clean up timers/listeners even if trusted injected
fetch ignores AbortSignal.

## Evidence and remaining gates

[35 native fixtures](../../tests/fixtures/rpc-contracts.json) cover all 12 wire
methods, both grant schemes, DIRECT/ROOT, buckets, revoked stale grants, warnings
and node errors. The [Go producer](../../tests/go-rpc-reference/contracts_test.go)
uses production Handler/API with owned in-memory state. The
[native checker](../../scripts/check_rpc_contracts.mjs) checks the pin, CGO and
exact regenerated results; see [testing](../guides/testing.md). SDK tests include
905 deletion/unknown-field cases plus numeric, canonical/context, deadline,
redaction and real HTTP concurrency cases.

This proves pinned contract interoperability and native simulation fixtures,
not running-network/funded lifecycle finality, P-256 simulation signing, browser
qualification or independent review. Receipt/lookup contracts require
[SDK#40](https://github.com/Resilience-Network/sdk/issues/40) after
[Chain#375](https://github.com/Resilience-Network/Chain/issues/375).
