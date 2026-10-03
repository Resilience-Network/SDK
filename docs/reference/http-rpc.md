# HTTP JSON-RPC transport

`@resilience-network/sdk/rpc` exports `HttpRpcClient`, `RpcClientError`, transport
types and `RETRYABLE_RPC_METHODS`. The root entry reexports them.
[Source](../../src/rpc/index.ts), [envelope tests](../../tests/rpc-contract.test.mjs),
[failure tests](../../tests/rpc-resilience.test.mjs) and
[actual HTTP tests](../../tests/rpc-http.test.mjs) define the implemented contract.

This is an envelope transport. Results have type `unknown`; validate a method's
fields, quantities, canonical bytes and identity before use. [Typed Chain reads](rpc.md)
implement method validation. Receipts and reconciliation follow in
[SDK#16](https://github.com/Resilience-Network/sdk/issues/16) and
[SDK#17](https://github.com/Resilience-Network/sdk/issues/17).

## Requests and batches

```ts
import { HttpRpcClient, RpcClientError } from "@resilience-network/sdk/rpc";

const client = new HttpRpcClient({ url: "http://127.0.0.1:8545" });
const controller = new AbortController();
try {
  const observation: unknown = await client.request("rsc_chainId", [], {
    signal: controller.signal,
  });
  // Validate against trusted deployment configuration before use.
} catch (error) {
  if (error instanceof RpcClientError) {
    console.error(error.kind, error.code, error.attempts);
  }
  throw error;
}

const outcomes = await client.batch([
  { method: "rsc_chainId" },
  { method: "rsc_blockNumber", params: [] },
]);
for (const outcome of outcomes) {
  if (outcome.ok) {
    const untrustedResult: unknown = outcome.result;
  } else {
    const nodeCode: number | undefined = outcome.error.rpcCode;
  }
}
```

Each call gets a numeric ID unique within its client. Notifications and custom
IDs are unsupported. Single responses must be objects; batch responses must be
arrays of the same size with exactly one matching response per ID. Batch outcomes
are returned in caller order. Valid batch node errors are per-call outcomes;
single calls throw them. Invalid envelopes and transport failures reject the
entire operation without returning partial results.

Envelopes require `jsonrpc: "2.0"`, matching IDs and exactly one own `result` or
`error` field. Node errors require a safe integer code and string message. Explicit
null, false, zero and empty results are valid. Missing result, null error,
unknown/string/null/duplicate IDs, duplicate JSON keys (including escaped aliases),
invalid UTF-8 and unsupported JSON fail closed.

Params are JSON arrays or plain objects; omitted params become `[]`. Nested
values must be JSON data: no bigint, undefined, non-finite/unsafe integer numbers,
cycles, sparse arrays, symbols, class instances, getters, serialization hooks or
ignored non-enumerable fields. Use explicit wire strings for protocol integers.
Shared acyclic values are allowed. The complete request is serialized before
dispatch, so later caller mutation cannot change a retry. Method names contain
1–128 ASCII letters/digits, underscores or dots, begin with a letter and exclude
the reserved `rpc.` prefix.

The parser accepts finite fractional numbers and rejects unsafe integer values;
fractions still have JavaScript floating-point precision. It does not convert
quantities to bigint or authenticate observations. Parsed `__proto__` keys are
ordinary own properties and cannot modify prototypes. Treat results as untrusted
when copying them into application objects.

## Bounds

Options are finite safe integers. Defaults and accepted ranges are:

- `timeoutMs`: 10,000; 1–120,000 milliseconds for fetch, body reads and backoff
  together. Input serialization is synchronous and structurally bounded.
- `maxRequestBytes`: 2 MiB; 1 byte–2 MiB, no higher than the pinned node's limit.
- `maxResponseBytes`: 2 MiB; 1 byte–16 MiB. Raise explicitly for larger query
  results. This bounds decompressed stream bytes, not just Content-Length.
- `maxBatchSize`: 32; 1–32, matching the pinned node.
- `maxRetries`: 2; 0–3 extra attempts for allowlisted reads; zero disables retries.
  Every other method gets one attempt regardless of this option.
- `retryDelayMs`: 100; 1–5,000 milliseconds.
- `maxRetryDelayMs`: 1,000; 1–5,000 milliseconds, at least `retryDelayMs`.

JSON has a fixed maximum depth of 64 (root depth zero) and 100,000 values per
envelope or entire batch, including envelope fields. Response streams have at most
65,536 chunks, including empty chunks. UTF-8 bytes and request escape sequences
count toward byte limits. Response buffers grow only to the configured limit.
Oversized declared Content-Length is rejected early; missing or smaller
declarations cannot bypass the stream cap. HTTP error bodies are discarded without
parsing or accumulating them.

## Cancellation and retries

Pre-abort makes zero attempts. Caller abort during fetch, body reads or backoff
rejects with `ABORTED`; deadline expiry rejects with `TIMEOUT`. Each operation owns
and disposes its timer, caller listener, attempt abort controller and reader.
Cancellation settles the SDK promise even when injected fetch ignores AbortSignal;
late responses are cancelled and late promise rejections consumed. A trusted
custom fetch/stream that ignores abort/cancel can retain its own external resources;
the SDK cannot force it to stop.

The fixed [allowlist](../../src/rpc/http.ts) contains `eth_`/`rsc_` aliases for chain
ID, block number, balance, transaction count, code/storage, block and transaction/
receipt lookup, gas-price/tip/fee-history reads and syncing. It also contains
`rsc_getRootAuthority`, `rsc_getSessionGrant`, `rsc_getSessionNonce`,
`rsc_getSessionUsage`, `rsc_getAuthorizationFinalityStatus`,
`rsc_getAuthorizationProof`, `rsc_decodePolicy` and `rsc_previewPolicy`.
Unknown methods, simulations, subscriptions and both `sendRawTransaction` aliases
are single-attempt. Callers cannot extend the retry allowlist.

Allowlisted calls retry transport/disconnection failures and HTTP 429, 502, 503
or 504. Delay doubles from the base up to its cap. A batch retries only if every
method is allowlisted; bytes and IDs stay identical. Retried reads can observe
newer state and do not provide a consistent-state snapshot. Parsing, protocol,
node, limit, cancellation and deadline errors and other HTTP statuses never retry.

A nonnegative integer `Retry-After` delay in seconds can increase the backoff
when it fits `maxRetryDelayMs`. Invalid hints, HTTP-date hints or delays beyond
the cap prevent retry. Waiting stays inside the overall deadline. No automatic
re-signing, nonce replacement or submission reconciliation occurs.
`requestMayHaveReachedNode: true` after an attempted send means acceptance is
uncertain on failure; it does not prove admission, rejection or inclusion. An
application must reconcile before deciding on another submission.

## Errors and dependencies

`RpcClientError` carries stable `code`, `kind`, `attempts`,
`requestMayHaveReachedNode`, and optional `httpStatus`/`rpcCode`. Kinds separate
input, limit, transport, HTTP, JSON parsing, protocol, node, cancellation and
timeout failures. Diagnostics contain fixed messages and numeric metadata; they
omit params, URLs, bodies, remote messages/arbitrary data, Retry-After text, abort reasons
and original exceptions/causes. For node code -32000, `authorizationFamily` retains
only the fixed known tokens listed in the [typed RPC reference](rpc.md); unknown
tokens are discarded. There is no logging hook. Applications must also
avoid logging their secrets.

Endpoints are absolute HTTP(S) URLs without credentials, queries or fragments.
HTTP supports local development; use HTTPS for deployed services. Fetch uses
POST, JSON headers, `redirect: "error"`, `credentials: "omit"`, `cache: "no-store"`
and `referrerPolicy: "no-referrer"`. Redirect failure prevents automatic reposting
of submissions to another URL. These behaviors follow the
[Fetch standard](https://fetch.spec.whatwg.org/); envelopes follow
[JSON-RPC 2.0](https://www.jsonrpc.org/specification).

`fetch?: RpcFetch` injects a trusted Fetch-compatible implementation. `clock?:
RpcClock` injects trusted monotonic `now()` and paired timer methods for tests.
Defaults use runtime fetch, performance and timers when constructing/calling the
client. Module imports require neither browser state nor global fetch. Injected
fetch must honor options and cancellation; wrappers must not add hidden write
retries or redirect behavior.

## Interoperability and qualification

The [pinned node](protocol-sources.md) emits explicit `result:null` for successful
absent transaction/receipt lookups, preserves false/zero/empty values and emits
error-only envelopes. Native production-handler fixtures are exercised through
actual Node fetch, including mixed batches. The SDK still rejects omitted results
and ambiguous envelopes as `INVALID_RESPONSE`; it applies no compatibility
coercion. Null lookup is a bounded node observation, not proof of nonexistence or
rejection. [Typed receipt semantics](receipts.md) validate exact native commitments;
[submission/reconciliation](submission.md) preserves typed uncertainty.

Tests use injected fetch and actual Node fetch against owned loopback servers for
truncation, gzip expansion, throttling, redirects, abort and deadlines. This is
transport evidence. [Typed-method tests](rpc.md) provide schemas/identity and native
handler fixtures. Browser engines, running-network acceptance/finality and
independent security review remain separate gates in
[the plan](../../PLAN.md).
