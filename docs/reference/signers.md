# Raw transaction signers

The root and `@resilience-network/sdk/session` entries export
`signDirectTransaction`, `signRootTransaction`, `signSessionTransaction`,
`SignerError` and their TypeScript option/adapter types. Implementation:
[signers.ts](../../src/session/signers.ts); executable adversarial cases:
[session-signers.test.mjs](../../tests/session-signers.test.mjs).

These functions produce owned canonical `Transaction` objects from a trusted
chain/genesis context, an intent and explicit authority inputs. They validate
local signatures and witness representation. They do not fetch state, choose
nonces, establish current authority, check policy membership/budgets, reserve
nonces, submit transactions or prove execution/finality. The application must
perform those steps; a valid signature alone is insufficient.

## External key ownership and digest contract

An adapter is `{ keyScheme, publicKey, sign(request) }`. Its `sign` method returns
a promise of `{ keyScheme, publicKey, signature }`. Wrap any provider/private-key
object in this public interface; adapters and responses reject unknown enumerable
fields. No private key enters the SDK signing functions or RPC. The SDK generates
no keys, persists no keys/signatures and offers no default wallet or custody.

The request contains `mode`, `keyScheme`, a copied `publicKey`, the exact copied
32-byte authorization `digest`, and an operation-owned `AbortSignal`. Return the
same scheme/key and a raw 64-byte signature:

- Ed25519 signs the digest **as message bytes**, using ordinary Ed25519 rather
  than Ed25519ph or an additional application hash. Keys are canonical 32-byte
  non-small-order points. DIRECT checks `Keccak256(publicKey)[12:]` against the
  intent sender. ROOT and DIRECT accept only scheme 1.
- P-256 SESSION uses scheme 2, a raw 64-byte big-endian X||Y key, and raw 64-byte
  big-endian r||s. Sign the already-hashed digest without hashing it again. For an
  explicit externally owned Noble adapter, this requires `prehash: false`.
  Both low- and high-S signatures are accepted, matching the pinned Chain.
- WebCrypto ECDSA with SHA-256 on this digest hashes it again and fails native
  signature verification. A WebAuthn assertion signs a different message; DER
  conversion or a passkey prompt cannot make it a native session signature.

Ed25519 verification enforces canonical A/R/S, non-small-order A/R and Chain's
exact uncofactored equation `SB = R + kA`. Noble's `zip215: false` setting alone
still uses a cofactored equation at the pinned dependency version. The SDK adds
the exact equation check; it does not invent a torsion-free public-key rule.
See [SDK #45](https://github.com/Resilience-Network/sdk/issues/45) and the retained
cofactor/mixed-order regressions in the unit and native suites.

```ts
import {
  signDirectTransaction,
  transactionCodec,
  type RawSigner,
} from "@resilience-network/sdk/session";

const signer: RawSigner<1> = {
  keyScheme: 1,
  publicKey: trustedProviderPublicKey,
  async sign({ digest, signal }) {
    const signature = await externalEd25519Provider.signMessage(digest, signal);
    return { keyScheme: 1, publicKey: trustedProviderPublicKey, signature };
  },
};
const transaction = await signDirectTransaction({
  context: trustedChainContext,
  intent: reviewedIntent,
  nonce: observedAndCoordinatedNonce,
  signer,
  signal: operationAbortController.signal,
  timeoutMs: 30_000,
});
const canonicalBytes = transactionCodec.encode(transaction);
```

The provider/context/nonce variables are application inputs, not bundled SDK
services. Nonce coordination remains a separate delivery task. Applications must
review canonical bytes rather than labels or
untrusted node claims; see [threat model](../security/threat-model.md).

## Canonical approval before signing

All three signing functions accept optional `approve({ review, signal })`.
Supplying it binds an explicit application-owned review to the signer's exact
validated snapshots. The callback runs once before any external signer; only
literal `true` approves. Omitting it deliberately uses the low-level signing API
without an SDK review prompt. The SDK cannot prove that a UI was shown or that a
human read it; the application owns that interaction.

```ts
const transaction = await signDirectTransaction({
  context: trustedChainContext,
  intent: intendedTransaction,
  nonce: observedAndCoordinatedNonce,
  signer,
  approve: async ({ review, signal }) => {
    // Show ALL canonical template fields AND public signing authority.
    return showReviewAndAskForApproval(review, signal);
  },
});
```

`SigningReview` is a frozen tree of immutable primitives:

- `intent`: the complete canonical intent review with expected network/genesis.
- `transactionTemplate`: a complete envelope review with each 64-byte signature
  replaced by zeros. Every credential/epoch/nonce/proof is present. Its hash is
  a template hash, **not the final signed transaction ID**.
- `authority`: DIRECT/SESSION scheme, exact public key and fingerprint; or ROOT
  threshold, canonical config, every config key/ID and sorted selected signing IDs.
  These are supplied signing inputs, not authenticated live authority.
- `signingDigest`: the exact native domain digest sent to all selected signers.
- `reviewHash`: an SDK-only binding covering the template and all public signing
  authority inputs, including SESSION public keys absent from the envelope.
  `reviewHashDomain` is `RESILIENCE_SDK_SIGNING_REVIEW_V1`; this hash is never used
  as a Chain signature digest or advertised as a transaction/policy ID.

The SDK review hash is Keccak256 of UTF-8 domain bytes, ChainDomain, canonical
zero-signature TransactionV2, and metadata concatenated in that order. Metadata
is `u16(1) || u8(mode) || u8(scheme)`, then DIRECT/SESSION wire-width public key,
or ROOT `u32(configByteLength) || canonicalRootConfig || u8(selectedCount) ||`
every sorted 32-byte selected key ID. Integers are big-endian. It changes with
all public authority choices even when a chain digest intentionally binds an
external grant/config by identity rather than containing its public keys.

Approval shares the overall signing deadline and operation-owned abort signal.
Changing intent, network, credential/config/nonces, proof, signer key/scheme/
callback or approval callback while approval is pending fails the mutation guard
before a signer is invoked. Rejection or reviewer failure also prevents signing.
No state/nonce is reserved by approval; current authority/policy/budget and
receipt checks remain necessary. Deliberately repeated application calls can
request a new signature; no automatic resign, submission or nonce reuse occurs.

[Review integration tests](../../tests/review-signing.test.mjs) cover every common
field, authority/proof/grant-policy mutations, cancellation, exact precision and
metadata limits. [Independent SDK review-hash goldens](../../tests/display/golden/signing-binding.json)
use the pinned Python model's Keccak with separately assembled metadata/wire
signature offsets. The native gate signs through approved callbacks and replays
transactions through production Go verifiers.

## ROOT and SESSION inputs

ROOT additionally takes canonical `config`, `authEpoch`, `nonce` and `signers`.
Select exactly `config.threshold` distinct Ed25519 adapters from its 1–8 keys.
The function validates every config point and selected key before invoking a
callback, sorts the selected IDs, collects signatures sequentially and emits
exactly the threshold. Missing/excess/duplicate/unknown/P-256 signers fail instead
of silently selecting another key or adding unnecessary signatures. The config
itself must already be canonically sorted; there is no format compatibility shim.

SESSION takes `credential` with `grantId`, `authEpoch`, `policyHash`, `nonce`,
`keyScheme`, `publicKey`, plus a matching signer and optional `recipientProof`.
Credential hashes are exact nonzero 32-byte values; integers have u64 bounds.
The proof is canonically encoded/copied, but membership in the grant's recipient
root and actual grant state are not verified by this signing function.

All three functions reject nonzero sponsorship: sponsor lifecycle/co-signing is
outside this initial API, even though canonical codecs preserve sponsor fields.
Input protocol validation errors are `CodecError`. Returned transactions own all
their byte arrays and remain unchanged if a caller/provider later edits its
original buffers. Applications can subsequently mutate the returned transaction;
such mutation invalidates its signature and requires a new deliberate signing
operation, not automatic resigning or submission.

## Mutation, cancellation and failure

Canonical intent/context, nonces/epochs, config/credential/proof and adapter
scheme/key/callback are snapshotted before asynchronous work and checked at
callback boundaries and completion. Any observed change rejects the operation.
Adapters receive separate byte copies; changing a request digest/key/metadata
also rejects the operation. The guard observes boundary differences, not a
complete history of edits that are restored before the next check. It is not
isolation from hostile code running in the same JavaScript process.

`timeoutMs` is an overall operation deadline of 1–300000 ms, default 30000 ms,
including approval and all ROOT signatures. A pre-aborted signal invokes neither
reviewer nor signer. Abort or
timeout rejects promptly even if a provider ignores its signal, prevents further
ROOT callbacks, and handles late promise failures. Operation signals are isolated;
one signing cancellation does not abort another operation. Timers/listeners are
removed on settlement. Synchronous provider code can block the JavaScript event
loop; the elapsed-time check rejects its eventual result but cannot preempt it.

`SignerError.code` is `INVALID_SIGNATURE`, `SIGNER_MISMATCH`, `SIGNER_FAILED`,
`MUTATED_INPUT`, `ABORTED`, `TIMEOUT`, `REVIEW_REJECTED` or `REVIEW_FAILED`.
Exceptions from reviewers/providers and caller abort
reasons are not copied into SDK diagnostics. The SDK does not log request/result
bytes or retain private keys. It cannot guarantee erasure of JavaScript/GC memory,
erase a provider's secrets, retract a signature a provider already produced, or
enforce provider cancellation/key storage. Those responsibilities remain with the
external adapter and application.

## Native evidence boundary

Run `npm run check` and the [native signature gate](../guides/testing.md) against
the immutable [source baseline](protocol-sources.md). The gate uses production
Go DIRECT/ROOT/SESSION verifiers, independent Node/OpenSSL Ed25519 and standard Go
Ed25519/P-256 signatures, exact thresholds, both P-256 S forms, context/nonce/key
and signature mutations, WebCrypto/WebAuthn confusion and Ed25519 equation cases.
It proves stateless signature agreement on the pin. It does not prove funded
localnet grant lifecycle, browser/device support or independent security review.
