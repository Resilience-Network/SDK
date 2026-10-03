# Canonical review API

`@resilience-network/sdk/display` exports `reviewPolicy(canonical)`,
`reviewIntent(expectedContext, canonical)` and
`reviewTransaction(expectedContext, canonical)`, also available from the root.
They accept `Uint8Array` canonical bytes, decode the entire supported grammar and
return a frozen `CanonicalReview` containing exact bytes/hash binding and an
ordered list of `ReviewField` objects. No UI framework or DOM is required.

```ts
import { reviewTransaction } from "@resilience-network/sdk/display";

const review = reviewTransaction(expectedChainContext, canonicalTransaction);
// Render all fields as text. Keep the binding visible with the review.
for (const field of review.fields) {
  renderText(field.label, field.value, field.unit, field.meaning);
}
```

A stable `path` identifies each field; `value` is an exact decimal/hex/enum string
or boolean. `unit` distinguishes base units, gas price, gas, heights, integers,
bytes and enums. `meaning` explains sentinels and authority implications. `source`
distinguishes canonical fields from derived hashes/counts/arithmetic. Consumers
must display all authority fields rather than filtering by truthiness, clipping
recipient lists or suppressing zero values. Never inject values as HTML.

## Binding and verification boundary

`binding.canonical` is the complete canonical encoding, as lowercase hex.
`binding.hash` uses the exact pinned `RESILIENCE_POLICY_V1`,
`RESILIENCE_TX_INTENT_V2` or `RESILIENCE_TX_ID_V2` domain identified by `hashDomain`.
Intent/transaction bindings include the supplied chain ID, genesis hash and
chain-domain hash. Intent chain ID must match that expected context. The expected
genesis is an application trust input, not a node identity proof. Policy hashes
are chain-independent; standalone policy reviews do not claim an account or
network absent from their encoding.

`verification` is always `canonical-structure-only`. A review does not validate
signatures, live root/grant authority, proof membership, nonce availability,
funding, admission, inclusion or execution success. Transaction reviews show the
native signing digest and every authorization identity/nonce/witness field.
ROOT witness count is a provided count, not a verified live threshold. SESSION
public keys are not carried in the envelope: resolve a matching live grant
separately; do not present a grant ID as a key fingerprint. Sponsorship can be
reviewed but is unsupported by the current raw signer helpers.

Both the object tree and fields are frozen, contain only immutable primitives
and retain no caller byte-array references. Later input/context mutation cannot
alter a previously returned review. The review API alone does not require a
signer to use those reviewed bytes; explicit review-to-signing binding is a
separate tracked requirement (#22).

## Supported field mapping

- Policy: version, transfer-only action mask, finite included-attempt cap, all gas
  and fee caps/bucket configuration, inline recipient count/every address or Merkle
  root/count, transfer per-transaction/lifetime caps and bucket, zero/self flags,
  and the six explicitly disabled policy sections.
- Intent: every header field, exact sender/destination/sponsor, value and all fee
  fields, exact action data and derived maximum possible fee. The fee multiplication
  remains exact even beyond u256; this does not establish admission of such a cap.
- Actions: activation root config/hash/threshold/all scheme/key/ID fields and
  reserve; grant scheme/raw public key/fingerprint/validity/deposit/policy/hash;
  revoke/replace IDs; rotation config and reserve mode/value; reserve replacement;
  cleanup owner/ID; explicit revoke-all and session-cancel effects.
- Envelope: version/mode/scheme, credential/policy/epoch/nonces, full witness and
  sponsor witness, exact native authorization/sponsor digest, DIRECT key/signature,
  ROOT signer IDs/signatures, or SESSION signature/proof presence/position/count/
  every sibling. Signature framing is not signature verification.

Zero value caps mean **cannot move value**, never unlimited. An absent bucket
means no additional bucket rate limit while finite caps still apply. Zero refill
means no replenishment. Fee and attempt caps, bucket capacities and storage
deposits must be nonzero where required by the pinned codec. Inline and Merkle
recipient sets are restricted; no unrestricted recipient encoding is supported.
Grant validity is `[validAfterHeight, validUntilHeight)`; no approximate time
estimate is trusted. Rotation preserve mode's zero replacement reserve is a
sentinel to preserve the existing reserve; replace mode can explicitly set zero.

Contract calls/creation, staking/rewards/name policies, recovery and other
unsupported action codes or policy sections fail with `CodecError` rather than
returning a partial review. Versions, lengths, sorted recipient sets, canonical
booleans and trailing bytes use the [canonical codec limits](canonical-api.md).
No selectors, code/proxy identities or extension summaries are inferred.

Application names, Unicode labels, token tickers/decimals, chain names and
wall-clock estimates are absent from canonical bytes. Keep them in visibly
untrusted application context, never substitute them for canonical values or
hashes. Review APIs do not accept those labels or a supplemental summary. Render
addresses/hashes as full canonical hex, not label-dependent authority claims.

## Exact formatting and evidence

`formatBaseUnits(value, decimals = 0)` accepts only unsigned u256 `bigint` and an
integer decimal count from 0 through 255. It returns every digit with fixed
fractional width, without locale separators, rounding or scientific notation.
A decimal count/ticker is supplied application metadata; canonical review fields
always remain exact integer base units. `1_000_000_000_000_000_001n` with 18
decimals returns `1.000000000000000001`.

Implementation: [review.ts](../../src/display/review.ts).
[Golden field fixtures](../../tests/display/golden/fields.json) use literals from
the pinned independent Python-model vectors plus authored control expectations.
[Display tests](../../tests/display.test.mjs) cover all supported actions,
Ed25519/P-256, ROOT/DIRECT/SESSION/sponsor digests, finite zero/disabled semantics,
max recipients/proofs, precision, frozen snapshots, malformed/unsupported bytes
and untrusted labels. [Protocol sources](protocol-sources.md) links the exact
Chain policy evaluator, codecs and lifecycle contract. Run the commands in the
[testing guide](../guides/testing.md); test descriptions are not pass evidence.
