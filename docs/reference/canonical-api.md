# Canonical API and supported scope

This page describes the implemented P1 codecs and hashes. It does not provide a
signer, node transport, authority verifier, browser ceremony or production wallet.
The [source baseline](protocol-sources.md) is immutable for this implementation.

## Entry points and values

- `@resilience-network/sdk/core`: `CodecError`, hex/byte comparison, checked
  integer encoding/decoding, and `keccak256` with original Keccak padding.
- `@resilience-network/sdk/session`: canonical types, action/mode/scheme constants,
  codec objects, key validation/fingerprints and typed hashes.
- `@resilience-network/sdk`: reexports both. There is no import-time browser access.

All amounts/heights/nonces/chain IDs are checked `bigint`. u64 is 0 through
2^64−1; u256 is 0 through 2^256−1. Versions, counts and discriminants use bounded
safe integer numbers. Addresses/hashes are exact 20/32-byte `Uint8Array`.
Hex parsers require `0x`, complete byte pairs and bounded length. Invalid values
throw `CodecError` with a code; no private input values are included in messages.

Codec objects expose `encode(value)` and `decode(bytes)`. Decoders reject trailing
bytes, invalid versions, counts/order, booleans, sentinel fields and unsupported
features. Returned byte arrays are owned copies. Encoders reject unknown enumerable
structured fields rather than silently dropping them. There is no automatic sorting
or backward-format negotiation.

## Supported codec objects

- `txIntentCodec`, `authEnvelopeCodec`, `transactionCodec`: Transaction V2 intent
  and AuthEnvelope V1. Complete transactions are intent bytes followed immediately
  by envelope bytes. No wrapper/extra length prefixes. Intent is 181 fixed bytes
  plus data; envelope is 100 fixed bytes plus witnesses. Maximum transaction is
  67,011 bytes. Fee and sponsor fields are included and sponsor binding is checked.
- `rootConfigCodec`: V1 Ed25519 root keys sorted strictly by root key ID;
  1–8 keys and a nonzero threshold no greater than count. Codec validation matches
  the source structural rules; root public-key/signature/authority verification is
  a separate signing-layer responsibility.
- `encodeRootWitness` / `decodeRootWitness`: exactly the supplied threshold,
  strictly sorted unique key IDs, 64-byte signatures. An envelope independently
  checks structural count/order; it cannot infer an account's actual threshold.
- `sessionWitnessCodec`: 64-byte raw signature and optional position-bound
  recipient proof. It checks representation, not signature validity or membership.
- `recipientProofCodec`: u32 index/count, 0–32 sibling hashes, exact depth
  ceil(log2(count)), index below count. Tree membership requires a trusted root.
- `policyCodec`: V1 transfer-only policy (`actionMask = 1n`), fee/attempt limits,
  inline recipients (1–128 strictly sorted nonzero addresses) or Merkle recipients,
  transfer flags/value limits and optional fee/value token buckets. Fee bounds and
  bucket capacity must be nonzero. Limits may be zero where the source permits.
- `activateAuthorizationCodec`: V1 action, root body and u256 security reserve.
- `createGrantCodec`, `replaceGrantCodec`: scheme-width key, validity interval,
  canonical policy, nonzero deposit; replacement also binds the old grant ID.
- `revokeGrantCodec`, `cleanupGrantCodec`: nonzero grant ID; cleanup also binds owner.
- `rotateRootCodec`: config and preserve/replace reserve mode; preserve requires
  zero replacement reserve. `setSecurityReserveCodec` includes the full u256 reserve.

Supported intents are TRANSFER, SESSION_CANCEL, CLEANUP_GRANT, ACTIVATE_AUTHORIZATION,
CREATE_GRANT, REVOKE_GRANT, REPLACE_GRANT, REVOKE_ALL_GRANTS, ROTATE_ROOT and
SET_SECURITY_RESERVE. Cancel and revoke-all have empty action data. Other known
Chain actions fail explicitly with `UNSUPPORTED_FEATURE`. Contract/staking/name/
recovery policies/actions are not partially decoded. Grant maximum lifetime,
minimum reserve/deposit and live limits are stateful checks, not invented codec
constraints.

## Key and hash contracts

Ed25519 session keys use 32 wire bytes; P-256 keys use 64 raw big-endian X||Y bytes.
Public SDK inputs do not accept 64-byte zero-padded Ed25519 storage keys. Grant
codecs validate canonical non-small-order Ed25519 points or valid P-256 points.
P-256 has no low-S consensus rule; signatures here are structural 64-byte r||s.
No signing API is provided and neither DER assertions nor WebCrypto signing are
automatically converted to native session signatures.

Available typed hashes: `chainDomain`, `intentHash`, `transactionId`,
`rootKeyId`, `rootConfigHash`, `policyHash`, `sessionKeyFingerprint`, `grantId`,
`directDigest`, `rootDigest`, `sessionDigest`, `sponsorDigest`, authorization
meta/recovery/grant/active keys, recipient leaf/empty-leaf/node hashes and
`validatorConsensusKeyHash`. Recipient hash action kinds are TRANSFER or DELEGATE;
the latter does not imply SDK delegation-policy support. Hash helpers mirror the
source input/domain contract, not stateful authorization. `transactionId` hashes
individually canonical components; use `transactionCodec` to check their sponsor
binding before dispatch. Receipt-counter-delta and decision hashes are deferred
with their receipt/state codecs.

`intentHash` checks chain ID against the provided context. Changing the genesis
changes the signed domain. The application must supply a trusted expected context;
hashing untrusted node-reported genesis does not establish network authenticity.

## Provenance and verification

Runtime dependencies `@noble/hashes` and `@noble/curves` are pinned at 2.4.0 with
lockfile integrity. Their use here is checked by known-answer hashes, independent
Chain vectors and Go conformance; the SDK has not received independent security
review. See [testing](../guides/testing.md) for executable commands and limits.

The independent fixture contains deterministic test-only identities/signatures.
Native Go fills specific layout gaps rather than treating self-roundtrips as
independent evidence. No fixture encodes real wallet secrets.
