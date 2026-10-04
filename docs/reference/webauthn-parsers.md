# WebAuthn representation parsers

`@resilience-network/sdk/webauthn` and the root entry export bounded ES256
representation parsing. [Source](../../src/webauthn/index.ts),
[parser tests](../../tests/webauthn-parsers.test.mjs) and
[installed consumer checks](../../scripts/check_package.mjs) define the API.
Browser ceremony helpers and authoritative RP verification remain separate work.

```ts
import {
  parseCoseP256PublicKey,
  parseAuthenticatorData,
  parseClientDataJSON,
  derToP256Signature,
} from "@resilience-network/sdk/webauthn";

const key = parseCoseP256PublicKey(storedCoseKeyBytes);
const observed = parseAuthenticatorData(authenticatorDataBytes, "authentication");
const client = parseClientDataJSON(clientDataJSONBytes);
const signature = derToP256Signature(signatureDERBytes);
```

All inputs are `Uint8Array`, including Node buffers. Public calls bound intrinsic
view length before copying, ignoring shadow `length`/`buffer` properties; proxies
and shared backing stores fail. Returned binary fields are owned copies. Readonly
types do not prevent callers mutating their own arrays; original inputs and
separate parsed fields do not alias. Parsing is synchronous and makes no network,
key-store or browser-global calls. Node import does not run a ceremony.

## Supported functions

- `parseCoseP256PublicKey(bytes): ParsedP256PublicKey` accepts exactly the
  canonical five-parameter WebAuthn EC2 key: kty=2, alg=-7, crv=1, and 32-byte x/y.
  It checks the P-256 field/curve point and returns algorithm -7, original
  canonical `coseKey`, and 64-byte X||Y `publicKey`. Optional parameters,
  compressed points and other keys/curves/algorithms are unsupported.
- `parseAuthenticatorData(bytes, ceremony): ParsedAuthenticatorData` requires
  explicit `registration` or `authentication`. It returns original bytes,
  rpIdHash, flags, UP/UV/BE/BS observations and exact u32 `signCount` as a number.
  Registration requires AT data: 16-byte AAGUID, nonempty bounded credential ID
  and exact supported COSE key. Authentication forbids AT and requires exactly
  37 bytes. Reserved flags, BS without BE, trailing data and ED extensions fail.
  Missing UP/UV is represented as false; the RP must enforce its required flags.
- `parseNoneAttestationObject(bytes): ParsedNoneAttestation` accepts exactly a
  canonical map of `fmt: "none"`, empty `attStmt` and supported registration
  `authData`. Other formats/fields are unsupported. A `none` object supplies no
  attestation signature, independent key-possession proof or hardware provenance.
  [ADR-0002](../decisions/0002-authoritative-webauthn-rp.md) requires a fresh
  verified assertion before completing enrollment/session grant.
- `derToP256Signature(bytes): Uint8Array` requires one exact DER SEQUENCE with two
  minimally encoded positive INTEGERs in `[1, n-1]`. It checks sign padding,
  lengths, scalar ranges and complete consumption, returning 32-byte-padded r||s.
  It preserves both low/high s; it neither hashes nor normalizes the signature.
  Representation conversion leaves the signed message unchanged. WebAuthn
  responses cannot become native SessionDigest signatures through this function.
- `parseClientDataJSON(bytes): ParsedClientData` preserves original UTF-8 bytes,
  accepts `webauthn.create`/`webauthn.get`, and returns canonical decoded challenge,
  nonempty origin, boolean crossOrigin (false if absent) and optional topOrigin.
  It rejects duplicate decoded keys at every level, malformed/ill-formed Unicode,
  unsupported field types, nonfinite/unsafe integer numbers and trailing JSON.
  Other ordinary bounded JSON fields convey no authority and are not projected.
  Cross-origin fields are observations; the selected RP profile must reject them.

Origin/RP/type/challenge equality, UP/UV policy, key ownership, stored BE/counter
behavior, revocation, cryptographic signatures, expiry and atomic challenge
consumption are authoritative verifier responsibilities. No parser returns a
`verified` result or binds an app account to Chain authority. Keep original
clientDataJSON for hashing; reserialized JSON changes signed bytes.

## Exact bounds and unsupported structures

`WEBAUTHN_PARSE_LIMITS` is frozen and records these fixed implementation bounds:

- Client-data and authenticator buffers: 8192 bytes each.
- `none` attestation object: 16384 bytes; COSE key: 1024 bytes.
- Credential ID: 1–1023 bytes; 1024 rejects, correcting the earlier planned bound.
- DER signature: at most 72 bytes; both scalars strictly less than P-256 order.
- Challenge representation: 1–1024 decoded bytes, canonical unpadded base64url
  with zero unused bits. The selected RP issues 32-byte challenges and must check
  exact equality; this wider representation bound does not alter RP policy.
- CBOR/JSON: at most four container levels, 32 entries per map/array/object, and
  128 total values/keys/containers. Declared sizes are checked before allocating.

CBOR uses minimal integer/length widths, definite lengths, unique map keys and
CTAP2 encoded ordering. The internal subset supports integers (exact bigint when
outside safe number range), text/bytes, arrays/maps and booleans/null. Map keys
are integer/text only. Tags, floats, undefined, indefinite lengths and alternate
decoders are unsupported. UTF-8 is strict. These limits and the no-extension,
none-attestation/ES256 profile are intentional, with no relaxed fallback.

`WebAuthnParseError` exposes fixed `code` and bounded generic message, without
input bytes, origin, credential ID, provider exceptions or nested causes. Codes
are `INVALID_ARGUMENT`, `LIMIT_EXCEEDED`, `INVALID_CBOR`, `UNSUPPORTED_COSE`,
`INVALID_POINT`, `INVALID_AUTHENTICATOR_DATA`, `UNSUPPORTED_EXTENSION`,
`UNSUPPORTED_ATTESTATION`, `INVALID_CLIENT_DATA` and `INVALID_DER`.

## Evidence and limits

[Public fixtures](../../tests/webauthn/parser-v1.json) include the W3C ES256 point
and eight independent Node/OpenSSL P1363/DER signature cases, with both padding
and reflected s values. [Provenance](../../tests/webauthn/parser-v1.provenance.json)
binds fixture and [generator](../../scripts/generate_webauthn_parser_fixtures.mjs)
hashes. Generator `--write` is intentional regeneration using new disposable
keys/signatures; no private key is persisted. Explain semantic/provenance changes
before replacing goldens. OpenSSL verifies the DER and converted P1363 values.

Focused tests cover all fixture truncations, noncanonical/duplicate/nested CBOR,
point/scalar boundaries, flags/unsupported forms, original byte ownership,
JSON/base64url limits and 5000 seeded byte mutations. Native signature-domain
separation is tested against the actual SDK SessionDigest, not inferred from
equal scalar width. These are parser/interoperability tests, not actual browser
engine, physical device, authoritative RP/store or independent security approval.
Those gates remain #25/#27/#30/#31/#34.

Normative standards:
[W3C WebAuthn key/format rules](https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data),
[CTAP2 canonical CBOR](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#message-encoding),
and [ES256 DER signatures](https://www.w3.org/TR/webauthn-3/#sctn-signature-attestation-types).

Hostile input validation reconstructs errors with fixed messages and validated
codes. It does not forward caller-supplied error objects, messages or causes,
including modified SDK error instances or throwing classification properties.
