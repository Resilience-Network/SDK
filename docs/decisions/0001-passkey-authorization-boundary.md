# ADR-0001: Passkey and native session authorization boundary

Status: signature boundary accepted for planning; end-to-end passkey-wallet trust
model remains proposed and must be reviewed before a combined implementation.

## Context

[Chain#25](https://github.com/Resilience-Network/Chain/issues/25) proposes browser
WebAuthn ceremonies, DER conversion and a valid P-256 session signature. The
[pinned chain verifier](../reference/protocol-sources.md) uses raw ECDSA over the
already-computed SessionDigest. ROOT/DIRECT authority remains Ed25519.

WebAuthn ES256 assertions authenticate authenticator data concatenated with the
SHA-256 hash of clientDataJSON, with an ECDSA/SHA-256 signature. Challenge, origin,
RP-ID and flags are part of ceremony validation. See the
[W3C assertion verification procedure](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion).
The authenticator does not expose arbitrary raw-digest signing through WebAuthn.
Changing DER signature representation cannot change the signed message.

Similarly, browser ECDSA `SubtleCrypto.sign` hashes its input according to the
algorithm; it is not a raw prehashed-digest signer. See the
[Web Cryptography signing algorithm](https://www.w3.org/TR/WebCryptoAPI/#ecdsa-operations).
Raw session signer adapters need proven semantics rather than double-hashing.

## Decision

Keep `webauthn` ceremonies and native session signing separate in SDK contracts.
Helpers must not describe parsing or a biometric prompt as on-chain authority.
The initial native grant flow requires an external Ed25519 root signer; session
flows use raw Ed25519/P-256 adapters verified against independent/Go vectors.
No implicit custodial service or conversion of passkey keys into root authority.

Before a passkey-wallet product example, review the key storage/unlock model,
authoritative RP verifier, root authorization and threat model. An app login does
not prove a transaction was authorized by a passkey. Any design enforcing passkey
authority on chain/through contracts must specify complete assertion validation,
replay/origin/RP/UV rules, costs and activation in coordinated Chain work.

## Consequences

The original issue's combined browser-to-native-signature acceptance wording needs
explicit revision or a separately implemented authorization extension. SDK-only
P-256 support cannot satisfy it by DER conversion. Record the decision in GitHub
and keep the parent issue open until all resulting criteria are accounted for.

Tests must demonstrate successful raw session signing, valid WebAuthn ceremonies
under their own verifier contract, and rejection of signature-domain confusion.
Virtual authenticators do not prove physical-device/biometric coverage. UI labels
must reflect which credential actually controls on-chain authority.
