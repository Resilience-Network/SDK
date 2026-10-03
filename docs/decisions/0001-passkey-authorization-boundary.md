# ADR-0001: Passkey and native session authorization boundary

Status: external native key authority and separate application authentication
selected under SDK #24; acceptance requires its linked review/merge. Combined
example qualification remains gated by actual browser/verifier evidence.

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

Use the key ownership model below and the
[authoritative RP contract](0002-authoritative-webauthn-rp.md) for future examples.
Implement and qualify their actual verifier/browser boundaries before combining
them. An app login does not prove a transaction was authorized by a passkey.
Any design enforcing passkey
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

## Key ownership and generation

The application supplies `RawSigner` adapters with public keys and explicit
digest-sign callbacks. A DIRECT account and every selected ROOT witness use
Ed25519; a SESSION grant selects raw Ed25519 or P-256. The existing
[signer API](../reference/signers.md) validates returned signatures and exact
message semantics. The SDK creates no production private key, hidden root,
custody service or association between a passkey key and a native key.

The owner chooses native key generation, storage, backup, unlock and signer
transport. Keep root keys separate from bounded session keys. An application
that generates a raw session key must use a cryptographically secure source and
provide a tested prehashed-digest adapter; browser WebCrypto ECDSA signing is
not that adapter. A passkey credential is created by WebAuthn for application
authentication and its private key is not exported by these helpers.

The [disposable native example](../guides/session-example.md) generates test-only
keys in external closures. It is reproducible evidence, not a production storage
recommendation. No key persistence, encryption wrapper, key derivation from a
WebAuthn signature/PRF, IndexedDB custody or automatic signer unlock is included
in the supported SDK model. Any later adapter must document its own guarantees
and be reviewed separately.

## Authentication, review and unlock

The RP's opaque application account and a configured Chain owner are separate
identities. An application must establish any association through its own reviewed
account/ownership procedure; an email, user handle, successful app login or RPC
response cannot synthesize Chain root authority. The native signer still proves
the required account/root/grant authorization on Chain.

Use explicit user-facing labels: **Sign in to the application with a passkey**,
**Authorize a grant with the Ed25519 root signer**, and **Send using the selected
raw session key**. Show native chain/account/key fingerprint and bounded policy
through [canonical review](../reference/display.md); require explicit approval
for the [lifecycle](../reference/lifecycle.md). Do not label a transaction
"passkey-signed" or an app-login result "on-chain authorized".

Applications may require a fresh RP authentication before invoking an external
signer, but that is application access policy. If the same origin holds or can
invoke the raw key, XSS or compromised application code can bypass that policy.
A biometric/UV prompt does not cryptographically unlock or constrain that native
key. The SDK does not promise same-origin enforcement, JavaScript memory erasure,
encrypted persistence safety against live XSS, hardware isolation or unattended
custodial signing. Maintainer self-review is not independent security approval.

## Persistence, recovery and revocation

Default SDK state contains no private keys. `MemoryNonceReservationStore` is
one-process coordination, not durable wallet storage. An application durable
adapter must preserve uncertain/signed records across crashes, serialize access
across tabs/workers and protect its integrity; authentication logout does not
authorize deleting those records to reuse a nonce. Keep backups, databases,
validator signing watermarks and retained failure evidence outside disposable
test ownership. A lost HTTP acknowledgment requires explicit read-only recovery
of the same ID, not signing a replacement automatically.

Application logout/credential deletion and on-chain grant revocation are distinct.
Logout can stop new application requests but does not remove a valid Chain grant.
Use ROOT individual revocation or revoke-all, observe its finalized receipt and
current authority, and retain uncertain results if unavailable. SESSION_CANCEL
consumes an attempt/fee and leaves the grant active. Expiry uses authoritative
heights. Discarding a local raw key does not prove the network revoked it.

Recovery of an RP credential restores only application authentication. Recovery
of an external Ed25519 root is owned by that signer/account's actual recovery
model; the SDK cannot recover a lost private key from a passkey. Supported root
rotation uses the existing authorized threshold and an explicitly selected new
config; it is not recovery without authority. Guardian recovery UI and storage
providers remain outside this SDK scope. Grant replacement/cleanup do not justify
erasing unrelated key or signing state. No format migration or legacy fallback
is introduced.

## Accounting for original Chain#25 acceptance

The original criteria remain visible in
[Chain#25](https://github.com/Resilience-Network/Chain/issues/25). This selected
consensus-free model explicitly splits its combined passkey/native wording:

- **Browser creates a credential and produces a native P-256 session signature**:
  these are separate supported workflows. Browser registration/assertion and
  authoritative verification require SDK #25/#26/#27/#30, with physical devices
  in #31. Raw native SESSION signatures have independent #18/#22 evidence and
  actual node execution in #29. A direct passkey-controlled native extension is
  deferred to separately tracked
  [Chain#382](https://github.com/Resilience-Network/Chain/issues/382); this SDK does
  not deliver or silently enable it.
- **Node accepts/verifies on localnet**: reviewed
  [SDK PR #59](https://github.com/Resilience-Network/sdk/pull/59) qualifies funded
  DIRECT activation, ROOT controls and both raw session schemes on immutable
  Chain `007356ef5e5e1769cfda2290fcafc9db5d48bbfd`. Topic
  `1878eb838f2b129ae3fcfed6d8d84120191f2e4f` includes actual replay/expiry/domain/
  included-failure/concurrency/uncertain-send evidence. It is raw native acceptance,
  not WebAuthn assertion acceptance or independent finality.
- **Reference docs updated at the former wallet-guide path**: the canonical current
  path is `docs/guides/wallet-integration.md`. SDK #33 owns the installed-consumer
  guide and coordinated Chain topic-branch/PR docs/evidence link; this decision
  does not claim that future upstream update has already landed.

The clarified parent criteria map to native #29, authoritative/browser/device
#27/#30/#31, this key decision #24 alongside RP #23, and coordinated docs #33.
Combined example #32 must demonstrate two independently verified capabilities
with the labels above. Chain#25 stays open until its resulting scope is actually
accounted for; no criterion is closed by parsing DER or a package scaffold.

GitHub [SDK #24](https://github.com/Resilience-Network/sdk/issues/24) owns the
exact decision review/merge evidence. The selected model changes no Chain codec,
gas, activation, root/state rule, manifest or genesis. Direct WebAuthn enforcement
would require separately reviewed protocol/contract design, resource bounds,
state/replay semantics and coordinated implementation under Chain#382.
