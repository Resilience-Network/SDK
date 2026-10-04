# SDK security boundaries

This initial threat model covers the planned client SDK. It is a design checklist,
not an audit report or a claim that any feature is implemented or qualified.

The [2026-10-04 implementer review](reviews/2026-10-04-local-candidate.md)
records reproduced RPC context/error and qualification/cleanup defects in its
exact baseline. GitHub owns their disposition. Passing existing suites did not
exercise those failures; the review does not satisfy independent sign-off #34.

## Assets and trusted boundaries

Root/session private keys, exact reviewed transaction bytes, grant authority,
chain/genesis identity and user-visible permission limits are sensitive assets.
Wallet/signer adapters and the application origin control secrets and signing.
RPC responses, app metadata and network messages are untrusted inputs. A trusted
full-node connection is an explicit model; independent proof verification is deferred.

## Required controls

- Domain/replay: bind genesis/chain/account/grant/policy/epoch/nonce and message
  type exactly; reject unknown versions and context mismatches.
- Parsing/precision: enforce canonical widths/order, bounded collections and
  checked bigint arithmetic; reject malformed DER/CBOR and unvalidated EC points.
- Review/sign: derive the display from the actual canonical bytes, freeze signing
  inputs and detect async mutation. Untrusted app labels cannot redefine authority.
- Secrets: no private keys in RPC/logs/URLs, no default persistence, explicit signer
  ownership and reviewed storage/unlock adapters. JavaScript memory zeroization
  cannot promise removal of runtime copies or safety against XSS.
- State/nonce: reconcile uncertain submissions, distinguish action failure from
  rejection, serialize nonce use and observe finalized revocation.
- Passkeys: validate challenge/origin/RP/type/UV at an authoritative verifier,
  consume challenges once and expose the difference from raw session signatures.
  Synced authenticators and counter semantics need explicit treatment.
- Dependencies: pinned crypto implementations, independent vectors, dependency
  license inventory and reviewed release provenance; no unreviewed runtime hooks.

## Limits and release gates

A compromised origin/signer process, user-approved unrestricted authority or a
dishonest trusted RPC cannot be fixed by a client-side display alone. Simulation
is advisory; pending transactions are public. Use appropriate slippage/deadline
controls in market-sensitive applications.

Independent signing/parsing review, negative tests and end-to-end evidence are
release gates in [PLAN.md](../../PLAN.md). Any direct passkey authorization design
requires its own enforcement-boundary review and coordinated chain/contract scope.

## Selected relying-party design

[ADR-0002](../decisions/0002-authoritative-webauthn-rp.md) assigns challenge,
credential and authentication decisions to an application-owned RP. Browser
parsing and client-provided verification booleans grant no authority. Its initial
ES256 profile requires same-origin UP/UV, rejects unsupported extensions and
attestation formats, and does not infer biometric/hardware provenance from flags,
attachment, transports or an AAGUID. A `none` registration awaits a fresh verified
assertion before enrollment/session grant; registration alone proves no key possession.

Replay prevention requires durable linearizable terminal challenge takes with
account/session/expiry binding. Crashes, invalid attempts, lost results and commit
failures cannot revive a taken challenge. Registration uniqueness and conditional
credential updates prevent overwriting another account's key or granting sessions
after concurrent revocation. A per-worker map cannot establish these guarantees
for a deployed service. Rate limits and authenticated enrollment/recovery remain
application responsibilities.

Synced credentials may have nonincreasing counters. The selected profile uses
one-use challenges and explicit backup/counter policy, retaining the maximum
observed counter rather than labeling every synced credential as cloned. Zero
counters do not prove clone detection. A compromised RP/browser origin can bypass
application login or misuse its externally owned native signer; this design
creates no cryptographic passkey-to-Chain enforcement.

The [normative case inventory](../../tests/webauthn/rp-contract-cases.json) is not
execution evidence. Real verifier/parser/browser checks are #27/#26/#30; physical
devices and independent review remain #31/#34. GitHub owns their actual results.

## External native key model

[ADR-0001](../decisions/0001-passkey-authorization-boundary.md) keeps application
login, native key ownership and native authorization distinct. Explicit external
Ed25519 root/raw session adapters own key generation, persistence, backups and
unlock. No passkey-derived root, implicit custody or production key-storage
provider is shipped. Fresh passkey login before signing is application policy;
it cannot constrain a raw key available to compromised origin code.

Logout and passkey recovery do not revoke grants or recover an Ed25519 root.
Observe actual finalized ROOT revocation/epoch change or authoritative expiry;
SESSION_CANCEL does not revoke. Preserve uncertain nonce records and all existing
wallet/signing state. Memory coordination and test key closures are not durable
wallet custody. Direct native WebAuthn enforcement remains separate
[Chain#382](https://github.com/Resilience-Network/Chain/issues/382) design work.
