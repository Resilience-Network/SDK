# ADR-0002: Authoritative WebAuthn relying-party contract

Status: selected implementation contract under SDK #23; acceptance requires the
linked PR review and merge. This decision defines the implemented helpers and
[executable RP conformance reference](../reference/webauthn-rp-reference.md), not a
shipped authentication service or production durable-store qualification.

## Decision and responsibilities

WebAuthn authenticates an application account at its relying party (RP). It grants
no Chain authority. [ADR-0001](0001-passkey-authorization-boundary.md) governs the
separate external native signers. An application owns its RP deployment,
authenticated enrollment/account recovery, credential database, session issuance,
CSRF protection, rate limits and trusted configuration. SDK browser helpers
collect and serialize public ceremony responses; their parsing success and any
client-supplied `verified` field are never authoritative results.

The reference conformance boundary in #27 uses
[`@simplewebauthn/server`](https://simplewebauthn.dev/docs/packages/server) for
registration/assertion cryptographic verification, with an explicit application
wrapper enforcing this narrower profile and transactional storage semantics.
Its development dependency is exact-pinned at 14.0.3 in package/lock files.
Keep this Node test/reference dependency outside browser/core/session imports;
do not implement a second cryptographic verifier or install a backend implicitly.
A production RP adapter must satisfy the same conformance cases with its actual
durable store. In-memory reference success does not qualify multiple workers.

The standards baseline is the
[W3C Level 3 Recommendation](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/).
Its [RP operations](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-rp-operations)
bind ceremony type, challenge, origin, RP-ID hash, flags and credential signature.
Counters are not universal replay protection; backup eligibility remains fixed
while backup state may change. These facts motivate the local choices below.

## Supported application profile

The first profile is account-bound registration/login, ES256 only (COSE algorithm
-7, EC2/P-256), UP and UV required, same-origin ceremonies, no authenticator
extensions, and `attestation: "none"`. Only a `none` attestation object with an
empty statement is accepted; other formats fail explicitly. This profile makes
no manufacturer, authenticator hardware, PIN-versus-biometric or device-local
private-key claim. AAGUID, transports and attachment are informational. A `none`
registration carries no attestation signature or independent key-possession
proof. Store it as awaiting proof; a fresh, fully verified assertion with that
key is required before completing enrollment or granting an authentication
session. Registration alone never creates a new authenticated session.

The RP supplies one explicit RP ID and an exact allowlist of serialized origins.
Production origins must be HTTPS; HTTP loopback origins are allowed only in an
explicit disposable development profile. Reject wildcards, opaque origins,
userinfo, paths, queries and fragments in configuration. Never derive trusted
RP/origin values from response data, request forwarding headers or RPC. Browser
`crossOrigin` must be absent/false; reject true, nonboolean values and `topOrigin`
in this same-origin profile. No suffix/prefix origin match or related-origin
fallback is permitted. Legitimate unsupported flows need a new reviewed profile.

Enrollment requires an already authenticated account/recovery procedure; a new
credential cannot choose the account it is attached to. Initial login challenges
are bound to that application's selected account and known credential IDs.
Discoverable account selection is outside this profile. A nonnull assertion
user handle must match the account's stored opaque handle; a null handle is
allowed only when account/credential ownership is already established by the
stored challenge. WebAuthn user handles are random opaque bytes, not an email,
Chain address, secret, or proof of Chain ownership.

## Challenge lifetime, ownership and one-use storage

The RP generates independent 32-byte CSPRNG challenges and opaque request IDs.
Persist before returning options: version 1, request ID, challenge bytes,
ceremony (`registration`/`authentication`), account ID/user handle, authenticated
browser-session binding, allowed credential IDs, trusted RP/origin/profile
snapshot, issued time, exclusive expiry and `pending` state. Reference lifetime
is 180 seconds; browser UI timeout never extends authoritative validity. Reject
server times before issuance or at/after expiry. Reissuance creates a new ID and
challenge; it never resets a consumed or expired record.

Verification receives an untrusted response plus the request ID. The RP obtains
session/account binding from its trusted request context. Atomically take a
matching pending record under those bindings and the time check, marking it
terminal before cryptographic work. Missing, wrong-binding, expired or already
taken records fail closed. Storage failure returns no verified result. Once
taken, invalid responses, verifier errors, cancellation, process death and
commit failures burn that challenge; never restore it for retry. A fresh ceremony
is required. Rate limits are necessary because invalid bound attempts can burn
their own challenges. Unknown request IDs disclose no account details.

The store must make this compare-and-transition linearizable across all service
workers and durable across restarts. TTL cleanup is housekeeping, not an expiry
check or replay lock. Two simultaneous consumers must yield at most one take.
No read-then-delete lock, per-worker map or client-side challenge generator
satisfies a production adapter. Transport retries never replay a verification
POST automatically; a lost result is uncertain and does not revive the challenge.

## Verification and commit contract

After the take, verify bounded original response bytes against the stored profile
and challenge, not client options. Enforce exact credential ID/raw ID agreement,
ceremony type, canonical challenge bytes, allowed origin/RP ID, UP/UV, supported
algorithm/point and the assertion signature; reject tampered bytes and unsupported structures.
Hash the original clientDataJSON bytes for the signature check, never a parsed
and reserialized object. Unknown ordinary client-data properties convey no
authority; malformed/duplicate JSON keys fail. No extension output is used to
unlock or derive a native signing key.

Registration requires AT data, matching credential ID and supported COSE key;
assertions forbid AT data. ED data is unsupported. Reject reserved flag bits,
BS without BE, or changed BE on an existing credential. New credential IDs must
be unique across accounts; registration never overwrites an existing credential.
Only assertions checked with a stored nonrevoked credential/key may authenticate.

Credential records use explicit version 1, account/user handle, credential ID,
canonical supported COSE key, algorithm -7, RP/profile binding, BE, last observed
BS, maximum observed u32 counter, awaiting-proof/active state, revocation state
and a storage version. Binary
fields are bytes in memory and canonical unpadded base64url in JSON. Do not
persist private keys, biometrics, ceremony responses, bearer session tokens or
raw challenges in public evidence. Credential IDs themselves are privacy-sensitive.

For BE=false, require a new counter above the stored value whenever either is
nonzero; both zero may authenticate without clone detection. For BE=true, a
nonincreasing counter alone does not reject a valid fresh assertion. Record the
maximum and updated BS; use challenge consumption for replay protection.
The adapter must apply these policies explicitly around the maintained verifier,
including any verifier's stricter built-in counter behavior. Counter anomalies
are risk signals, not proof of cloning; zero counters never prove hardware.

Before success, commit credential insertion or conditional update against the
verified storage version and revocation/account binding, along with the final
authentication outcome. Recheck the exclusive challenge expiry and issuance
bound at commit; a valid take does not authorize completion after expiry. Bound
verifier work by the remaining lifetime and cancellation; a late completion
cannot commit or return success. Credential revocation or concurrent update conflicts
fail closed and require a new ceremony; do not overwrite a newer record or issue
a session before commit. An application needing an atomic session grant must
include that grant in its same transaction. The already-taken challenge remains
terminal on every failure.

Success is a server-only result containing ceremony/account/credential binding,
UP/UV and backup observations, counter outcome and committed record version.
There is no `onChainAuthorized`, `biometricVerified`, `hardwareAttested` or
native-signature field. Client JSON cannot manufacture this result. Public errors
use bounded classifications and omit verifier exceptions, identifiers, signed
response bytes and secrets; private service diagnostics follow its access policy.

## Bounds and delivery evidence

The reference profile caps decoded request bodies at 64 KiB, clientDataJSON at
8 KiB, authenticator data at 8 KiB, `none` attestation objects at 16 KiB, credential
IDs at 1–1023 bytes, supported COSE keys at 1024 bytes, user handles at 1–64 bytes,
and ES256 DER signatures at 72 bytes. Bound JSON/CBOR nesting and entry counts
before allocating or traversing. Unsupported versions/encodings fail; there is
no legacy decoder or relaxed fallback. Parser #26 and browser #25 must publish
their exact implemented bounds and account for these contracts.

[Normative case inventory](../../tests/webauthn/rp-contract-cases.json) records
required outcomes for real signed fixtures and storage races in #27. The inventory
is a design input; the linked executable reference suite and exact-revision
evidence report establish actual signature/store results, not browser evidence. #30 adds actual browser
engines/virtual authenticators; #31 retains physical-device evidence. #32 may
combine app login and native signing only after #24/#25/#26/#27 review/merge and
those separate boundaries are visible. Independent security sign-off remains #34.

Owner-authorized implementer review/merge of #23 records the selected contract;
it does not stand in for implementation conformance or independent review.
GitHub [#23](https://github.com/Resilience-Network/sdk/issues/23) owns the review
link and acceptance; future evidence must identify the verifier version, store,
runtime, exact revision and actual results, including unsupported coverage.
