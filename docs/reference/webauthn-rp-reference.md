# Authoritative RP conformance reference

The [Node reference](../../examples/webauthn/reference-rp.mjs) executes the
[ADR-0002](../decisions/0002-authoritative-webauthn-rp.md) profile around the
exact-pinned development dependency `@simplewebauthn/server` 14.0.3. It is outside
SDK runtime entrypoints and the published archive: importing the SDK installs no
server, datastore, authentication session, private key or custody provider.
The [maintained verifier documentation](https://simplewebauthn.dev/docs/packages/server)
and the installed exact-version source are the integration baseline.

This is an executable single-process conformance fixture, not a production RP.
Applications own authenticated enrollment/recovery, trusted request bindings,
CSRF, rate limits, deployment and actual durable storage/session transactions.
`ReferenceMemoryRpStore` makes its comparisons/transitions synchronously in one
JavaScript process. A Map is never a multiple-worker lock and does not survive a
restart. No durable store, crash recovery, production session service or independent
security qualification follows from its tests. A production adapter must run the
same conformance cases against its real durable linearizable take/CAS transactions.

## Reference operations and trust

The application puts an existing account with a random opaque 1–64-byte user
handle in the store. `ReferenceRelyingParty` receives an explicit RP ID, exact
origin allowlist (1–8 origins), a trusted clock and the store. Configuration uses
HTTPS or explicitly enabled HTTP localhost/127.0.0.1 development; paths, wildcards,
userinfo and noncanonical serialized origins fail. Never derive these values or
account/browser bindings from client response fields, RPC or forwarding headers.

`issueChallenge(ceremony, trustedContext)` generates two independent 32-byte
CSPRNG values: opaque request ID and challenge. It persists the versioned profile,
account/user handle, authenticated browser-session binding, known credential IDs,
issued time and exclusive 180-second expiry before returning options. Registration
requires `enrollmentAuthorized: true` from a trusted application enrollment gate.
Assertions are account-bound to a unique list of 1–32 stored nonrevoked credentials.
The reference does not implement discoverable account selection or account recovery.

`verify(requestId, originalBodyBytes, trustedContext, { signal })` atomically takes
a matching pending challenge before response parsing or cryptographic work. Wrong
bindings, unavailable IDs, invalid time or storage failure produce no authenticated
result. An observed exclusive expiry changes a pending record to terminal
`expired` before rejection. Rolling the supplied clock back cannot revive it;
a new independent request/challenge is required. Unexpired wrong-binding requests
still cannot burn another account's pending challenge. Production time-source
and durable cross-worker expiry retirement remain application responsibilities.
Invalid bound responses burn a taken challenge. An error, timeout, lost
result or commit failure never restores it; obtain a fresh challenge. Browser UI
success/cancellation and transport retries do not change this server record.

Bodies are owned nonshared UTF-8 bytes capped at 64 KiB. The internal bounded
JSON reader rejects duplicate decoded keys, malformed text and depth/count
excesses before the request is projected. Original base64url fields are strictly
decoded and rechecked using the same supported representation profile on the
server; trusting a previous client parse is forbidden. Unknown request fields,
client `verified` claims and extensions fail. Original client JSON is preserved.
Client data, authenticators, COSE, credential IDs, handles and DER signatures have
the [documented representation limits](webauthn-parsers.md).

The maintained verifier checks the real WebAuthn message against persisted
challenge/origin/RP and the supported key. The wrapper independently enforces
same-origin/top-origin rejection, exact ID/allowed-list/account/user-handle
bindings, required UP/UV, ES256, `none` attestation, supported flags and fixed BE.
Stored record versions, counter ranges, backup invariants and public key integrity
must be valid. There is no alternate cryptographic verifier or legacy decoder.

## Enrollment, counter policy and commit

A verified `none` registration stores a new unique public credential in
`awaiting-proof` state and returns `applicationAuthenticated: false`. It does not
prove private-key possession or grant an authentication session. A fresh actual
verified assertion is required to transition the record to `active`. No credential
insertion can overwrite another account's existing ID.

For single-device BE=false, any nonzero previous/new counter requires an increase;
zero/zero can succeed without clone detection. BE is immutable. For BE=true, the
wrapper applies the reviewed synced-credential policy: it passes counter zero
only to the maintained verifier's stricter counter precheck, still verifies the
actual signature and bindings, then commits the maximum of the actual old/new
counter. The stored counter is never reset. BS can change on a verified assertion.
An executable test shows the maintained strict default rejecting an otherwise
valid synced zero-counter assertion and the wrapper accepting it under ADR-0002.
Challenge consumption, not a synced counter, prevents replay.

A successful signature is insufficient for success. Conditional credential commit
must still match the read storage version, nonrevoked status, account/user handle,
RP/profile and challenge time. Revocation or a competing update fails closed.
Challenge validity is rechecked at completion and commit; cancellation or late
verifier completion cannot update credentials or return authentication success.
The fixture models an authentication outcome in the same synchronous transition;
a real application's session grant belongs in the same durable transaction.
The returned server-only result never includes native signature, biometric,
hardware or on-chain authority claims. Public errors have fixed messages and
bounded codes; raw verifier exceptions and identifiers are omitted.

## Executable evidence

```sh
npm ci
npm run check
npm run test:webauthn-verifier
```

The [suite](../../tests/webauthn-verifier.test.mjs) executes every one of the 67
[normative inventory cases](../../tests/webauthn/rp-contract-cases.json), plus real
maintained-verifier success/false-signature cases, native-domain separation,
both mathematical s values, store integrity, duplicate request JSON, captured
bindings and competing fresh challenge/credential updates. Independently generated
[Node/OpenSSL fixtures](../../tests/webauthn/signed-fixtures.mjs) sign
`authenticatorData || SHA256(original clientDataJSON)` with ephemeral private
KeyObjects held only in memory. They do not simulate a biometric or physical
browser/device. No private keys are written or retained in public evidence.

The [evidence runner](../../scripts/check_webauthn_verifier.mjs) verifies complete
case coverage and zero failures/skips/todos, then writes ignored
`artifacts/webauthn-verifier/latest.json`: exact SDK revision/clean status,
Node/OpenSSL and pinned verifier version/integrity, source hashes, case outcomes
and explicit limitations. It contains no credential IDs, account/user handles,
raw challenges, response/signature bodies, session tokens or keys. Exact-head
results are attached to GitHub delivery; prior artifacts are historical evidence.

Actual engine/virtual authenticator qualification remains #30 and physical device
coverage #31. The combined application/native example is #32. Independent review
is #34; this reference never turns a WebAuthn assertion into raw SessionDigest
signing or waives production RP/store obligations.
