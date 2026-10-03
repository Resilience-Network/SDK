# WebAuthn browser helpers

The root and `@resilience-network/sdk/webauthn` exports provide
`webAuthnCapabilities`, `createPasskeyCredential`, `getPasskeyAssertion`,
`serializePasskeyRegistration`, `serializePasskeyAssertion` and
`WebAuthnBrowserError`. Imports do not access browser globals or prompt.
Capabilities are checked at call time, without network requests or a device probe.
Availability means that a secure context exposes the required browser methods;
it does not promise a usable authenticator, biometric verification or hardware.

[ADR-0002](../decisions/0002-authoritative-webauthn-rp.md) defines the authoritative
application RP. The application obtains a persisted server challenge/options under
its authenticated account/browser binding. The helpers never fetch/generate a
challenge, automatically retry a prompt/verification POST, store keys or issue a
session. A browser result is untrusted transport data until the RP verifies and
commits it. `none` registration remains awaiting proof: a fresh verified assertion
must prove key possession before enrollment completes.

## Explicit options and supported profile

Options must be plain objects with own data properties, without getters or
inherited required fields. Every ceremony requires `rpId`, exact serialized `origin` and a 32-byte server
`challenge`. The current page origin must match. RP ID must be a lowercase ASCII
host matching the origin host or a dot-delimited parent; browser enforcement still
owns public-suffix/domain validity. Production origins use HTTPS. HTTP
`localhost`/`127.0.0.1` needs `developmentLoopback: true` and a browser-reported
secure context. Origin paths, credentials, noncanonical ports, wildcards and
opaque/related origins are unsupported. This helper requires a top-level page;
iframe ceremonies are outside this profile.

Registration additionally requires `rpName`, `userHandle` (1–64 opaque bytes),
`userName` and `userDisplayName`; optional `excludeCredentialIds` prevents known
credentials from being selected again. Names are application display labels,
never secret/Chain key material. RP name is 1–128 UTF-16 units; user names are
1–256, without ASCII control characters. Assertions require a nonempty explicit
`allowCredentialIds` list for the account. Credential descriptors are unique,
1–1023-byte IDs, at most 32. Discoverable account selection is unsupported.

The browser request hardcodes ES256 (-7), `userVerification: "required"`,
`attestation: "none"`, and registration `residentKey: "preferred"`. It provides no
algorithm/extension/attestation/UV override, provider persistence or custody
option; unknown option fields fail. Resident preference does not prove a
credential is discoverable, device-local or synchronized.

```ts
import {
  createPasskeyCredential,
  getPasskeyAssertion,
} from "@resilience-network/sdk/webauthn";

// Values come from the application's authenticated RP, not local generation.
const registration = await createPasskeyCredential({
  rpId: server.rpId,
  origin: server.origin,
  rpName: server.rpName,
  challenge: server.challengeBytes,
  userHandle: server.userHandleBytes,
  userName: server.userName,
  userDisplayName: server.userDisplayName,
  excludeCredentialIds: server.existingCredentialIds,
  signal: controller.signal,
});
// Send registration once to the application's bound verification endpoint.
// The RP stores awaiting-proof enrollment; registration does not log in the user.

const assertion = await getPasskeyAssertion({
  rpId: login.rpId,
  origin: login.origin,
  challenge: login.challengeBytes,
  allowCredentialIds: login.allowedCredentialIds,
  signal: controller.signal,
});
// Only the RP's committed assertion result can authenticate the application.
```

This snippet describes application-owned values/endpoints; it is not a deployed
server or an executed combined example. Reference verifier conformance is #27;
combined native/application integration is #32.

## Ownership, projection and limits

Options are synchronously copied before the async browser call. Challenge and
user handle are owned ordinary nonshared views; the bounded representation
[parser](webauthn-parsers.md) enforces intrinsic sizes. The browser result projects
only the supported credential ID/type/response fields, empty extension results
and optional attachment observation. IDs/raw IDs must agree canonically. Binary
response fields become canonical unpadded base64url strings. Objects/nested
responses/transport lists are frozen; later mutation of input buffers cannot
change returned strings. Original client JSON, authenticator bytes and DER
signature are preserved. No `verified` or native-authority field is returned.

Client JSON, authenticator data, attestation, COSE and DER bounds come from the
parser reference (8 KiB / 8 KiB / 16 KiB / 1024 / 72 bytes). User handles are null
or 1–64 bytes; null is forwarded for the RP's account-bound rule. Nonempty
extension outputs, non-ES256 keys, non-`none` attestation, malformed structures,
absent UP/UV and cross-origin/top-origin fields fail locally. Registration key/ID
and assertion allow-list agreement are checked. Standalone serializers validate
representation only; ceremony wrappers also compare original challenge/origin
and RP hash with their owned options. The RP must independently repeat all
required checks against persisted trusted data and verify the signature, expiry,
account, counter/backup state and atomic store commit. Client checks can be bypassed
by a caller and cannot replace authoritative verification.

Registration transports are optional informational observations: a unique list
of at most 8 supported strings (`usb`, `nfc`, `ble`, `internal`, `hybrid`,
`smart-card`). Attachment is null/absent, `platform` or `cross-platform`. Unknown
values fail the narrow profile; no device/hardware/biometric claim follows.

## Cancellation and bounded failures

`timeoutMs` is an integer 1–180,000 (default 180,000). Browser UI timeout is
accompanied by a local timer and monotonic completion deadline. It never extends
server challenge validity. A pre-aborted `signal` prevents prompting; in-flight
abort or timeout rejects promptly and aborts the signal passed to the browser.
Even if a browser ignores cancellation, late success/rejection cannot change the
settled outcome; rejection handlers remain installed. Listeners/timers are removed.
No automatic retry occurs; obtain a fresh RP challenge after an uncertain result.

`WebAuthnBrowserError.code` is `INVALID_ARGUMENT`, `INVALID_CONTEXT`,
`UNSUPPORTED`, `CANCELLED`, `TIMEOUT`, `DENIED_OR_UNAVAILABLE`,
`ALREADY_REGISTERED`, `INVALID_RESPONSE` or `BROWSER_FAILED`. Errors use a fixed
message without response bytes, browser exceptions, identifiers or abort reasons.
`NotAllowedError` does not distinguish a denial, absence or browser timeout;
`DENIED_OR_UNAVAILABLE` preserves that uncertainty. These helpers do not acquire
native nonce reservations or authorize Chain actions.

## Verification boundary

[Executable contract tests](../../tests/webauthn-ceremonies.test.mjs) cover mocked
browser APIs, independent representation fixtures, option copies, contexts,
cancellation, controlled timeout/late completion and sanitized hostile inputs.
Installed package checks verify exports/types and cold Node imports. These are
not actual browser-engine or signed RP authentication evidence. #30 qualifies
engines/virtual authenticators; #31 records physical devices; #27 qualifies the
maintained authoritative verifier/store wrapper. Independent review remains #34.
The API follows [W3C WebAuthn](https://www.w3.org/TR/webauthn-3/), with an explicitly
narrower application profile.
