# Separate app passkey login and native session example

The executable [combined example](../../examples/passkey-session/run.mjs) connects
actual browser WebAuthn authentication to an application policy gate, then uses
separately owned test native keys on an owned funded four-validator network.
It demonstrates the selected [key model](../decisions/0001-passkey-authorization-boundary.md)
and [RP contract](../decisions/0002-authoritative-webauthn-rp.md). A passkey assertion
is never converted into a native signing credential.

## Run and qualified scope

Use the pinned Node 24.21.0 runtime and a clean immutable native Chain checkout
from [protocol sources](../reference/protocol-sources.md). Build/crypto work uses
native CGO. This example requires an actual provisioned Chromium engine supporting
CDP virtual authenticators. It performs no engine fallback or binary installation.
The installed Chrome 154.0.8037.95/headless/macOS 26.6.2 arm64 profile is separately
[qualified](browser-qualification.md); other engines/devices remain #69/#31.

```sh
npm ci
npm run check
RSC_CHAIN_DIR=/absolute/path/to/clean/pinned/chain \
  RSC_BROWSER_CHROMIUM_CHANNEL=chrome npm run example:passkey-session
```

A failed build, browser launch, proof, native admission, finality observation or
cleanup fails the command. Missing engines are not passing or skipped evidence.
SIGINT/SIGTERM abort native work and close owned resources; failed native runtimes
retain restricted keys/database/signing state for inspection, following the
[native harness ownership rules](native-localnet.md). Never erase that state to
resolve an assertion or timeout.

## What executes

The browser consumer is built from the actual npm tarball. Its cold public imports
must issue no fetch or credential calls. A CTAP2.1 virtual authenticator then
creates an ES256 credential. The maintained server verifier accepts registration
only as awaiting proof; it cannot open the example application gate. Actual invalid
signature, expired challenge and cancelled browser ceremony leave that gate closed.
A fresh actual assertion must pass authoritative verification before the gate opens.
Replaying the response cannot reopen a cleared gate; a new assertion is required.

The public application account and generated funded Chain owner are separate
fixture identities connected explicitly by this disposable application. Production
applications must establish and review that association themselves; the SDK and RP
verifier do not infer native ownership from a passkey credential.

Only after that verified app login does the native fixture provision independently
owned test DIRECT/ROOT/session keys. The example still approves every native
operation from its canonical review. Those explicit fixture approvals are separate
from login: production applications must display the actual canonical review and
obtain transaction consent through their own reviewed UI. Logout/expiry/cancellation
can prevent the app from requesting a signature, but this illustrative in-process
policy is neither a production signer unlock nor on-chain enforcement.

Actual DIRECT activation funds root authority. Closing the app gate rejects native
approval without a signature or RPC submission; a pre-aborted native operation
also preserves account authority. A fresh real login permits ROOT grant creation,
SESSION transfer and finalized ROOT revocation for both raw Ed25519 and P-256.
A previously signed transfer is then refused by both advisory simulation and
actual node admission after revocation, with account state unchanged. Only this
native authority transition revokes the grant; clearing the app gate does not.

The [small application gate](../../examples/passkey-session/app-gate.mjs) consumes
only the Node reference RP's trusted verified result inside this example. It never
accepts browser transport data as a verification decision. Its in-memory permit
has a separate account binding and an exclusive monotonic expiry (at most fifteen
minutes). Meaningful unit tests cover pending proof, wrong account, invalid
lifetimes, expiry, cancellation and clearing/replacement. It is not a durable,
multi-worker or production application session implementation.

## Evidence and secret ownership

Browser virtual credential keys are never requested through CDP export methods.
Browser responses remain in memory; public aggregate output excludes credential
IDs, handles, challenges and signatures. Native test keys stay inside externally
owned signer closures and owned restricted runtime files. They are not derived
from the passkey, persisted by the SDK, sent over RPC or placed in URLs/logs.
Captured native logs are checked against all known validator/wallet/signer private
strings before the example succeeds.

Ignored `artifacts/passkey-session/latest.json` (0600) records exact SDK/source and
tarball hashes, browser version, aggregate outcomes and a native ownership ID.
The referenced `test-results/localnet/<ownership-id>/evidence.json` records actual
native revision, CGO/runtime, operation receipts and owned teardown/log capture.
Successful public browser consumers and owned native runtimes are removed; evidence
remains. Failed restricted native safety state is preserved. Reports from another
revision are historical, not fresh PASS evidence.

This example does not qualify physical Face ID/Touch ID/Windows Hello, another
browser/OS, production custody, recovery, durable RP/session storage or independent
security review. No direct passkey native-authority claim follows from successful
login; any future extension remains coordinated separately in Chain#382.
