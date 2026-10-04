# Installed browser qualification

The [strict browser runner](../../scripts/check_browser.mjs) builds a consumer
from the actual npm tarball and bundles the public root/core/session/rpc/display/
webauthn entrypoints using exact-pinned esbuild 0.28.2. No server verifier or
unresolved Node-only import may enter the browser output. Playwright 1.63.0
launches each requested engine in an isolated disposable context; no existing user
profile, passkey, account or browser tabs are accessed.

The currently qualified profile is **Google Chrome 154.0.8037.95, headless,
macOS 26.6.2 arm64**, using the installed Chrome channel. These results do not
qualify another version/distribution/OS or an emulated mobile device. Node support
remains the pinned Node 24.21.0 profile. Exact revision/OS/browser versions are
recorded on every run and in its delivering GitHub PR.

Other browser engines are not advertised as qualified. Official Playwright
Chromium 153.0.8010.12/v1243, Firefox 155/v1543 and WebKit 26.6/v2359 downloads
repeatedly timed out on this runner. **#69 retains that external provisioning and
remaining engine qualification gap**. A build/mocked API test is not an engine
pass. The default full matrix fails if any requested engine is unavailable;
selecting an explicit local profile never converts omitted engines into passing
or skipped-required results. v0.2/release qualification is not silently waived.

## Commands and requirements

```sh
npm ci
npm run check
npx playwright install --no-shell chromium firefox webkit
npm run test:browser
```

The default `RSC_BROWSER_ENGINES` is `chromium,firefox,webkit`. To reproduce the
actual available installed Chrome profile:

```sh
RSC_BROWSER_ENGINES=chromium RSC_BROWSER_CHROMIUM_CHANNEL=chrome npm run test:browser
```

An explicit requested-engine list contains unique names from `chromium`, `firefox`
and `webkit`; each requested engine must actually pass. Chromium channel may be
`chrome`, `chromium` or omitted for the bundled default. No binary download,
physical device prompt, engine fallback or skipped unavailable-engine success is
performed inside qualification. Install official binaries separately. The
[Playwright browser guide](https://playwright.dev/docs/browsers) describes binary
version coupling and branded channels. Esbuild/Playwright are development-only
qualification dependencies.

## Actual checks and boundaries

Every requested engine imports all installed entrypoints with fetch/credential
calls trapped, then checks the independent Keccak answer, pinned native canonical
intent/hash vector, exact bigint width and absence of Node globals. Actual
browser execution also creates ephemeral externally owned Ed25519/P-256 raw
signer providers and verifies signing/encoding/canonical review through the SDK.
No browser private signer key is returned or persisted. These signing checks
qualify bytes/crypto execution, not live Chain authorization or finality.

Chromium additionally uses a CDP CTAP2.1 internal virtual authenticator with
resident-key and required UV support. Actual browser helpers create a credential;
the separately reviewed Node RP reference stores it as awaiting proof. A fresh
actual assertion is cryptographically verified before the RP commits authentication.
The suite rejects replay, revocation, nine mutations of actual response data
(challenge/origin/type/RP hash/UV/signature/ID/BE/extensions), and proves a real
browser assertion signature fails native SessionDigest verification. It exercises
pre-abort, observed in-flight browser-call cancellation, presence-blocked bounded
failure, bad-UV response override and a fresh valid recovery ceremony.

Cancellation resolves locally before a user agent is necessarily finished closing
its underlying operation. The fixture observes native promise settlement before
starting its next independent prompt; no sleep or automatic prompt retry substitutes
for that synchronization. A presence-blocked browser can report either the local
`TIMEOUT` or its own indistinguishable `DENIED_OR_UNAVAILABLE`; the actual bounded
classification is recorded, not renamed. Controlled unit tests separately prove
the local monotonic deadline/timer behavior.

No CDP method that exports credential private keys is called. The virtual
configuration and actual outcome codes are retained without keys, IDs, user
handles, raw challenges or signed responses. It does not prove Face ID, Touch ID,
Windows Hello, physical PIN/biometric provenance, hardware protection or actual
user consent. Firefox/WebKit virtual ceremonies are not advertised by this CDP
fixture; new engine adapters need separately reviewed actual evidence. Physical
qualification remains #31 and independent security review #34.

## Ownership and evidence

The [harness](../../scripts/browser_harness.mjs) owns its new temporary consumer,
loopback-only asset server, browser contexts and virtual authenticator. It closes
owned resources on success/failure. Successful public consumer trees are removed
only after their ownership marker matches; failed public fixtures are retained for
inspection. Existing user/browser/Chain state is preserved. Recorded HTTP paths
are bounded and only generated bundle assets are served.

Ignored `artifacts/browser/latest.json` (0600) records actual result, requested and
unrequested engines, distribution/version, source hashes, tarball hash, bundle
size, check outcomes, OS/Node, SDK revision/clean status and explicit limitations.
Failures produce a failed report and nonzero command status. A previous revision's
report is historical evidence; verify matching revision/source hashes and result.
No hosted/browser PASS follows from an absent workflow. Actual local results are
attached to the issue/PR; #69 and other external gates remain unpassed.
