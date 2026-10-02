# SDK implementation plan

This is the canonical design and delivery sequence for the standalone Resilience
Network TypeScript SDK. GitHub issues own assignments, priority and current work
status; PRs own implementation and verification evidence. This plan describes
intended behavior; the [canonical API](docs/reference/canonical-api.md) documents
the available core/session subset; the [HTTP API](docs/reference/http-rpc.md)
documents implemented envelope transport. Neither establishes production qualification.

Origin: [Chain#25 / FR-013](https://github.com/Resilience-Network/Chain/issues/25).
The [GitHub delivery goal](https://github.com/Resilience-Network/sdk/issues/13)
defines completion and owns the actionable hierarchy; the
[tracking guide](docs/guides/project-tracking.md) explains milestones and progress views.
The [source baseline](docs/reference/protocol-sources.md) pins the Chain revision.
This initial scope adds no chain state, gas, activation, manifest or genesis rules.

## 1. Product objective and boundaries

Enable a wallet or dApp developer to construct exact Transaction V2 intents,
explain bounded authority, collect signatures from explicit signer adapters,
submit transactions and inspect canonical results. Browser passkey ceremony
helpers are a separate capability with a documented authorization boundary.

The first working milestone is an externally Ed25519-authorized grant followed
by a valid bounded session transaction and finalized revocation on disposable
localnet. A biometric/passkey prompt alone cannot create root authority or a
native session signature under today's protocol.

### Initial feature scope

- Canonical transaction intents/envelopes, root config/witnesses, session
  witnesses, root activation, grant actions and transfer policies, including exact widths and bounds.
- Keccak-256 hashes and typed chain/genesis, intent, direct/root/session, policy,
  key-fingerprint, grant-ID and transaction-ID constructions.
- Explicit DIRECT/ROOT Ed25519 and SESSION Ed25519/P-256 signer interfaces.
- Chain identity checks, root/grant/nonce/usage reads, fees, authorization gas,
  simulation, submission, lookup and receipts.
- Grant creation, individual/revoke-all lifecycle, expiry and nonce discipline.
- Canonical permission review and transaction review data, rendered by the app.
- WebAuthn ES256 registration/authentication helpers and strict parsing boundaries.
- Independent vectors, adversarial tests, browser coverage and localnet examples.

### Deferred capabilities

Shielded Orchard proof generation/scanning, hardware-wallet integrations,
custodial key services, account-provider extensions, independent state/finality
proof verification, guardian recovery UI, staking/name-service convenience APIs,
nonzero sponsorship and WebSocket subscriptions are later scoped work. Their
existing chain fields must still be accounted for in canonical encoding; an
unsupported SDK feature fails explicitly instead of dropping fields.

The SDK must not promise Ethereum transaction-wire compatibility. Unknown
versions/actions/flags fail closed. No old-format migrations, alternate decoders
or legacy fallback are planned. Each release has one documented protocol baseline.

## 2. Package and repository architecture

Begin with one npm package and one repository. Split packages only after a
demonstrated distribution or runtime boundary requires it. Proposed name:
`@resilience-network/sdk`; registry ownership and availability are release gates.

Source modules and export boundaries:

- `src/core/`: byte codecs, checked integers, hashing, chain identity and errors;
  entry `@resilience-network/sdk/core`.
- `src/session/`: policy/grant codecs, witnesses, typed digests, lifecycle and
  signer contracts; entry `@resilience-network/sdk/session`. Lifecycle and signer
  APIs follow the implemented codecs/hashes in P3.
- `src/rpc/`: injectable HTTP transport, validated method contracts, queries,
  simulation, submission and receipt tracking; entry `@resilience-network/sdk/rpc`
  currently implements bounded HTTP envelope transport.
- `src/webauthn/`: browser ceremonies, credential serialization and supported
  ES256 response parsing; planned entry `@resilience-network/sdk/webauthn`.
- `src/display/`: structured review data derived from decoded canonical bytes.
- `tests/`: unit/adversarial, versioned vectors, Go differential and browser suites.
- `examples/`: a basic session lifecycle and a separate passkey ceremony example.

Core/session codecs, hashes and HTTP envelope transport are available. Typed RPC
methods, reconciliation, display, signers and WebAuthn remain planned. Do not add
placeholder functions that claim support.

Use ESM with emitted declarations, strict TypeScript, `Uint8Array` for binary
values and checked `bigint` for amounts/nonces/heights. Never round a protocol
integer through JavaScript `number`. RPC quantity and byte encodings have distinct
parsers. Inputs are validated before allocation; decoding has bounded resource use.

Core/session imports must be usable without `window`, `navigator`, DOM state or
Node-only modules. The WebAuthn entry checks secure context and supported APIs at
call time, not module import. A Node import must not trigger a browser ceremony.
Runtime crypto dependencies must be reviewed, pinned and proven against vectors.
The core uses exact-pinned `@noble/hashes` and `@noble/curves` for Keccak and session
point validation. Their use does not satisfy the independent SDK review in P7.

## 3. Authorization and signing flow

1. Configure an expected chain ID, genesis hash and supported authorization
   capability from trusted deployment configuration. Query
   `rsc_getAuthorizationFinalityStatus` and reject mismatches. Node-reported
   identity is an observation, not independent proof of trust.
2. Read root authority, nonce, current grants/usage and finalized state context.
   Record the block context; refresh when separate reads observe inconsistent
   heads rather than inventing a historical selector the endpoint does not accept.
   If the account is still DIRECT, explicitly authorize
   `ActionActivateAuthorization` with its existing Ed25519 signer, the chosen
   root configuration and security reserve. Wait for finalized activation and
   reread authority before creating a grant. Never assume onboarding activates it.
3. Generate or obtain a session public key through an explicit signer adapter.
   Keep session secrets separate from root secrets. The SDK never sends either
   private key to RPC and does not persist keys by default.
4. Build a canonical policy and grant intent. Decode the actual canonical bytes
   for the review display: chain/account, scheme and key fingerprint, application
   context, allowed actions/recipients/contracts/selectors, validity heights,
   value/fee/attempt/rate limits, deposits and code/proxy risks.
5. Collect exactly the required, canonically ordered Ed25519 root witnesses.
   Root signing is an explicit external wallet/provider responsibility; browser
   authentication alone is insufficient. Submit, then verify receipt/action
   success and current grant state before using the grant.
6. Build a session intent with the actual nonce, fees and policy evidence. Freeze
   canonical bytes before signing and detect mutation during asynchronous signer
   calls. Sign the exact raw digest appropriate to the scheme, assemble witnesses,
   estimate/simulate with the actual witness shape, then submit.
7. Track accepted, included and action-success outcomes separately. A failed
   included action can consume nonce and fees. On an ambiguous timeout, reconcile
   the known transaction ID and authorization state; do not automatically create
   and sign a replacement or reuse consumed authority. RPC lookup is bounded, so
   an unknown lookup does not establish historical non-inclusion.
8. Serialize account/root or grant nonce operations through an explicit
   coordinator. Multi-tab/process coordination needs an app-supplied adapter;
   document limits. Retry idempotent reads with bounded backoff/cancellation;
   retry sends only through explicit reconciliation policy.
9. Revoke using root authority, wait for finalized success and reread grant state.
   Dropping a local key or toggling a UI switch does not revoke on-chain authority.

## 4. Passkey decision and security contract

The accepted constraint in [ADR-0001](docs/decisions/0001-passkey-authorization-boundary.md)
is that native P-256 session verification is not WebAuthn verification. WebAuthn
ES256 signs SHA-256 over authenticator data and the client-data hash; the chain
expects ECDSA over its already computed SessionDigest. DER-to-raw conversion only
changes representation. Browser WebCrypto ECDSA also hashes supplied input; blindly
passing SessionDigest causes an additional hash and is not a valid raw signer.

The initial SDK can provide browser authentication helpers and separately valid
session signer adapters. It cannot promise passkey-only on-chain onboarding.
Before a combined passkey-wallet example, choose and review one trust model:

- An existing Ed25519 wallet authorizes the grant; passkeys authenticate the app,
  with app-owned key storage/unlock explicitly described and reviewed.
- A protocol/contract authorization design validates the complete assertion at
  the authority-enforcement boundary. It needs separately scoped Chain work and
  is outside this consensus-free SDK bootstrap.

No default custody service, passkey-to-root conversion or synthetic passkey
signature is allowed. The SDK will expose capability boundaries explicitly.

WebAuthn deliverables must address:

- Secure-context capability checks, cancellation, denied/cancelled prompts and
  ES256 algorithm selection; no assumptions about a specific biometric modality.
- Authoritative RP-generated unpredictable challenges with expiry and one-use
  consumption; verification must bind type, exact challenge, allowed origin and
  RP-ID hash. Client validation is defense in depth, not an authoritative verifier.
- User-presence/verification flags and explicit cross-origin/top-origin policy;
  authenticators' backup/counter semantics cannot be reduced to a mandatory
  monotonic counter for synced credentials.
- Valid COSE EC2/P-256 keys, bounded CBOR/authenticator structures and strict DER
  integer/length/range checks; verify signatures against the actual signed bytes.
- Registration records, credential IDs, algorithm and attestation policy. Default
  attestation policy must not imply attested hardware or biometric provenance.
- Replay, malformed/truncated data, unsupported algorithms, wrong origin/RP,
  wrong challenge, absent UV and tampering cases. Relying-party server verifier
  integration and storage remain explicit responsibilities.

XSS or a compromised signing process can defeat app-side checks. Avoid key
logging, unsafe HTML, hidden approvals and unreviewed secret storage. RPC values
are untrusted until validated; independently authenticated proofs are deferred.

## 5. Delivery stages and dependencies

### P0 — Repository foundation

Deliver contributor/agent rules, strict build and locked dev tools, package smoke
checks, documentation, source provenance, issue templates, manual CI and this
plan. Bootstrap acceptance requires a published topic-branch PR with local
evidence, while Chain#25 remains open. This stage implements no signing features.

### P1 — Canonical core and independent conformance

Depends on P0. Inventory the exact pinned chain codec fields, versions, limits,
domains and supported actions. Snapshot available independent vectors with source
commit, file hash and regeneration instructions; identify missing or stale vectors
before porting behavior. Update a source/vector conflict through reviewed Chain
work instead of changing golden values to match the SDK.

Implement checked bytes/u64/u256, canonical intents/envelopes/root/session
witnesses, root configuration/activation, grant/revoke actions and transfer policy codecs.
Account for fee and sponsor fields even when sponsorship is unavailable. Add
Keccak known-answer tests (`empty`, `abc`) and the typed hashes for these data:
chain domain, intent/transaction IDs, authorization signing digests, root/policy
hashes, key fingerprints, grant IDs, authorization storage keys and recipient
tree hashes. Receipt-counter/decision hashes follow their receipt/state codecs.

Acceptance: byte-for-byte encodings/digests/IDs agree with independent and Go
references; malformed lengths, trailing bytes, duplicates/order, unknown
versions/schemes and overflow are rejected. Add deterministic mutation/property
coverage with retained seeds and bounded decode allocation. Self-roundtrips alone
are insufficient. Every initially supported action has an explicit coverage list.

### P2 — Typed HTTP RPC and reconciliation

Depends on P0; transaction helpers depend on P1. Validate request/result IDs and
schemas, quantity encodings and error families. Implement root/grant/nonce/usage,
identity/finality-context, policy decode/preview, fees, estimation/simulation,
submission and receipt/transaction lookup. Treat HTTP errors, malformed JSON,
JSON-RPC errors and cancellation separately. Use injectable fetch, timeout and
bounded idempotent-read retries. Batch requests must honor server limits.
Implement the deferred canonical receipt-counter-delta/decision models and typed
hashes alongside receipt contracts, with independent native Go conformance.

Implement this stage in bounded steps: transport/error contracts and deterministic
adversarial plus actual HTTP tests (#14), identity/read schemas (#15), submission/
receipt models (#16), then reconciliation/polling (#17). Transport returns
untrusted results and cannot substitute for method validation. Keep retries on a
fixed read-only allowlist; sends get one attempt. Investigate node/schema conflicts
before adding convenience APIs. Correct omitted nil-success results upstream and
review the protocol baseline before claiming interoperable null lookups/receipts.

Acceptance: pinned-handler contract fixtures, malformed-response and rate-limit
tests, identity mismatch rejection, deterministic timeout behavior and ambiguous
send reconciliation. Do not auto-resign/reuse a nonce after an uncertain result.

### P3 — Signers and bounded session lifecycle

Depends on P1/P2. Add external Ed25519 direct/root and Ed25519/P-256 session signer
contracts with explicit raw-digest semantics. Verify public keys/signatures and
scheme restrictions; test raw-vs-prehashed and WebAuthn confusion cases. Implement
explicit DIRECT-to-ROOT activation, grant creation, policy-hash/key-fingerprint identity, nonce coordination, transfer,
revoke and revoke-all. Enforce exact threshold/order and state/expiry checks.

Acceptance: Go accepts both supported session schemes; rejects wrong chain,
genesis, key, epoch, policy, nonce, expired/revoked authority and P-256 ROOT/DIRECT.
Included action failure is reported with consumption semantics. No secrets cross
RPC and no transaction can mutate between review and signing.

### P4 — Canonical permission review

Depends on P1/P3. Produce structured display data from the exact decoded policy
and intent bytes, with stable base-unit formatting, height semantics and a clear
application-context trust boundary. Show unrestricted authority explicitly.
Do not label unverified code hashes, app names or approximate expiry as trusted.

Acceptance: golden review fixtures bind to canonical bytes/hash; adversarial tests
cover selectors, recipient sets, omission, precision, Unicode/application labels,
code/proxy warnings, limits and expiry. No UI framework dependency is required.

### P5 — Passkey trust model and ceremony helpers

Depends on P0; combined examples depend on P3/P4 and a reviewed authorization
decision. Specify supported off-chain use, who verifies ceremonies, where keys
live and who authorizes on-chain grants. Implement feature detection, credential
create/get, serialization, supported key extraction and strict signature parsing.
Offer full assertion verification only with a separately specified authoritative
verifier contract and reviewed implementation; parsing is never named verification.

Acceptance: virtual-authenticator/browser tests and negative origin/RP/challenge,
UV/replay/DER/CBOR/key cases; explicit proof that raw assertion signatures are not
accepted as session witnesses. Track any Chain extension in a separate issue.

### P6 — Browser/localnet examples and end-to-end evidence

Depends on P1–P5 for combined scope; a session-only example can run after P3/P4.
Build reproducible disposable localnet setup tied to the pinned Chain revision,
explicit signer provisioning with test-only keys, and cleanup confined to owned
temporary paths. Demonstrate finalized create/use/revoke, both session schemes,
expiry/replay/wrong-context failure and consumed nonce on action failure. Include
DIRECT-to-ROOT activation in the onboarding example, with explicit root config,
reserve and funded test accounts rather than silently presuming a rooted account.

Browser tests cover supported engine behavior and error/cancellation. Virtual
authenticators do not establish physical Face ID, Touch ID or Windows Hello
coverage; device checks are separately recorded, including browser/OS. Concurrent
tabs/sends and uncertain submissions must be tested against the chosen coordinator.

Acceptance: retained revision/runtime/commands/logs, actual node acceptance and
correct final receipts/state, independently checked transaction IDs, secrets absent
from retained logs and preservation of pre-existing node/wallet/safety files.

### P7 — Review and reproducible release

Depends on P1–P6. Review crypto dependencies, public API, parsing bounds, display
binding, secret lifetime and passkey trust model independently of the implementer.
Resolve High/Critical findings or block release. Establish supported browser/Node
matrix, dependency license inventory, bundle size/performance budget and docs.

Choose licensing, verify npm scope/name ownership, retain lockfile provenance,
inspect installable tarball and declarations in clean consumer projects, confirm
runtime imports have no credential access or unsolicited network activity, and
define prerelease/version/protocol compatibility policy. Publish only through a
reviewed release PR/tag and owner-authorized registry credentials/process.

Acceptance: all applicable vector/unit/property/browser/differential/localnet
suites pass without required skips, recorded security sign-off, a reviewed license
and verified release artifacts. Removing `private: true` is a release decision.

## 6. Work coordination and estimates

P1, P2 contract design and the P5 authorization decision can proceed independently
after P0. P3 depends on codec/RPC contracts; P4 shares canonical policy inputs.
P6 integration follows implementation. P7 release gates cannot be closed by
scaffold checks. Parallel contributors must claim separate issues and coordinate
shared exports/protocol constants; this is sequencing guidance, not authorization
to take someone else's claim.

Rough initial effort: P1/P2/P3/P5/P6 each M, P4 S, P7 L. A direct on-chain passkey
extension is a separate estimate and could require substantially more protocol
work. Re-estimate after the vector inventory and trust-model decision. No fixed
calendar promise or percentage-complete ledger is maintained here.

### Release milestone mapping

- `v0.1-session-foundation`: P0–P4 plus P6's native localnet harness, session-only
  integration and consumer docs. Exit requires actual funded DIRECT activation,
  grant/use/finalized revocation for both schemes and negative/concurrency/uncertain
  submission evidence, rather than canonical construction alone.
- `v0.2-webauthn-helpers`: P5 plus P6's browser/device/verifier and reviewed combined
  example. Exit requires the approved RP/key model and evidence for every advertised
  ceremony/platform claim; assertions remain separate from raw session signatures.
- `v1.0-sdk-release`: P7 plus all preceding gates. Completion requires reviewed
  merged scope, no required test skips or unresolved High/Critical findings, approved
  licensing/registry/provenance and actual owner-authorized publication verified by
  downstream consumers.

The integration epic spans v0.1/v0.2, while its leaf tasks each have one milestone.
Milestone descriptions on GitHub own current exit criteria. Implementation dates
remain unset until owners and estimates are agreed. Scope changes require review;
tracking setup does not authorize registry publication, custody or chain extensions.

## 7. Parent issue acceptance and change control

Chain#25 originally requests a browser credential producing a valid P-256 session
signature and node acceptance. Today's raw verifier cannot satisfy that wording
through DER conversion. Keep it open and explicitly split the criteria into:

1. Valid session signatures from a supported raw signer accepted on localnet.
2. Browser passkey registration/authentication verified under its own contract.
3. A reviewed decision connecting those capabilities, or a separately delivered
   chain/contract authorization extension for direct passkey authority.
4. Updated canonical wallet integration docs (the current Chain path is
   `docs/guides/wallet-integration.md`, replacing the old path in the issue).

Revise feature scope only through an issue discussion and reviewed design/PR.
Do not claim the original biometric onboarding feature is finished by creating a
repository. SDK issue closures must account for each criterion and real evidence.

## 8. Verification and operational gates

See [testing](docs/guides/testing.md) for available commands and planned gates.
Run `npm ci`, `npm run check` and `git diff --check`. Canonical changes also run
the pinned native Go differential gate. Feature work
must add actual unit/vector/browser/localnet commands to the shared check workflow
or clearly documented integration gate. Do not install a no-op `npm test` command.

Integration consumes Chain as an immutable external dependency. If Chain source
changes are needed, use its issue/branch/PR workflow and full local CI-equivalent
requirements; a pure TypeScript build is not node/native evidence. A mismatch
fails closed and never triggers database, signing-record or key deletion.

GitHub remains private, matching Chain. Hosted workflows remain manual until
their reviewed resumption. This task publishes the repository and bootstrap PR,
not an npm package, network deployment or unreviewed merge.

## 9. GitHub work packages

These links identify scoped deliverables; their live status and ownership are kept
in GitHub, not duplicated here. The RPC through release stage issues (#3–#9) are
acceptance epics with native sub-issues containing reviewable scope, target files,
tests and prerequisites.
The pinned [delivery goal](https://github.com/Resilience-Network/sdk/issues/13)
links the complete hierarchy, milestones and definition of complete.

- [[FR-013:SessionAuth] Implement canonical codecs and independent hash conformance](https://github.com/Resilience-Network/sdk/issues/2) — P1.
- [[API:RPC] Add typed HTTP transport and submission reconciliation](https://github.com/Resilience-Network/sdk/issues/3) — P2.
- [[FR-013:SessionAuth] Add raw signer adapters and bounded grant lifecycle](https://github.com/Resilience-Network/sdk/issues/4) — P3.
- [[FR-013:Wallet] Derive permission and transaction review from canonical bytes](https://github.com/Resilience-Network/sdk/issues/5) — P4.
- [[FR-013:WebAuthn] Specify the passkey wallet authorization and key ownership model](https://github.com/Resilience-Network/sdk/issues/6) — P5.
- [[FR-013:WebAuthn] Implement browser ceremonies and strict ES256 response parsing](https://github.com/Resilience-Network/sdk/issues/7) — P5.
- [[HARNESS:Testing] Add browser and disposable localnet SDK lifecycle evidence](https://github.com/Resilience-Network/sdk/issues/8) — P6.
- [[SEC-GATE:Client] Qualify SDK signing security and reproducible package release](https://github.com/Resilience-Network/sdk/issues/9) — P7.
