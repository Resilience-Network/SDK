# Testing and evidence

This guide defines what current implementation checks prove and the additional gates
required as SDK features are implemented.

## Available SDK checks

```sh
npm ci
npm run check
git diff --check
```

The check script validates formatting, strict TypeScript, local documentation file
links/source pin, a clean build, unit/vector/mutation suites and an installable
package with root/core/session/rpc import and declaration checks. Tests cover checked
integer boundaries, Keccak known answers, independent canonical/hash vectors,
all supported actions, malformed and oversized inputs, ordering, point validation,
sponsor/context binding, retained mutation seeds and decoded byte ownership
(including Node Buffer inputs). Package smoke tests exercise installed APIs;
they do not establish signature or authority verification.

The [HTTP transport suite](../reference/http-rpc.md) also covers response IDs and
partial batch errors, UTF-8/JSON/structural limits, generated parser cases with
retained seed `0x14c0ffee`, JSON mutations/truncations with seed `0x14badbee`,
request snapshots, diagnostic redaction, fake-clock
deadlines/cancellation/retries, late promise cleanup and single-attempt submissions.
Actual Node fetch tests start owned loopback servers on OS-selected ports and
close their connections in teardown. They cover throttling, truncated bodies,
gzip expansion, redirect prevention and cancellation isolation, with no node/
wallet databases or claim of native acceptance/finality.

Run the affected transport tests after a build:

```sh
npm run build
node --test tests/rpc-contract.test.mjs tests/rpc-resilience.test.mjs tests/rpc-http.test.mjs
```

The suite checks Node behavior and imports without browser state/global fetch;
it does not qualify browser engines. Native [envelope fixtures](../../tests/fixtures/rpc-envelopes.json)
exercise corrected null successes, errors and falsy values through actual Node
fetch. Missing results remain invalid; see the [HTTP API](../reference/http-rpc.md).

Run `npm test` for the build and all Node unit suites. See the
[canonical API](../reference/canonical-api.md) for exact implemented limits and
unsupported sections. The docs checker does not validate external links,
Markdown heading anchors or prose semantics.

Typed [Chain RPC tests](../reference/rpc.md) use production-handler fixtures for
all 12 wire methods, both grant schemes and revoke-all stale records. They exercise
905 missing/unknown-field cases, canonical view binding, integer boundaries,
wrong identity/capability, inconsistent heads, bounded refreshes, overall deadlines
and redacted node error families. Real Node fetch covers concurrent typed batches
and independent response ownership. Run the affected suites after a build:

```sh
node --test tests/rpc-methods.test.mjs tests/rpc-methods-http.test.mjs
```

Hosted [SDK checks](../../.github/workflows/checks.yml) use manual dispatch while
workflows are paused. Full applicable local equivalents are required before a
PR; missing hosted runs are not PASS evidence.

## Mandatory canonical Go differential gate

Use a separate clean checkout at the exact `protocol-source.json` revision;
do not reset an existing working tree or alter its safety state. For example:

```sh
RSC_CHAIN_DIR=/absolute/path/to/pinned-chain npm run test:differential
```

The script rejects a different HEAD, tracked source changes or disabled CGO,
builds native crypto with `make build-crypto`, and compiles the SDK's test-only
[Go oracle](../../tests/go-reference/main.go) against that checkout's production
packages. It compares canonical acceptance/rejection, exact reencoding and hashes
on supported fixtures plus reproducible truncations, trailing bytes and seeded
bit mutations. A valid Chain action outside the initial SDK scope is reported
separately as an explicit unsupported action, rather than counted as conformance.

Seven Go-generated onboarding layouts cover activation, revocation, replacement,
both rotation reserve modes, reserve update and cleanup. Eight additional
storage/recipient/validator hash helpers are compared directly. The fixture bytes
and seed are retained in [test sources](../../tests/helpers.mjs); failure reports
identify the codec/sample/mutation for reproduction. The script's temporary
binary directory is owned and removed by the test. Chain's ignored native build
outputs are kept in the external checkout.

The [independent vector snapshot](../../tests/vectors/chain-v1.json) is copied
byte-for-byte from pinned Chain. Unit tests verify its source SHA-256 before use;
its independent model and regeneration instructions are linked in
[protocol sources](../reference/protocol-sources.md). Do not format or regenerate
the snapshot to make an SDK failure pass. A new protocol baseline needs reviewed
source, provenance, fixtures and API changes together.

This gate is required locally for canonical changes. The manual SDK workflow runs
`npm run check`; native differential testing requires the separate private Chain
checkout and its toolchains, and is not claimed by that hosted job. Neither check
proves signature acceptance, stateful authorization, browser behavior or localnet
finality. Those gates follow their feature implementations.

## Native RPC contract fixture gate

For RPC schema/canonical projection changes, run against an owned clean checkout
at the immutable protocol revision:

```sh
RSC_CHAIN_DIR=/absolute/path/to/pinned-chain npm run test:rpc-native
```

The [checker](../../scripts/check_rpc_contracts.mjs) rejects wrong HEAD, tracked
changes and disabled CGO, runs `make build-crypto`, then installs an exclusively
created, uniquely named SDK test file in the pinned `internal/rpc` package. This
test uses production Handler/API/state with the pin's existing test-only mockChain
and policy helper. It creates only in-memory databases and fixed test-only signing
keys; no keys or private material are exported in fixtures. It verifies simulation
does not change the backing state. The owned file is removed in `finally` only
after its contents are checked; existing files are never replaced or removed.
Native build outputs remain in the external checkout.

The gate compares all 35 envelopes/parameters/identities byte-semantically against
[retained fixtures](../../tests/fixtures/rpc-contracts.json). To intentionally
regenerate after inspecting a source/projection change:

```sh
RSC_CHAIN_DIR=/absolute/path/to/pinned-chain node scripts/check_rpc_contracts.mjs --write
```

Record the semantic reason and rerun ordinary SDK tests and the comparison gate.
No source pin or independent codec golden vectors change as part of generating
these fixtures. This gate is local and is not included in the manual SDK-only
workflow; it requires the private Chain checkout and native toolchains. It proves
native handler/SDK contract agreement on the pin, not a running-network funded
lifecycle, P-256 signer acceptance, browser qualification or release sign-off.

## Native signature verification gate

```sh
RSC_CHAIN_DIR=/absolute/path/to/pinned-chain npm run test:signatures-native
```

The [checker](../../scripts/check_signatures.mjs) rejects wrong HEAD, tracked
source changes and disabled CGO, runs `make build-crypto`, and compiles the owned
test-only [Go oracle](../../tests/go-signature-reference/main.go) without modifying
Chain source. It removes only its temporary binary directory; native crypto build
outputs remain in the pinned checkout. No databases, existing keys or signing
watermarks are used or removed. All signing keys are predictable public test data.

The gate verifies SDK-assembled transactions through production DIRECT, ROOT and
SESSION verification. Independent Node/OpenSSL Ed25519 and Go standard Ed25519/
P-256 signing, ROOT thresholds 1–8, high-S, wrong context/nonce/epoch/key/intent,
signature mutations with seed `0x18a11ce`, malformed witnesses, actual WebCrypto
double hashing and a different assertion message are covered. Explicit Ed25519
cofactor-only signatures fail in SDK and Go; an exact-equation mixed-order key is
accepted by both, preserving the pin's actual rule rather than adding a key ban.

Run affected SDK tests after building:

```sh
node --test tests/session-signers.test.mjs
```

The [signer API](../reference/signers.md) explains external ownership and limits.
The unit suite covers mutation/cancellation/deadline isolation and diagnostic
redaction. The native gate proves stateless signature agreement, not grant policy/
budget execution, funded localnet lifecycle, device qualification or independent
security approval. It requires the private pinned checkout and is not included
in the SDK-only manual hosted workflow. Run the canonical differential gate for
this signing change as well as full SDK checks.

## Further feature gates

- Extend unit/vector, mutation and differential cases for each added codec/hash,
  policy/action or signing feature. Retain minimized failures as regressions
  instead of editing expected hashes; record source/vector gaps explicitly.
- RPC contracts: validated results/errors, transport cancellation, identity
  mismatch, pagination/batch bounds, ambiguous sends and bounded historical lookup.
- Browser: WebAuthn virtual authenticators, unsupported APIs, UV/origin/RP/challenge
  validation and cancellation; record each engine. Physical biometric/device
  evidence is separate from virtual-authenticator results.
- Localnet: actual grant/create/use/revoke for both session schemes, final receipts,
  expiry/replay/wrong-context rejection, failure consumption and concurrent nonces.
- Release: clean installed consumer checks, export/type resolution, dependency
  inventory, security review and retained reproducible artifacts.

Add executable commands when their implementations exist. Empty test directories,
roundtrips through one implementation and mocked node acceptance are not substitutes
for the required independent or integration evidence.

## Chain integration requirements

Native tests require `make build-crypto` first. If modifying Chain source, its
local pre-PR equivalent is mandatory: `make build-crypto`, `go mod verify`,
`go vet ./...`, `make lint-determinism`, `go test -race -count=1 ./...`,
`go test -tags storytests -count=1 ./internal/p2p/ -run 'TestByzantine|TestStoryGate'`
and the `./fuzz/...` smoke targets. Follow its current testing guide for exact
fuzz commands/toolchains and run `python3 scripts/check_docs.py` for Chain docs.
These are not SDK-only checks. `CGO_ENABLED=0` is not native shielded
verification. Hosted pauses do not waive local gates.

New Chain stories have unique STORY_ID, STORY_NAME and STORY_TIMEOUT headers;
do not edit the runner simply to register them. Integration setup/cleanup owns
only its disposable data/processes and never deletes existing keys, wallet data,
databases, validator locks or signing watermarks.

## Reporting

Record command, revision, pinned Chain revision when relevant, runtime/browser/OS,
result, meaningful limits and retained artifacts. Describe a required skip or
blocked test explicitly. Historical PASS claims are revision-bound and cannot
be copied as new evidence. An independent security review is a separate gate
from implementer tests or these implementation checks.

## Canonical review checks

After building, `node --test tests/display.test.mjs` checks the field goldens,
all supported actions and digest modes, zeros/disabled limits, maximum recipient/
proof shapes, exact u256 formatting, frozen snapshots and bounded deterministic
mutations. Goldens in `tests/display/golden/fields.json` are authored from pinned
independent vectors, not regenerated from display output. `npm run check` includes
this suite and installed `/display` runtime/declaration consumers. Review changes
that alter canonical hash use also run `npm run test:differential` against the
immutable native pin. Review is structure-only, not signature/live-authority proof.

`node --test tests/review-signing.test.mjs` verifies approval-to-signer binding
for all modes/schemes, mutation before any key callback, finite precision and
policy/authority/proof field coverage, rejected/failed approval, cancellation and
shared deadlines. The SDK-only review hash uses independent Python Keccak
goldens with explicit wire/metadata provenance. `test:signatures-native` also
exercises approved callbacks before production Go acceptance/negative replay.

## Receipt commitment and observation checks

`node --test tests/receipts.test.mjs` checks independent field/hash fixtures, every
truncated length, exact consumption semantics for constructed native projections,
required-field deletion/unknown fields, numeric/context/nonce/fee/event mutations,
unknown/pending lookups, copied canonical input, moving head refresh and bounded
abort/deadline behavior. Actual Node HTTP runs concurrent native receipt batches
with independent output ownership. These are projection/transport checks, not
funded execution or independent finality verification. See [receipt API](../reference/receipts.md).

```sh
RSC_CHAIN_DIR=/absolute/path/to/pinned-chain npm run test:receipts-native
RSC_CHAIN_DIR=/absolute/path/to/pinned-chain npm run test:rpc-native
RSC_CHAIN_DIR=/absolute/path/to/pinned-chain npm run test:differential
```

The receipt native gate requires clean exact pinned HEAD and CGO, builds crypto,
and exclusively installs a temporary owned test in native sessionauth. Production
counter/event codecs and internal decision seal/shape rules produce independent
fixtures. The test-only decision decoder is a commitment oracle, never an exported
node protocol decoder or policy evaluator. Exact bytes/hashes and acceptance are
compared for every truncated length and 48 seeded bit mutations per fixture
(seed `0x16ce1a`). Owned tests/temporary data are removed only after content
ownership verification; native build outputs are retained. The full differential
command includes this gate alongside the original canonical suite. Native RPC
regeneration also checks constructed receipt/transaction projections against the
production Handler/API; cancellation's structural test signature is explicitly
identified. Funded/native lifecycle and browser/security gates remain separate.

## Submission and reconciliation checks

`node --test tests/submission.test.mjs` exercises single writes, lost/malformed/
conflicting replies, node rejection, canonical snapshots, read-only same-ID
reconciliation, native success/failure/authority observations, pending/pruning,
state/nonce/block contradictions, polling bounds and cancellation/deadline. An
actual Node HTTP server records a send then drops its reply; reconciliation
confirms the same fixture ID with one write total. This is transport/projection
evidence, not live pool acceptance or independent finality.

`test:rpc-native` additionally regenerates native reconciliation fixtures using
owned rooted/grant state, source signature/policy evaluation and session usage
settlement. Grant activation heights come from pinned intervals (Ed25519101,
P-256201). Cancellation has a native evaluated reference test signature. Receipts/
blocks and DIRECT/sponsor nonce observations remain explicitly constructed; funded
block processor/network execution stays separate. Source pin, all existing
commitment/receipt vectors and full differential gate remain unchanged.

## Nonce coordination

[Coordinator tests](../../tests/coordinator.test.mjs) run in `npm run check` and cover
atomic contention across coordinator instances, duplicate requests, consumed action
failure, fresh nonce watermarks, unknown/rejected/not-sent retention, read-only
recovery, ignored signer cancellation, input/state mutations at async boundaries,
strict persisted records, capacity, owner checks and explicit obsolete retirement.
These are client orchestration tests; an in-memory adapter does not establish
cross-tab/process durability. Application durable adapters must separately qualify
atomic compare/exchange, linearizable reads, persistence before acknowledgement and
crash behavior. Funded running-node lifecycle qualification remains a distinct gate.

## Owned native localnet

After `npm ci`, set `RSC_CHAIN_DIR` to a clean detached checkout at the immutable
source pin and run `npm run test:localnet`. This builds native crypto and real
CGO-enabled node/keygen binaries, independently computes the generated genesis
identity through production Go initialization, and starts four explicitly peered
loopback validators in a new owned temporary directory. It requires finalized
progress and hash/state agreement, shielded read APIs, genesis funding and actual
SDK root/fee/absent-receipt probes. `npm run test:localnet-failures` separately
qualifies setup/ready-node failure, readiness deadline, ignored-callback timeout,
actual SIGINT/SIGTERM and an injected missing-log capture. It checks the explicit
log manifest, copied byte sizes/hashes and generated-key redaction,
with restricted failed-run retention, closed owned processes and preserved external
safety sentinel. No native gate runs implicitly inside unit-only `npm run check`.

[Harness guide](native-localnet.md) defines ownership, artifacts, trust and cleanup.
[Supervisor tests](../../tests/localnet-harness.test.mjs) are unit coverage for
process groups/ports/path guards; they do not replace real native-node checks.
Funded activation/grant/transfer/revocation qualification remains separate #29.

## Funded account/session lifecycle

`RSC_CHAIN_DIR=/absolute/pinned/chain npm run test:lifecycle-native` runs real
four-validator funded DIRECT onboarding, both session signature schemes and
root maintenance through the [lifecycle API](../reference/lifecycle.md). It checks
typed finalized receipts, state/usage changes and revoked-key denial before signing.
The broader replay/expiry/included-failure/concurrency gate is SDK #29; physical
passkeys, independent review and publication are separate gates.

## Native session adversity and executable example

`RSC_CHAIN_DIR=/absolute/pinned/chain npm run test:session-e2e` runs a separate
fresh four-validator genesis with an explicit maximum-balance recipient. Both
raw session schemes exercise real native simulation/admission rejection for
premature/expired/revoked/old-epoch grants, wrong chain/genesis/key/policy/nonce,
invalid signatures, denied recipients/value limits and finalized replay. Each
requires the expected simulation authorization family and method-specific RPC
code; unrelated server errors cannot count as authority rejection.
It verifies failed transfer execution consumes exactly nonce/attempt/actual fee
without value/success consumption; DIRECT/ROOT failures keep their nonce domains
distinct. SESSION_CANCEL consumes a fee/attempt and keeps the grant active.

Shared-adapter contention holds the first signer and proves the second flow signs
nothing. A real loopback HTTP proxy forwards a write to the node then destroys
the acknowledgment socket and keeps initial reconciliation reads unavailable.
One unknown send remains reserved and explicit read-only recovery on a healthy endpoint finds that same finalized ID without signing/resending.
The proxy and native process handles are run-owned. All logs are independently
checked for hashes/coverage and known runtime/closure test-secret absence.

`RSC_CHAIN_DIR=/absolute/pinned/chain npm run example:session` executes the
[session-only example](../../examples/session-localnet.mjs): DIRECT activation,
ROOT grant, both raw SESSION transfers and finalized ROOT revocation.
The broader [lifecycle gate](../../scripts/check_lifecycle.mjs) additionally
checks replacement, reserve, revoke-all, cleanup and root rotation. These are
trusted-node observations on disposable test networks; they do not qualify
physical passkeys, cross-process adapter durability or independent finality.

Lifecycle approval deadline tests use a controlled internal clock in their isolated
Node test context. They establish reviewer entry before advancing to expiry,
verify no reservation/sign/send and disposed timers, and separately prove that
pre-review whole-flow expiry yields TIMEOUT. Immediate rejection/failure tests
use the normal flow budget; a scheduling race is not approval behavior evidence.

## WebAuthn contract inventory

[ADR-0002](../decisions/0002-authoritative-webauthn-rp.md) and its
[normative cases](../../tests/webauthn/rp-contract-cases.json) define future real
verifier/storage coverage for SDK #27. The inventory contains scenario IDs,
mutations and required outcomes, not signed fixtures or executed test results.
It does not increase the SDK passing-test count. Implemented parser/browser/
verifier suites must supply actual bytes, cryptographic checks and store races;
planned cases cannot substitute for those gates.

## WebAuthn parser/interoperability tests

After `npm run build`, `node --test tests/webauthn-parsers.test.mjs` runs actual
bounded representation tests: W3C public point and eight Node/OpenSSL DER/P1363
fixtures, all truncations, canonical CBOR/JSON count/depth/duplicate checks,
point/scalar/flag/credential-size boundaries, intrinsic byte-limit/shadow-property
regressions, owned copies and 5000 seeded byte mutations. OpenSSL verifies both
DER and converted signatures. `npm run check` includes these tests and installed
root/webauthn import/type/representation checks plus cold Node imports with DOM
access blocked. This is not a browser-engine/authoritative RP/device test.

Public fixture/provenance files and deliberate generator `--write` are linked in
[the parser reference](../reference/webauthn-parsers.md). Regeneration changes
disposable signatures/keys; review semantic/provenance changes rather than treating
a newly generated golden as independent approval. Actual #27/#30/#31/#34 gates
remain open.

## WebAuthn browser API contract tests

After `npm run build`, `node --test tests/webauthn-ceremonies.test.mjs` checks
call-time capabilities, explicit options/copies, create/get projection, unsupported
contexts, browser denial, pre/in-flight abort, controlled timeout/late completion,
malformed/hostile buffers and sanitization. It uses mocked browser methods and
public parser fixtures, including an intentionally unrelated signature; serialization
does not verify that signature. The suite is included in `npm run check`.
Installed-package checks cover types/exports and cold Node imports. Actual browser
engine/virtual-authenticator qualification remains #30, verifier/store conformance
#27 and physical-device evidence #31. See the [browser API](../reference/webauthn-browser.md).
