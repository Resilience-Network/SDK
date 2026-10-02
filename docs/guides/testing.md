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
it does not qualify browser engines. The pinned node's missing nil-success result
is an upstream defect, not a reason to weaken envelope validation. Its separate
correction/baseline gate is documented in the [HTTP API](../reference/http-rpc.md).

Run `npm test` for the build and all Node unit suites. See the
[canonical API](../reference/canonical-api.md) for exact implemented limits and
unsupported sections. The docs checker does not validate external links,
Markdown heading anchors or prose semantics.

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
