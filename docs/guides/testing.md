# Testing and evidence

This guide defines what current scaffold checks prove and the additional gates
required as SDK features are implemented.

## Available scaffold checks

```sh
npm ci
npm run check
git diff --check
```

The check script validates formatting, strict TypeScript, local documentation file
links/source pin, a clean build and an installable package import/declaration
boundary. The docs checker does not validate external links, Markdown heading
anchors or prose semantics. Package smoke checks do not verify cryptography.

Hosted [SDK checks](../../.github/workflows/checks.yml) use manual dispatch while
workflows are paused. Full applicable local equivalents are required before a
PR; missing hosted runs are not PASS evidence.

## Feature gates to implement

- Unit/vector: independent fixture encodings and hashes, malformed input, checked
  integer boundaries, deterministic outputs, exact signature scheme semantics.
- Property/mutation: reproducible seeds, rejection invariants, bounded parsers;
  retain minimized failures as regressions instead of editing expected hashes.
- Differential: cross-check canonical data with the pinned Go verifier and
  independent model; record vector gaps and source conflicts explicitly.
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
These are not SDK-only scaffold checks. `CGO_ENABLED=0` is not native shielded
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
from implementer tests or this scaffold's checks.
