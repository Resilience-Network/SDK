# Local candidate deep review — 2026-10-04

This is a historical implementer review of SDK
`fac5ba1843be7ed51562f4387c34e82677c4216d` (tree
`db764ae05431c761f689375bc8acba9a3ae4a3e7`, identical to the previously
qualified `ab468e777ef69923e26f9248073c1443ff0adf13`). It challenges the earlier
local readiness estimate. It is **not independent security sign-off**, a formal
cryptographic audit, production RP qualification or a published-release approval.
[Review issue #83](https://github.com/Resilience-Network/sdk/issues/83) owns this
review's delivery; GitHub owns the findings' current status.

The baseline has substantial implemented and exercised functionality, but the
review reproduces five defects: four Medium and one Low. None is fixed by this
report. No High/Critical exploit was demonstrated within this review; that is not
an assurance that none exists. The earlier “approximately 9/10” local estimate
was too confident about robustness. My revised **historical judgment is about
8/10 for the selected local implementation**, pending findings disposition and
fresh final qualification. This is a subjective assessment, not a computed
completion percentage or the definition of a complete v1 release.

## Review method and boundaries

Four passes inspected the relevant implementation, documented trust contracts,
existing tests and pinned native source:

1. Canonical input/encoding, bigint widths and bounds, domain-separated hashes,
   keys/witnesses, review-to-signature binding and asynchronous signer handling.
   Sources: `src/core`, `src/session/{transaction,policy,root,hash,keys,signers,
signing-review}.ts` and `src/display/review.ts`; core, byte-bound, display,
   review/signing and signer suites. Native codec/hash/signature oracles and
   independent fixtures were rerun, with unsupported grammars kept explicit.
2. HTTP serialization/envelopes, retries/cancellation/deadlines, expected network
   identity and contextual reads, receipt commitments, single-send uncertainty,
   readonly reconciliation, nonce storage/CAS/recovery and lifecycle preflight.
   Sources: `src/rpc`, `src/session/{coordinator,lifecycle,lifecycle-policy}.ts`;
   HTTP, method, resilience, receipt, submission, coordinator and lifecycle suites.
   Native evaluator/settlement/lifecycle code and actual handler fixtures were
   compared with the SDK's supported subset. Cross-poll contradictions exposed
   a gap that ordinary state-movement tests did not cover.
3. WebAuthn representation limits, CBOR/COSE/DER/client-data parsing, browser
   options/context/UP/UV, RP take-before-verify and conditional commit transitions,
   registration proof, replay, counters, expiry/rollback and errors. Sources:
   `src/webauthn`, `examples/webauthn/reference-rp.mjs`, passkey application gate,
   parser/browser/RP tests and ADR-0001/0002. Actual maintained-verifier fixtures
   and installed Chrome ceremonies were rerun.
4. Candidate stage/artifact predicates, clean revision/tool/profile checks,
   installed archive equality, native ownership/teardown and log capture/hash
   verification. Sources: `scripts/qualification`, `scripts/localnet`, installed
   consumer/API/browser checks and their tests. New adversarial probes used actual
   owned subprocesses; the candidate timeout probe executed the verbatim reviewed
   process-controller code in isolation from the full native pipeline.

This was a targeted review of important contracts and failure paths, not an
exhaustive line-by-line proof of all SDK, dependency or Chain code. The reviewer
also implemented the SDK, so correlated assumptions remain possible. Injected
JSON transport tests reproduce client behavior; they do not establish occurrence
on a real faulty network. No production keys or prior wallet/signing state were
used or modified. Every subprocess started for a reproduction was explicitly
closed using its own recorded ownership, without process-name kills.

[Historical executable probes](2026-10-04-probes.mjs) reproduce all five findings,
including both R1 scenarios. From the SDK root, run `npm run build`, then
`node docs/security/reviews/2026-10-04-probes.mjs`. They refuse changed reviewed
source hashes, use public fixtures/injected responses, and clean up only their
own newly spawned processes/runtime. Successful execution confirms known defects
in this baseline; it is deliberately **not** a passing qualification suite.
The [sanitized probe output](2026-10-04-probe-results.json) records a repeated
source-guarded execution during report preparation; its timings differ slightly
from the initial individual reproductions below. It explicitly records
`qualificationPassed: false` and actual probe-owned cleanup.

## Confirmed findings

### R1 — Medium: finalized reconciliation context is forgotten between polls

[Issue #88](https://github.com/Resilience-Network/sdk/issues/88).
[Baseline source](https://github.com/Resilience-Network/sdk/blob/fac5ba1843be7ed51562f4387c34e82677c4216d/src/rpc/methods.ts#L437).

`reconcileTransaction` overwrites `lastObservation` and `authority` each iteration.
It validates receipt → authority → block consistency within that iteration but
retains no finalized context watermark from earlier polls.

An actual `ChainRpcClient` with JSON `Response` objects and the first native
`rpc-reconciliation.json` fixture observes height 106 in the first, unknown poll.
The second poll consistently supplies the original valid height-101 fixture.
It returns **`reported-finalized-success` at 101**, two polls and zero sends.
A separate probe keeps both polls at height 101 while changing nonzero block and
state-root hashes; the client again returns success. Both conflict with the
submission reference's nonregressing finalized observation contract.

Impact: a stale/inconsistent trusted-node route can produce a terminal result
instead of unknown/context error. This is not independent finality verification
or a demonstrated dishonest-node/signature bypass. Fix with a per-invocation
context watermark and regression/equal-height contradiction tests; preserve
readonly polling, bounded budgets and held uncertain nonce records.

### R2 — Medium: hostile RPC request inspection forwards original typed errors

[Issue #84](https://github.com/Resilience-Network/sdk/issues/84).
[Baseline source](https://github.com/Resilience-Network/sdk/blob/fac5ba1843be7ed51562f4387c34e82677c4216d/src/rpc/http.ts#L266).

A Proxy parameter throws a caller-modified `RpcClientError` from its
`getPrototypeOf` trap. Request serialization's catch directly rethrows nominal
SDK errors. The public rejection is the **same object**, with the caller's altered
message and cause, and zero fetches. Only a public sentinel was used.

```js
const original = new RpcClientError("NETWORK_ERROR");
original.message = "REVIEW_PUBLIC_SENTINEL";
original.cause = "REVIEW_PUBLIC_SENTINEL";
const params = new Proxy(
  {},
  {
    getPrototypeOf() {
      throw original;
    },
  },
);
await client.request("rsc_chainId", params);
```

Impact: caller data can escape into error logging despite the fixed diagnostics
contract. No remote-node-only exploit or key compromise was demonstrated. Rebuild
fresh bounded request errors with guarded code/class inspection; also inspect
response callback boundaries without forwarding mutable SDK error instances.

### R3 — Medium: candidate timeout can wait indefinitely after SIGTERM

[Issue #86](https://github.com/Resilience-Network/sdk/issues/86).
[Baseline source](https://github.com/Resilience-Network/sdk/blob/fac5ba1843be7ed51562f4387c34e82677c4216d/scripts/qualification/run.mjs#L115).

Stage timeout/output overflow marks failure and sends SIGTERM; interruption uses
the same termination helper. The promise waits for `close` without a subsequent
grace/escalation/finalization bound. An owned child with a SIGTERM handler that
returns and an active interval stays running.

The verbatim process controller, exercised with a 200ms stage deadline, remained
unsettled at 755ms with its owned child alive. The probe then killed only its
recorded owned group and verified closure. This is a controller reproduction;
the full 15-stage native candidate was not forced into this timeout condition.

Impact: no final failed/interrupted manifest and lingering test resources under
noncooperation. A fix must coordinate native detached child ownership before
escalation, retain evidence and test interruption/overflow/descendant pipes.

### R4 — Medium: native supervisor skips a surviving group after parent exit

[Issue #87](https://github.com/Resilience-Network/sdk/issues/87).
[Baseline source](https://github.com/Resilience-Network/sdk/blob/fac5ba1843be7ed51562f4387c34e82677c4216d/scripts/localnet/harness.mjs#L64).

`OwnedProcesses.stop` skips both signals when `entry.exited` is true, although
`entry.closed` can remain false while descendants retain inherited pipes.
The existing nested-child regression keeps the group leader alive.

The actual exported supervisor started an owned Node parent that spawned an
unref'ed descendant inheriting stdout, then exited with code 0. The descendant
ignored SIGTERM and retained its pipe. `stop(20)` rejected at 2023ms with
`Owned child did not close after kill`; the group still ran. Explicit probe-owned
SIGKILL then closed it. The bounded rejection correctly reports failure, but
does not provide the promised containment.

Impact: owned test descendants can leak after direct-child exit. Resolve safe
ownership across parent exit and inherited descriptors, avoiding reused/stale
process identifiers and preserving unrelated processes and safety evidence.
Coordinate this with R3 rather than assuming parent exit means group teardown.

### R5 — Low: RP artifact minimum accepts absent/non-numeric test counts

[Issue #85](https://github.com/Resilience-Network/sdk/issues/85).
[Baseline source](https://github.com/Resilience-Network/sdk/blob/fac5ba1843be7ed51562f4387c34e82677c4216d/scripts/qualification/profile.mjs#L164).

`verifyArtifact("rp", ...)` accepts a same-revision clean object with
`failures/skipped/todo: 0` but no `tests` field. It also accepts `tests: "76"`.
The comparison `tests < 76` fails to establish a required integer count. An
in-memory NaN also passes, although NaN is not a parsed JSON value.

The separate executed-stage output minimum remains enforced. This does **not**
show that any historical full candidate actually omitted tests or fabricated PASS.
Impact: the advertised independent artifact predicate fails open for malformed
evidence. Validate required safe integer counts and array shapes explicitly,
retaining both output and artifact checks.

## Fresh baseline verification

All results below were obtained during this review on the clean baseline, not
borrowed from an earlier PR. Node v24.21.0, npm 11.12.1, Python 3.14.3, macOS arm64;
native checks used Chain `007356ef5e5e1769cfda2290fcafc9db5d48bbfd`, Go 1.26.8,
CGO=1 and Homebrew Rust 1.98.1. Browser checks used installed Chrome
154.0.8037.95. This does not qualify Chain CI Rust 1.88.0 or other platforms.

- `npm ci` and `npm run check`: PASS; 305 tests, zero failures/skips/todos;
  formatting, types, docs, installed six-entry import/type/package smoke checks.
- `node --experimental-test-coverage --test tests/*.test.mjs`: PASS; 305 tests.
  Node reports lifecycle emitted JS at 83.73% lines/85.10% branches, qualification
  profile at 85.93%/84.00%, and native harness at 26.90%/81.25% in this unit run.
  The aggregate 91.93% lines/95.42% branches includes helpers/tests/examples/tools,
  so it is **not a production-SDK-only coverage percentage**. Native integration
  was separately executed without this coverage instrumentation. Coverage does
  not prove semantic completeness: the cross-poll bug exists despite high RPC
  coverage.
- `node scripts/check_differential.mjs` with explicit `RSC_CHAIN_DIR`: PASS;
  1925 cases, seven Go onboarding layouts and eight additional hash helpers.
- `node scripts/check_receipts.mjs`: PASS; 166 native field/hash fixtures and
  26294 accepted/rejected/truncation/mutation cases.
- `node scripts/check_signatures.mjs`: PASS; 607 native/Node/OpenSSL signature
  acceptance/rejection cases, including Ed25519 equation distinctions and raw P-256.
- `node scripts/check_rpc_contracts.mjs`: PASS; 41 typed, 19 envelope, 11 receipt
  and 11 reconciliation production-handler fixtures; owned native additions removed.
- `node scripts/check_webauthn_verifier.mjs`: PASS; 67 normative cases, 76 tests,
  zero failures/skips/todos. These 76 tests overlap the 305-test suite.
- `node scripts/check_browser.mjs` with `RSC_BROWSER_ENGINES=chromium` and
  `RSC_BROWSER_CHROMIUM_CHANNEL=chrome`: PASS; 24 actual installed-Chrome checks,
  virtual authenticator/verifier negatives and cancellation. No physical device,
  Firefox or WebKit evidence follows from that result.
- `npm run test:api-qualification`: PASS; six entries/95 runtime exports, reviewed
  declaration hashes, installed notices/imports and budget checks. Root bundle
  247048 bytes/80900 gzip bytes. The first direct invocation omitted npm context
  and was correctly rejected; only the subsequent supported npm invocation is PASS.
- `node scripts/check_session_end_to_end.mjs`: PASS; fresh funded native four-node
  session qualification, 67 checks including both schemes, rejection domains,
  included-failure consumption, contention and actual lost acknowledgement.
  Owned run `5727f1f7-84dd-477c-8144-bcd519a252d5`: 24 captured logs, runtime removed,
  all owned children closed; evidence SHA256
  `32b8510d287f23a5976f077cbfd90fff41efe950d12fb5e97e19f9e257ea4520`.
- `npm audit --json`: zero registry-reported advisories at review time, including
  development dependencies. This checks the advisory database, not all code or
  future vulnerabilities.

No fresh full 15-stage candidate, physical-device matrix, additional engine,
independent security sign-off or publication was completed in this review.
Historical candidate PASS retains its revision-bound meaning and cannot override
these reproduced failures. SDK/Chain source stayed clean throughout baseline
execution; the original user's Chain branch and untracked readiness file remained
untouched. The delivering report PR independently reruns required SDK checks.

## Checks that did not become findings

- A batch method accessor is rejected before invocation; an injected fetch
  throwing a modified SDK error is reconstructed by its transport boundary.
  Those paths do not demonstrate the request-prototype defect R2.
- Nonce retirement uses `current.retirement ?? current.snapshot` as its next-flow
  watermark. The suspicion that retirement permits an old nonce/epoch to return
  was disproved by source inspection and the existing explicit retirement tests.
- Bucket multiplication/addition overflow is rejected before capacity capping in
  both the SDK and pinned Go evaluator. Saturating before overflow would change
  protocol semantics; the conservative rejection is not a mismatch.
- Browser representation helpers enforce type/ID/context/UP/UV and reject
  cross-origin/extensions, but remain collectors/parsers. Actual signature/account
  acceptance occurs at the reference RP, where challenge take precedes crypto and
  conditional credential commit prevents concurrent revocation/version overwrite.
- Block/receipt hashes and commitments are consistency checks over trusted-node
  observations. They are not validator certificates or independently proven finality.
  Missing/pruned grants/history remain unknown and do not free uncertain reservations.

## Disposition and next work

All five findings were filed immediately as open, unassigned implementation tasks
with severity, reproduction and regression acceptance. The affected historical
transport/submission/harness/qualification acceptance and foundation milestone
were reopened instead of retaining an unconditional completed claim. Original
closing summaries remain historical evidence. This report resolves the review
request only; it does not resolve the bugs or close independent review #34.

Recommended implementation order: R1 context watermark; R2 error reconstruction;
R4 native ownership/cleanup; R3 bounded candidate termination coordinated with R4;
R5 strict artifact schema. Start each from a verified issue claim/topic branch,
reproduce the failure as a regression, fix, run affected/full checks, submit/review
and merge the exact verified head. A final candidate run must follow all fixes.
Do not certify cleanup from a parent exit, unknown outcome from a higher nonce,
or robust coverage from a passing test count.

External gates remain [physical devices #31](https://github.com/Resilience-Network/sdk/issues/31),
[independent review #34](https://github.com/Resilience-Network/sdk/issues/34),
[license/registry ownership #35](https://github.com/Resilience-Network/sdk/issues/35),
[publication #38](https://github.com/Resilience-Network/sdk/issues/38) and
[additional browser engines #69](https://github.com/Resilience-Network/sdk/issues/69).
Durable multi-worker RP/key custody and independent finality proofs remain outside
the selected reference/client scope. Five local bugs remain local work even when
external gates are excluded from the autonomous target.
