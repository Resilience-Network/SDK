# Reproducible local candidate qualification

This pipeline qualifies the selected local profile at a clean explicit revision.
It does not publish, create tags, fetch/reset source checkouts, resume hosted
workflows or declare external gates passed. The retained manifest distinguishes
local implementation evidence from independent audit, physical devices, other
engines, license decisions and publication.

## Inputs and commands

Provide an existing clean private Chain checkout at the exact revision and vector
hash in `protocol-source.json`. Owner-provisioned access is required; the pipeline
never places tokens in commands, logs or artifacts. Preserve existing keys,
databases, signing records and evidence. The SDK itself must be clean at the full
40-character `RSC_CANDIDATE_REVISION` supplied by the reviewer.

The versioned profile in `scripts/qualification/profile.mjs` requires Node 24.21.0,
npm 11.12.1, Python 3.14.3, macOS arm64, Go 1.26.8, CGO=1, Homebrew Rust 1.98.1 and installed Chrome
154.0.8037.95. This is the actually exercised local native profile. Chain CI's
Rust 1.88.0 and other operating systems remain separate unqualified profiles.
Dependencies use the committed lockfile; `.github/workflows/checks.yml` pins its
actions to immutable commit IDs and stays manual while hosted workflows are paused.
A manually dispatched Linux SDK check is not this macOS/native/browser profile.

```sh
export RSC_CHAIN_DIR=/absolute/path/to/clean/pinned/chain
export RSC_CANDIDATE_REVISION=reviewed_full_commit_id
export RSC_BROWSER_ENGINES=chromium
export RSC_BROWSER_CHROMIUM_CHANNEL=chrome
npm run qualify:preflight
npm run qualify:candidate
```

Preflight validates inputs without executing suites and is never PASS evidence for
implementation. Qualification runs serially: locked install; complete SDK/package
checks; installed API budgets; signed RP conformance; actual Chrome ceremonies;
native RPC fixtures; codec/receipt differentials; native signatures; owned positive
localnet; seven actual failure/interrupt/log-capture scenarios; lifecycle;
67-check session adversity; session example; installed-tarball example; combined
browser/native example. Each command requires its actual result marker and minimum
coverage. Empty output, insufficient counts, skipped/todo SDK tests, missing native
runs, stale/dirty artifact revisions, wrong native context/toolchain and missing
teardown/log hashes fail. RP counts must be safe integers with at least 76 tests
and 67 distinct passing normative cases. Browser/combined coverage requires actual
arrays of distinct named passing checks, with minimums of 24 and 17 respectively;
missing, sparse or fabricated array-like objects do not establish coverage. Positive native runtimes must be removed; negative runs
must retain their restricted safety state and close all owned children.

Child commands are bounded with restricted retained output, and receive termination
through their owned process group. Native feature entry scripts run directly after
the clean build so their registered signal handlers own teardown; isolated native
nodes remain under the existing harness's child handles. No process-name or stale
PID killing occurs. Interrupted/failed candidates retain evidence and are not
resumed by copying historical PASS claims. Investigate failures, fix/review changes
and run a fresh candidate at the final revision.

The [2026-10-04 review](../security/reviews/2026-10-04-local-candidate.md)
reproduced incomplete RP artifact acceptance (now addressed by strict count/array
regressions in #85), a stage that remains running after its SIGTERM timeout (#86),
and surviving owned descendants after their parent exits (#87). Historical successful qualification does not establish those
failure-path guarantees. GitHub tracks their fixes; robust qualification requires
their regressions and a fresh final candidate after reviewed delivery.

## Evidence and review

Each run owns `artifacts/qualification/<UUID>/` with restricted command output and
`manifest.json`; `latest.json` is a convenience copy. The manifest records exact
source/lock/profile hashes, candidate/native revisions, toolchains, stage counts,
output hashes, a common enforced installed-archive digest, native ownership IDs,
evidence/log verification and hashes of fresh
API/RP/browser/installed/combined artifacts. Only the structured manifest is suitable
for review sharing after inspection. Command output stays restricted local evidence;
do not upload entire artifacts, retained runtimes, keys or wallet/signing state.

The native negative suite intentionally records failed/interrupted fixture runs;
its containing stage passes only after the expected rejection, owned teardown,
restricted safety-state retention and log integrity checks. This never changes a
failed run into successful native activity. Native suites serialize writes to the
private pinned checkout; concurrent native activity fails qualification.

## Release preparation and remaining approval

A locally passing candidate is not a publicly releasable SDK. Publication is a
separate owner-controlled task (#38) requiring:

- Independent security sign-off (#34), license/package ownership decision (#35),
  physical-device evidence (#31) and additional-engine qualification (#69) for
  any advertised broader support. Keep milestone/parent acceptance open.
- Reviewed stable API/version and release notes; private `0.0.0`/UNLICENSED must
  never be published as a purported stable version. Update metadata through a PR
  and requalify its actual final revision/archive rather than editing a validated
  archive after the tests.
- A protected release environment, explicit owner approval of exact commit/tag
  and package digest, least-privilege short-lived publication credentials, and
  provenance for the exact tested artifact. Validate the target registry/package
  ownership and immutable tag association before a separately authorized publish.
- Review immutable action revisions and least-privilege permissions in any future
  publication job. Existing check jobs remain read-only/manual; this delivery
  introduces no publish credential, automatic merge, tag or workflow resumption.

There is deliberately no executable publication job while license, ownership and
security approval are unresolved. The reviewed checklist defines its required
inputs and safeguards without a placeholder job that could appear qualified.
