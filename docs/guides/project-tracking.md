# GitHub delivery tracking

The [SDK delivery goal](https://github.com/Resilience-Network/sdk/issues/13) owns
the supported v1 scope and the definition of complete. GitHub owns live work
status, assignments, dependencies and acceptance evidence. [PLAN.md](../../PLAN.md)
owns architecture and sequencing; this guide defines the tracking workflow.

## Scope and completion

The initial SDK delivers canonical construction/review, validated HTTP RPC and
receipts, external Ed25519 DIRECT/ROOT and raw Ed25519/P-256 session signing,
bounded transfer-grant lifecycle and separately verified WebAuthn ceremonies.
Every advertised API, platform and authority claim needs actual evidence.

Direct on-chain passkey authority, implicit custody/key persistence, Orchard
proving/scanning, staking/name/recovery convenience APIs, contract policies,
sponsor lifecycle, WebSockets and independent state/finality proof verification
remain outside this scope. Existing canonical sponsor fields are preserved.
Unsupported capabilities fail explicitly. A scope change requires reviewed issue
and plan changes, with separate Chain work for any protocol extension.

Complete means reviewed merged features and documentation, all applicable final
tests without required skips, independent security sign-off with no unresolved
High/Critical findings, approved license/registry ownership, reproducible release
artifacts and an owner-authorized published package verified by installed consumers.
An issue count, passing codec tests or readiness score cannot establish those gates.

## Milestone exit gates

1. [v0.1-session-foundation](https://github.com/Resilience-Network/sdk/milestone/1)
   delivers a native wallet/session alpha: codecs/hashes, RPC/receipts, signers,
   lifecycle/nonce safety and canonical review. Its exit includes owned pinned-node
   localnet, funded DIRECT activation through grant/use/finalized revocation for
   both session schemes, negative/concurrent/uncertain-send results and executable
   consumer integration docs.
2. [v0.2-webauthn-helpers](https://github.com/Resilience-Network/sdk/milestone/2)
   delivers reviewed RP/key ownership, bounded browser helpers, authoritative
   verifier tests, declared browser/physical-device evidence and an accurate
   combined disposable example. Virtual authenticators do not prove physical
   biometric support; assertions remain separate from raw SessionDigest signing.
3. [v1.0-sdk-release](https://github.com/Resilience-Network/sdk/milestone/3)
   requires both feature milestones plus independent security review, licensing,
   registry ownership, stable API/platform/package budgets, reproducible full
   evidence and reviewed owner-authorized publication/downstream verification.

Each milestone's GitHub description owns its detailed exit criteria. Dates remain
unset until owners and estimates are agreed. Size labels estimate effort, not
calendar delivery. Hosted workflows remain manual while paused; missing runs are
not passing evidence and this tracking setup does not resume them.

## Issue hierarchy and dependencies

The pinned delivery goal has completed foundation tasks and seven stage epics:

- [RPC](https://github.com/Resilience-Network/sdk/issues/3): transport, pinned method
  contracts, canonical receipt models/hashes and bounded reconciliation.
- [Session](https://github.com/Resilience-Network/sdk/issues/4): raw signers,
  activation/grant/maintenance lifecycle and nonce/snapshot coordination.
- [Review](https://github.com/Resilience-Network/sdk/issues/5): canonical review
  output plus adversarial display/signing binding.
- [Trust decisions](https://github.com/Resilience-Network/sdk/issues/6): authoritative
  RP contract and wallet key/authority model, with actual review evidence.
- [WebAuthn](https://github.com/Resilience-Network/sdk/issues/7): ceremonies, strict
  parsers and authoritative verifier/replay/domain-confusion tests.
- [Integration](https://github.com/Resilience-Network/sdk/issues/8): native harness,
  session flows/docs, browser/device evidence and combined example.
- [Release](https://github.com/Resilience-Network/sdk/issues/9): independent review,
  license/registry decision, public API/package qualification, reproducible checks
  and final publication/verification.

Native sub-issues provide the actionable breakdown; native blocked-by relations
provide prerequisites. Each leaf has its own scope, target components, acceptance,
required evidence, size/priority and one milestone. An epic may span milestones:
the integration epic's native children are v0.1 gates, while its browser/combined
children are v0.2 gates. Its parent closes after both and cross-cutting acceptance.

Claim leaf tasks, not an epic as a competing implementation claim. Recheck native
dependencies, acceptance context, assignees and claim comments under
[CONTRIBUTING.md](../../CONTRIBUTING.md). A ready label is a scheduling hint,
not an atomic ownership lock. Newly planned work stays unassigned until claimed.

## Metadata and status

Every issue keeps one label in each existing dimension: type, area, consensus,
size and priority, plus one active milestone. Tracking adds:

- `tracking/roadmap`: the overall delivery goal.
- `tracking/epic`: a stage acceptance umbrella with sub-issues.
- `tracking/task`: a reviewable leaf deliverable or decision.
- `tracking/admin`: tracking administration, excluded from product progress.

Use exactly one `status/*` label:

- `status/backlog`: planned work with unmet prerequisites or an unscheduled stage.
- `status/ready`: an unassigned leaf with satisfied prerequisites and defined scope.
- `status/in-progress`: a verified active claim and unique topic branch.
- `status/in-review`: a delivering PR awaiting review/merge.
- `status/blocked`: active work needs a linked external decision or unblock; explain
  the condition and owner rather than labeling every future task blocked.
- `status/done`: reviewed merged delivery with acceptance evidence.

The claimant updates status at claim, PR creation and verified completion; checks
downstream prerequisites after completion; and records blockers or releases a claim
as required. All implementation checks remain those in [testing](testing.md).
Issue closure before PR merge, when allowed by the contribution policy, retains
`status/in-review` until merged evidence exists. Deferred work must link an actual
follow-up and cannot waive a milestone/security gate.

Epics become in progress when their children are active and close only after all
children and stage acceptance are evidenced. The delivery goal closes after all
milestone exit gates and actual release verification. Preserve historical closing
summaries as revision-bound evidence rather than rewriting them as fresh results.

## Useful views

Use these repository searches; they work without a Projects board:

- [Ready unassigned delivery work](https://github.com/Resilience-Network/sdk/issues?q=is%3Aissue%20is%3Aopen%20label%3Atracking%2Ftask%20-label%3Atracking%2Fadmin%20label%3Astatus%2Fready%20no%3Aassignee).
- [Active claims](https://github.com/Resilience-Network/sdk/issues?q=is%3Aissue%20label%3Atracking%2Ftask%20label%3Astatus%2Fin-progress).
- [Awaiting review](https://github.com/Resilience-Network/sdk/issues?q=is%3Aissue%20label%3Astatus%2Fin-review).
- [Active blockers](https://github.com/Resilience-Network/sdk/issues?q=is%3Aissue%20is%3Aopen%20label%3Astatus%2Fblocked).
- [Verified completed delivery](https://github.com/Resilience-Network/sdk/issues?q=is%3Aissue%20label%3Atracking%2Ftask%20-label%3Atracking%2Fadmin%20label%3Astatus%2Fdone).
- [Open release blockers](https://github.com/Resilience-Network/sdk/issues?q=is%3Aissue%20is%3Aopen%20label%3Apriority%2Fcritical).

Milestone/epic counts include different work sizes, umbrella issues and sometimes
PRs; they are not a weighted SDK completion percentage. Assess readiness from
reviewed leaf acceptance and milestone/security exit evidence. Keep live counts
in GitHub, not in this guide or a second documentation status ledger.

Projects access requires separate account permissions. Repository-native tracking
is the current usable system; a future board can visualize these same issues with
Status, Milestone, Priority, Size and parent fields without creating duplicate
draft tasks or replacing issue ownership.

## Parent feature and change control

[Chain#25](https://github.com/Resilience-Network/Chain/issues/25) retains the original
browser/native/docs acceptance. The trust-model decision must explicitly account
for the WebAuthn/raw-signature mismatch and any revised/deferred direct-passkey
criterion. SDK scaffold or codec completion does not close that parent. Chain docs
and protocol changes use Chain's own issue/branch/review/verification workflow.
