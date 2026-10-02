# Contribution workflow

This SDK inherits Chain's topic-branch, ownership, metadata and evidence rules,
adapted to a TypeScript client repository. [AGENTS.md](AGENTS.md) applies to all
agents. [Documentation policy](docs/documentation-policy.md) applies to all changes.

## Branches and pull requests

Never commit directly to `main`. Create a unique topic branch, normally
`codex/<issue>-<purpose>-<task-suffix>`, and submit with `gh pr create`.
Merge only after review and passing applicable CI. While hosted workflows are
paused, a complete local CI-equivalent run is mandatory before PR creation.
The initial GitHub-generated repository seed precedes this policy; all subsequent
changes, including bootstrap documentation, go through a PR.

Inspect the tree and preserve unrelated work, credentials, wallet data and
evidence. Do not force-push another contributor's branch or bypass review.

## Claiming work

Pick an open, unassigned issue. An issue assigned to the same GitHub account can
belong to another agent. Resume a claim only when explicitly requested.

```sh
gh issue view <number> --json assignees,comments,state
gh issue edit <number> --add-assignee @me
gh issue comment <number> --body-file /path/to/claim.md
gh issue view <number> --json assignees,comments,state
```

The claim identifies the unique topic branch and chat/task identifier. Recheck
after claiming: shared-account assignment is not an atomic lock. If a competing
claim won, choose another unassigned issue without removing that assignment.
If ownership cannot be verified, do not implement. Keep active claims; when
abandoning, leave a release comment and remove only your assignment after
confirming no other agent relies on it.

## Titles, labels and milestones

Issue and PR titles use `[<Category>:<Subsystem>] <actionable summary>`.
The PR reuses its linked issue's prefix. Supported categories are `FR-<number>`,
`BUG`, `API`, `DEVOPS`, `HARNESS`, `SEC-GATE`, `AUDIT`, `ROBUST`, `SEC-1P` and
`SEC-2P`. SDK subsystems are Client, SessionAuth, RPC, Wallet, WebAuthn, Tooling,
Testing and Deploy. FR-013 retains its parent feature identifier.

Every issue needs one label from each dimension:

- Type: `type/feature`, `type/bug`, `type/security-gate`, `type/test-harness`, `type/ops`.
- Area: `area/client`, `area/sessionauth`, `area/rpc`, `area/wallet`,
  `area/webauthn`, `area/tooling`, `area/testing`, `area/deploy`.
- Consensus: `consensus/none`, `consensus/soft`, `consensus/hard`.
- Size: `size/S` (<1 engineer-week), `size/M` (1–3), `size/L` (3–8), `size/XL` (>8).
- Priority: `priority/critical`, `priority/high`, `priority/medium`, `priority/low`.

SDK-only changes normally use `consensus/none`. A consensus-impacting proposal
must link coordinated Chain work; this repository cannot change node rules.
Estimates express effort, not promised calendar delivery dates.

Use one active milestone:

1. `v0.1-session-foundation`: codecs, hashes, RPC, signers, sessions and display.
2. `v0.2-webauthn-helpers`: authorization decision, ceremonies, browser/localnet examples.
3. `v1.0-sdk-release`: independent review, stable API and release qualification.

## Issue templates

Use [feature](.github/ISSUE_TEMPLATE/feature.md),
[bug](.github/ISSUE_TEMPLATE/bug.md) or
[security gate](.github/ISSUE_TEMPLATE/security-gate.md). Feature requests must
describe motivation, technical design, state/consensus impact, effort, target
components, dependencies and measurable acceptance/verification criteria.
Bugs require revision/runtime, reproduction, actual evidence and regression
criteria. Security gates require deliverables and explicit sign-off evidence.

```sh
gh issue create --title '[FR-013:SessionAuth] Implement bounded session lifecycle' \
  --label 'type/feature,area/sessionauth,consensus/none,size/M,priority/high' \
  --milestone v0.1-session-foundation --body-file /path/to/issue.md
```

After creating an issue, reread it to verify body, labels, milestone and assignment.
New follow-up work stays unassigned until claimed.

## Verification before PR creation

On the topic branch use Node.js from `.nvmrc`:

```sh
npm ci
npm run check
git diff --check
```

`check` runs formatting, TypeScript, docs, a clean build, unit/vector/mutation tests
and package import/types smoke checks. Canonical protocol changes must also run
`npm run test:differential` against the immutable Chain source pin. Feature PRs
add meaningful unit/vector coverage and browser, concurrency/localnet checks for
the behavior they introduce. The testing guide defines available commands and
later gates. Skipped or blocked required checks are not passing evidence.

Chain source changes must independently follow Chain's full pre-PR native Go,
vet, determinism, race, storytests and fuzz requirements. Go/race checks are N/A
to SDK-only changes; no native verification claim follows from a client build.

Hosted CI uses manual dispatch while workflows are paused. Do not assume a
missing workflow run passed, or bypass a configured required status check.

## PR and post-creation issue checks

Use [the PR template](.github/PULL_REQUEST_TEMPLATE.md). Include the problem,
resulting behavior, linked issue, relevant changes, exact verification evidence,
documentation impact and reviewer notes. Write multiline bodies to a file.

```sh
gh pr create --base main --head <topic-branch> \
  --title '[FR-013:SessionAuth] Implement bounded session lifecycle' \
  --body-file /path/to/pr.md
gh issue view <number> --json number,title,state
```

Immediately check every delivering issue. Close an open issue only if its
acceptance criteria are satisfied, or explicitly deferred to referenced
follow-up issues, and the delivering PR exists. Otherwise leave it open and
document the remaining criteria. PR creation alone does not establish completion
of a feature. A review failure that invalidates delivery requires reopening it.

Parent feature issues stay open when a scaffold PR delivers only one prerequisite.
The SDK bootstrap must not silently close Chain#25's browser/node criteria.

## Evidence-backed closing summary

Never close silently. At closure post:

```markdown
### Closing Summary

**Delivered by**: PR #<number> (branch `<topic-branch>`)
**Resolution**: <concrete delivered behavior>

**What was done**:

- <component and change>

**Acceptance criteria status**:

- [x] <criterion> — <actual test, command, file or linked evidence>
- [ ] <deferred criterion> — <reason and follow-up issue>

**Verification evidence**:

- <exact command> — <actual result and runtime/revision>
- <inapplicable check> — N/A (<reason>)

**Follow-ups**: None | <linked issues>
```

Post the summary with `gh issue comment <number> --body-file /path/to/closing-summary.md`,
then immediately close with `gh issue close <number>`.
Account for every criterion, link the delivering PR and branch, and report only
checks actually run. Merge remains a separate review-gated action.
