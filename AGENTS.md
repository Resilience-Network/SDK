# Agent instructions

These repository-wide instructions adapt the relevant rules from Chain. Read
[CONTRIBUTING.md](CONTRIBUTING.md) and [docs/README.md](docs/README.md) first.

## Workflow and ownership

- Never commit directly to `main`. Use a unique `codex/` topic branch and
  `gh pr create`; merge only after review and applicable CI/local checks pass.
- Inspect the working tree before editing. Preserve unrelated changes, keys,
  wallet data, databases, signing records and retained evidence.
- Pick only open, unassigned issues, even when an assignment belongs to the same
  account. Resume an existing claim only on an explicit user request.
- Before implementation, reread assignees and recent claim comments; assign with
  `gh issue edit <number> --add-assignee @me`, comment with the unique branch and
  chat/task identifier, then reread both. Self-assignment is not an atomic lock.
- If another agent claimed first, do not compete or remove their assignment.
  Do not implement until ownership is established. Keep the claim while active;
  on abandonment explain the release and remove only your own assignment after
  checking that no other agent relies on it.
- Follow the title, label, milestone, template and post-creation issue checks in
  CONTRIBUTING.md. Close only with satisfied or explicitly deferred criteria and
  an evidence-backed summary referencing the delivering PR and branch.

## Investigate and report discovered issues

- Proactively inspect newly discovered bugs, failing tests, implementation gaps
  and code/specification conflicts, including findings outside the current task
  or in an upstream repository. File an issue in the affected repository
  immediately; do not wait for the current task to finish, a complete root-cause
  analysis or additional permission to investigate and report.
- Check existing reports first and update the matching issue instead of creating
  a duplicate. Follow CONTRIBUTING.md for templates, labels, milestones and
  post-creation checks.
- Include observed versus expected behavior, source/revision, reproduction steps
  or available evidence, impact and remaining unknowns. Clearly distinguish
  suspected findings from confirmed defects; never invent evidence or PASS claims.
- Link the finding to the current issue/PR and record blocking dependencies when
  relevant. Leave new reports unassigned until claiming their implementation
  through the normal ownership workflow. Reporting does not bypass another
  agent's claim, topic branches, review or safety-state preservation.

## Context and protocol discipline

- Read [PLAN.md](PLAN.md), the relevant decision and
  [protocol sources](docs/reference/protocol-sources.md). Verify behavior against
  the pinned Chain source and independent vectors; investigate conflicts.
- Do not confuse WebAuthn assertion verification with raw P-256 session signing.
  DIRECT/ROOT use Ed25519. Never silently add a custody service or chain extension.
- Use checked integer ranges, canonical bytes and exact domain separators. Reject
  unsupported versions and encodings; no legacy fallbacks, migrations or shims.
- Do not regenerate golden vectors without explaining their semantic change.
  Review encoding, gas, activation, state-root, manifest and genesis implications
  together; chain changes require a separate Chain issue and reviewed PR.
- Keep secrets out of RPC, URLs, logs and fixtures. Signing displays must derive
  from the same canonical bytes being authorized. Simulation is advisory.
- Preserve replay/nonce rules, rollback boundaries, validator locks and signing
  watermarks. A timeout or mismatch never authorizes deleting safety state.
- Prefer focused modules. Review shared exports and protocol constants semantically.

## Verification and delivery

- Use the pinned Node runtime, `npm ci` and `npm run check` before raising a PR.
  For implemented behavior also run affected unit/vector suites, then all SDK
  unit suites; add browser/localnet/differential coverage when applicable.
- While hosted workflows are paused, local CI-equivalent evidence is mandatory.
  Record exact commands, revision, runtime, results and skipped/blocked coverage.
  Never reuse historical PASS claims or count an empty test suite as a pass.
- Chain integration uses Chain's own AGENTS.md and testing guide. Native Go
  checks require `make build-crypto`; `CGO_ENABLED=0` is not native shielded
  evidence. Chain source PRs require its full local CI-equivalent suite.
- Add Chain stories with unique STORY_ID, STORY_NAME and STORY_TIMEOUT headers;
  never change its runner merely to register a story. Use disposable integration
  directories and explicit ownership; preserve existing node/wallet state.
- Update canonical docs with behavior changes. GitHub owns live status; PLAN.md
  owns design and sequencing. Report material limitations honestly.
