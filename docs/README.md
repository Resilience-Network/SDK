# SDK documentation

This index separates intended SDK capabilities from the currently available
implemented canonical codecs/hashes, HTTP transport, typed Chain reads
and raw transaction signer adapters and canonical review data. Grant lifecycle and
browser APIs remain planned.

- [Implementation plan](../PLAN.md): feature scope, architecture and delivery gates.
- [GitHub tracking](guides/project-tracking.md): delivery goal, milestones, tasks,
  dependencies, status labels and progress views.
- [Local development](guides/local-development.md): install, build and package checks.
- [Testing](guides/testing.md): available commands and required feature evidence.
- [Owned native localnet](guides/native-localnet.md): generated funded genesis,
  real native validators, bounded ownership, evidence and failure/interrupt checks.
- [Protocol sources](reference/protocol-sources.md): immutable Chain source baseline.
- [Canonical API](reference/canonical-api.md): supported codecs/hashes and their limits.
- [HTTP RPC API](reference/http-rpc.md): envelope transport, limits, cancellation,
  errors, read retries and interoperability boundaries.
- [Typed Chain RPC API](reference/rpc.md): expected identity, finalized context,
  authorization/policy reads, fee contracts and advisory estimation/simulation.
- [Receipt API](reference/receipts.md): canonical commitments, bounded transaction/receipt
  observations, execution/consumption semantics and node trust boundaries.
- [Submission API](reference/submission.md): one send, typed uncertainty and bounded
  same-ID reconciliation with node-reported finality/consumption.
- [Nonce coordination](reference/coordinator.md): explicit reservations, async authority
  binding, uncertain-send retention and durable adapter/recovery requirements.
- [Raw signer API](reference/signers.md): external key ownership, exact digest
  semantics, canonical witnesses, mutation guards and bounded cancellation.
- [Canonical review API](reference/display.md): frozen bytes/hash-bound policy,
  intent and transaction fields with exact amounts and authority semantics.
- [Passkey authorization decision](decisions/0001-passkey-authorization-boundary.md).
- [Security boundaries](security/threat-model.md).
- [Documentation policy](documentation-policy.md).
- [Contribution workflow](../CONTRIBUTING.md) and [agent instructions](../AGENTS.md).

GitHub issues own work status, ownership and acceptance. Future API references
must document implemented behavior and link source/tests rather than copy a plan
as if every proposed capability shipped.
