# SDK documentation

This index separates intended SDK capabilities from the currently available
implemented canonical codecs/hashes, HTTP transport, typed Chain reads
and raw transaction signer adapters, canonical review data and account/session
lifecycle and bounded WebAuthn parsers/browser helpers. Actual engine and RP
verification use separate evidence gates with the exact qualified scope in their
references; physical devices and other engines remain separate.

- [Implementation plan](../PLAN.md): feature scope, architecture and delivery gates.
- [GitHub tracking](guides/project-tracking.md): delivery goal, milestones, tasks,
  dependencies, status labels and progress views.
- [Local development](guides/local-development.md): install, build and package checks.
- [Candidate qualification](guides/candidate-qualification.md): strict exact-revision
  local suite, hash-linked evidence and separate publication approval gates.
- [Testing](guides/testing.md): available commands and required feature evidence.
- [Owned native localnet](guides/native-localnet.md): generated funded genesis,
  real native validators, bounded ownership, evidence and failure/interrupt checks.
- [Native integration and troubleshooting](guides/native-integration.md): actual
  installed-tarball consumer, external authority, trusted configuration and safe
  ambiguity/failure recovery.
- [Native session example](guides/session-example.md): executable funded lifecycle,
  approval/signing boundaries and adversity/uncertainty checks.
- [Combined passkey/session example](guides/passkey-session-example.md): actual
  browser app authentication with separate native test-key approvals and finalized
  session lifecycle; no direct passkey authority or production custody.
- [Browser qualification](guides/browser-qualification.md): installed tarball
  execution and actual Chromium virtual ceremonies; exact qualified profile and
  explicit unavailable engine/device gates.
- [Protocol sources](reference/protocol-sources.md): immutable Chain source baseline.
- [API/platform qualification](reference/api-qualification.md): reviewed export/type
  inventory, installed consumers, dependency notices and measured local budgets.
- [Canonical API](reference/canonical-api.md): supported codecs/hashes and their limits.
- [HTTP RPC API](reference/http-rpc.md): envelope transport, limits, cancellation,
  errors, read retries and interoperability boundaries.
- [Typed Chain RPC API](reference/rpc.md): expected identity, finalized context,
  authorization/policy reads, fee contracts and advisory estimation/simulation.
- [Receipt API](reference/receipts.md): canonical commitments, bounded transaction/receipt
  observations, execution/consumption semantics and node trust boundaries.
- [Submission API](reference/submission.md): one send, typed uncertainty and bounded
  same-ID reconciliation with node-reported finality/consumption.
- [Account/session lifecycle](reference/lifecycle.md): DIRECT onboarding, bounded
  grant controls, both native transfer schemes, approval and post-finalized state.
- [Nonce coordination](reference/coordinator.md): explicit reservations, async authority
  binding, uncertain-send retention and durable adapter/recovery requirements.
- [Raw signer API](reference/signers.md): external key ownership, exact digest
  semantics, canonical witnesses, mutation guards and bounded cancellation.
- [Canonical review API](reference/display.md): frozen bytes/hash-bound policy,
  intent and transaction fields with exact amounts and authority semantics.
- [WebAuthn browser API](reference/webauthn-browser.md): explicit account-bound
  registration/assertion collection and bounded immutable transport responses.
- [WebAuthn representation API](reference/webauthn-parsers.md): bounded ES256
  COSE/authenticator/client-data/none-attestation/DER parsing; no verification claim.
- [RP conformance reference](reference/webauthn-rp-reference.md): maintained
  verifier, executable signed fixtures and single-process challenge/CAS evidence;
  not a production server or durable store.
- [Passkey authorization decision](decisions/0001-passkey-authorization-boundary.md).
- [Authoritative relying-party contract](decisions/0002-authoritative-webauthn-rp.md):
  selected WebAuthn implementation profile, challenge/store ownership and future
  verifier conformance; this decision is not a shipped server/browser API.
- [Security boundaries](security/threat-model.md).
- [Documentation policy](documentation-policy.md).
- [Contribution workflow](../CONTRIBUTING.md) and [agent instructions](../AGENTS.md).

GitHub issues own work status, ownership and acceptance. Future API references
must document implemented behavior and link source/tests rather than copy a plan
as if every proposed capability shipped.
