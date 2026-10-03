# Protocol source baseline

The SDK codec baseline is Chain revision
`007356ef5e5e1769cfda2290fcafc9db5d48bbfd`. It contains the reviewed explicit-null response correction in
[Chain PR #379](https://github.com/Resilience-Network/Chain/pull/379). Supported
codec/hash conformance is checked by independent and Go tests; this is not production authorization approval.
[protocol-source.json](../../protocol-source.json) records the same immutable pin
and the SHA-256 of the upstream vector file. The identical fixture is checked in
under [tests/vectors/chain-v1.json](../../tests/vectors/chain-v1.json); unit tests
verify its hash before using it. No upstream golden value was regenerated.

## Governing implementation and documentation

- [Authorization architecture](https://github.com/Resilience-Network/Chain/blob/007356ef5e5e1769cfda2290fcafc9db5d48bbfd/docs/architecture/authorization.md).
- [Session protocol](https://github.com/Resilience-Network/Chain/blob/007356ef5e5e1769cfda2290fcafc9db5d48bbfd/docs/reference/protocol/session-authorization.md).
- [Authorization decisions](https://github.com/Resilience-Network/Chain/blob/007356ef5e5e1769cfda2290fcafc9db5d48bbfd/docs/decisions/session-authorization.md).
- [P-256 session keys](https://github.com/Resilience-Network/Chain/blob/007356ef5e5e1769cfda2290fcafc9db5d48bbfd/docs/reference/protocol/p256-session-keys.md).
- [Wallet integration](https://github.com/Resilience-Network/Chain/blob/007356ef5e5e1769cfda2290fcafc9db5d48bbfd/docs/guides/wallet-integration.md).
- [RPC request contracts](https://github.com/Resilience-Network/Chain/blob/007356ef5e5e1769cfda2290fcafc9db5d48bbfd/docs/reference/rpc-requests.md).
- [Canonical codecs](https://github.com/Resilience-Network/Chain/tree/007356ef5e5e1769cfda2290fcafc9db5d48bbfd/pkg/sessionauth): codec.go, hash.go, verify.go, types.go, constants.go and action_codec.go.
- [Authorization RPC handlers](https://github.com/Resilience-Network/Chain/blob/007356ef5e5e1769cfda2290fcafc9db5d48bbfd/internal/rpc/authorization_api.go).
- [Independent model and vectors](https://github.com/Resilience-Network/Chain/tree/007356ef5e5e1769cfda2290fcafc9db5d48bbfd/reference/sessionauth).

The independent model has deliberately incomplete coverage. Inventory current
vectors against the pinned codecs before extending scope; record provenance and
identify missing/stale scenarios instead of assuming all chain fields are covered.
Any golden change requires semantic explanation and reviewed upstream evidence.

P1 covers the existing independent transfer/root/session/sponsored vectors.
Onboarding layout gaps (activation, revoke/replace, rotate, reserve, cleanup) are
covered by native Go-generated field fixtures and differential tests. Transfer
token buckets, Merkle recipients and proofs have Go differential coverage rather
than independent Python vectors. Receipt deltas/events and internal decision
commitments have independent native Go conformance; other intent/policy grammars
remain outside the initial supported scope; see [canonical API](canonical-api.md).

The [typed RPC API](rpc.md) consumes this same pin. Its native fixture gate
checks production handler projections and stateful simulation using owned
in-memory state. Stored authority/grant projections follow state_codec.go and
state_validate.go; simulation event framing follows receipt.go. These files are
recorded as sources; the codec-vector SHA-256 is unchanged.
[Receipt commitments and reads](receipts.md) add independent native field/hash
fixtures; funded lifecycle execution remains a separate delivery gate.

## Integration rules

The chain uses canonical Transaction V2 rather than standard Ethereum transaction
serialization. Hashes use original Keccak-256 padding, not SHA3-256. DIRECT/ROOT
are Ed25519; SESSION additionally supports raw P-256 X||Y keys and r||s signatures
over SessionDigest. Unknown formats fail closed. P-256 currently has no low-S
consensus rule; do not invent one as a client-side validity requirement.

Runtime identity requires expected chain ID/genesis and authorization capability;
RPC reports do not establish independently authenticated finality. Simulation is
advisory, receipt inclusion is distinct from successful execution, and bounded
transaction lookup cannot prove an old transaction never existed.

Update the pin only in a reviewed protocol-baseline PR with a field/domain/limit
diff, refreshed provenance, independent vectors and applicable node evidence.
Never silently negotiate old wire formats or patch existing databases/signing state.

## Reviewed baseline change

The complete diff from bootstrap revision
`773d20810e46a67e2cc68a3e58df7c08e5ac3784` contains exactly
`internal/rpc/types.go`, `internal/rpc/response_contract_test.go` and
`docs/reference/rpc.md`. Responses now include `result:null` for successful absent
lookups and omit `result` on errors. Request dispatch, canonical bytes, signing
domains, policy limits, gas, activation, state roots, manifest, genesis and
independent model/vector files are unchanged. No golden value was regenerated.

Display and SDK-only signing-binding goldens retain their original generation
revision and record this revision as `validatedAtRevision`. Their independent
vector/model hashes remain unchanged. The native RPC gate regenerates all typed
fixtures and [envelope fixtures](../../tests/fixtures/rpc-envelopes.json) at the
new revision. Envelope fixtures distinguish public API lookups from test-only
falsy-value probes registered on the production Handler. They establish envelope
interoperability, without proving running-network acceptance or finality.

Request-ID validation and notification dispatch remain separately reported in
[Chain#378](https://github.com/Resilience-Network/Chain/issues/378). The SDK sends
explicit numeric IDs and does not use notifications.

The lifecycle baseline consumes reviewed [Chain PR #381](https://github.com/Resilience-Network/Chain/pull/381)
for canonical IDs in decoded block RPC transaction lists. No codec/hash, gas,
state-root, manifest or genesis encoding changed. Native fixture goldens are
revalidated at the new immutable pin; signing-review golden digest values are
unchanged and only their validation provenance advances.
