# Protocol source baseline

The SDK planning baseline is Chain revision
`773d20810e46a67e2cc68a3e58df7c08e5ac3784`. It was main when the bootstrap was
prepared. This is source provenance, not SDK conformance or production approval.
[protocol-source.json](../../protocol-source.json) records the same immutable pin
and the SHA-256 of the upstream vector file. This scaffold has not imported or
executed those vectors; provenance is recorded for the P1 conformance work.

## Governing implementation and documentation

- [Authorization architecture](https://github.com/Resilience-Network/Chain/blob/773d20810e46a67e2cc68a3e58df7c08e5ac3784/docs/architecture/authorization.md).
- [Session protocol](https://github.com/Resilience-Network/Chain/blob/773d20810e46a67e2cc68a3e58df7c08e5ac3784/docs/reference/protocol/session-authorization.md).
- [Authorization decisions](https://github.com/Resilience-Network/Chain/blob/773d20810e46a67e2cc68a3e58df7c08e5ac3784/docs/decisions/session-authorization.md).
- [P-256 session keys](https://github.com/Resilience-Network/Chain/blob/773d20810e46a67e2cc68a3e58df7c08e5ac3784/docs/reference/protocol/p256-session-keys.md).
- [Wallet integration](https://github.com/Resilience-Network/Chain/blob/773d20810e46a67e2cc68a3e58df7c08e5ac3784/docs/guides/wallet-integration.md).
- [RPC request contracts](https://github.com/Resilience-Network/Chain/blob/773d20810e46a67e2cc68a3e58df7c08e5ac3784/docs/reference/rpc-requests.md).
- [Canonical codecs](https://github.com/Resilience-Network/Chain/tree/773d20810e46a67e2cc68a3e58df7c08e5ac3784/pkg/sessionauth): codec.go, hash.go, verify.go, types.go, constants.go and action_codec.go.
- [Authorization RPC handlers](https://github.com/Resilience-Network/Chain/blob/773d20810e46a67e2cc68a3e58df7c08e5ac3784/internal/rpc/authorization_api.go).
- [Independent model and vectors](https://github.com/Resilience-Network/Chain/tree/773d20810e46a67e2cc68a3e58df7c08e5ac3784/reference/sessionauth).

The independent model has deliberately incomplete coverage. Inventory current
vectors against the pinned codecs before implementation; snapshot provenance and
identify missing/stale scenarios instead of assuming all chain fields are covered.
Any golden change requires semantic explanation and reviewed upstream evidence.

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
