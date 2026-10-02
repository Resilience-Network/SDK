# Independent vector provenance

`chain-v1.json` is the byte-identical snapshot of Chain's
`reference/sessionauth/vectors/v1.json` at the revision in
[protocol-source.json](../../protocol-source.json). The SHA-256 in that manifest
is checked by `npm test`. Keep this file out of automatic JSON formatting.

The pinned source's independent Python model defines the original encodings,
Keccak digests, deterministic test-only signatures, grant identities and
transaction IDs. [Protocol sources](../../docs/reference/protocol-sources.md)
links its source and regeneration instructions. Snapshot updates require an
explained protocol/source change; SDK implementation output is never a fixture
generator.

The original fixture covers direct/root/session and sponsored transactions,
Ed25519/P-256 grants and sessions, root config and transfer policy. Missing
onboarding action layouts are independently generated from Go production structs
by [the differential oracle](../go-reference/main.go). The SDK's sample builder
must match those bytes exactly. Bucket/Merkle policies, recipient proofs and
remaining supported actions also receive canonical Go differential coverage.

See [testing](../../docs/guides/testing.md) for commands, mutation seeds and limits.
