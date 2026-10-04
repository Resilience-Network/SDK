# Native SDK integration and troubleshooting

The private [SDK repository](https://github.com/Resilience-Network/sdk) implements
canonical transparent account/session codecs, exact hashes, external raw signers,
validated RPC/receipts, canonical review, bounded submission/reconciliation and
explicit lifecycle/nonce coordination. Use the public root or focused core,
session, rpc, display and webauthn entrypoints. Do not infer shielded-wallet,
sponsorship lifecycle, Ethereum transaction serialization or a browser provider
extension from these exports. [Canonical API](../reference/canonical-api.md) and
[lifecycle](../reference/lifecycle.md) define the supported operation scope.

## Consume an actual package

Use Node 24.21.0 and npm with the repository lockfile. Registry publication and
SDK licensing are separate owner/security gates; the package remains private,
version 0.0.0 and UNLICENSED. Do not invent a published npm install/version.
Authorized source consumers can build and create a local tarball:

```sh
npm ci
npm run check
npm run build
npm pack --ignore-scripts --pack-destination /absolute/owned/package-directory
```

Install that exact archive into a separate application's package manifest and
retain its hash/version with the application. A production application supplies
its own trusted deployment, signer/storage/UI providers and reviewed lockfile.
The executable installed-consumer gate runs the reviewed example unchanged apart
from two owned test-harness import URLs:

```sh
RSC_CHAIN_DIR=/absolute/path/to/clean/pinned/chain npm run example:session-installed
```

The copied application imports the SDK inside the newly installed consumer. The
owned network harness remains repository test tooling and uses its own SDK for
bootstrap/readiness; it does not supply the application lifecycle client. The native
RPC client is constructed from the installed SDK, avoiding accidental class
identity across source and installed module trees. This actually provisions a
funded native four-validator network and runs DIRECT activation plus grant,
transfer and finalized ROOT revocation for Ed25519/raw P-256 sessions. It verifies
known-secret log redaction and closes/removes successful owned state; failure
retains restricted safety state. See [native ownership](native-localnet.md).

Ignored artifacts/installed-session/latest.json records exact SDK/source/tarball
hashes and native ownership evidence. The source/copy hashes account explicitly
for the two harness import substitutions; no SDK import is rewritten to repository
dist. This demonstrates a local source archive, not npm publication verification.

## Configure authority and approval

Trust configuration outside the queried node. Application wiring starts with:

```ts
import {
  AUTHORIZATION_CAPABILITY,
  ChainRpcClient,
  SessionLifecycle,
  NonceCoordinator,
  hexToBytes,
} from "@resilience-network/sdk";

// These providers are application-owned; do not discover expected identity from RPC.
const context = {
  chainId: BigInt(deployment.chainId),
  genesisHash: hexToBytes(deployment.genesisHash),
};
const client = new ChainRpcClient({
  url: deployment.rpcUrl,
  expected: { ...context, authorizationCapability: AUTHORIZATION_CAPABILITY },
});
const lifecycle = new SessionLifecycle({
  context,
  client,
  coordinator: new NonceCoordinator(durableReservationStore),
});
```

This is illustrative application wiring: deployment, durableReservationStore,
external signers and review UI must be supplied by the app. The executable
examples use isolated test providers, not a production storage/unlock recommendation.
Wire/protocol quantities use checked bigint and canonical Uint8Array; convert
human amounts with an application-defined exact decimal policy, not Number.

DIRECT/ROOT keys are Ed25519. SESSION keys can use raw Ed25519 or P-256 over the
SDK's exact precomputed digest. RawSigner exposes public scheme/key and a digest
sign callback; private keys never belong in RPC. Browser ECDSA sign hashes its
input, and WebAuthn assertions sign a different message: neither is an implicit
raw SessionDigest provider. Use [signers](../reference/signers.md) and the
[selected key model](../decisions/0001-passkey-authorization-boundary.md).

Every lifecycle request supplies owner/operation/fees/reservation ID and an
explicit approval callback. Render the frozen canonical review and require a
literal true after user consent. Re-read current authority through validated
methods; a policy/nonce/epoch change needs a new explicit review, not a silent
refresh/re-sign. Configure bounded cancellation/reconciliation and a durable
linearizable shared reservation adapter for multiple tabs/processes or restarts.
MemoryNonceReservationStore is a single-process test/app adapter only.

Passkey application login is separately verified by the authoritative RP. The
[combined example](passkey-session-example.md) demonstrates separate app identity,
external native keys and canonical approvals; clearing an app session is not
native grant revocation. None registration requires fresh possession proof.
Physical-device, durable production RP and independent security review remain
separate qualification gates.

## Understand outcomes before recovery

A simulation is advisory. A valid simulated witness does not reserve authority,
prove admission/finality or guarantee execution success. Some rejected witnesses
produce typed node errors rather than authorized:false. Actual submission returns
reported-accepted, reported-rejected, not-sent or unknown with a local transaction
ID and zero/one send attempt; a node rejection is not necessarily a thrown SDK
exception. Consult [submission](../reference/submission.md) for exact contracts.

An unknown send may have reached the node. Preserve the canonical bytes, ID,
reservation and signing records. Use explicit bounded read-only reconciliation
of the same ID against the configured trusted node; never resend/re-sign or pick
a speculative next nonce to make an uncertainty disappear. Missing/pruned history,
a moved nonce or vanished grant alone does not prove this transaction consumed it.

Reported finalized action failure consumes the authority nonce and actual fee;
SESSION failure also consumes an attempt, with value/success rollback. ROOT nonce
and account nonce are distinct. SESSION_CANCEL consumes attempt/fee and keeps the
grant active; finalized ROOT revocation or epoch change removes authority. See
[receipt semantics](../reference/receipts.md) and [lifecycle](../reference/lifecycle.md).

Canonical receipt/event/counter commitments are checked locally from bounded
supplied data. Node observations and reported finality are not independent
consensus inclusion proofs against a separately trusted chain commitment.

## Diagnose failures without losing safety state

- Identity/capability mismatch: inspect trusted deployment and pinned protocol;
  reject the operation. Never learn the expected genesis from the suspect response.
- Unsupported encoding/action/scheme: use the supported canonical API; no legacy
  decoder or compatibility fallback is provided. P-256 DIRECT/ROOT is unsupported.
- Context/authority changed: fetch fresh validated reads and obtain a new review;
  preserve any already-signing/signed/uncertain reservation.
- Review rejected or pre-aborted: the lifecycle signs/sends nothing and reserves
  nothing. Failure after signing may require explicit recovery instead.
- RPC deadline/network failure: distinguish not-sent from unknown; inspect the
  bounded typed result and same-ID history. Do not retry the write automatically.
- Finalized failure: account for nonce/fee/attempt consumption before making a new
  request; rolled-back value does not mean the nonce is reusable.
- Revocation: wait for reported finalized native state and verify current grant or
  epoch. A local logout/cancel does not revoke on-chain authority.
- Local test failure: retain owned evidence and restricted runtime/signing state.
  The harness closes only owned children; it never repairs failures by deleting
  existing keys, databases or signing watermarks.

The canonical Chain [wallet guide](https://github.com/Resilience-Network/Chain/blob/main/docs/guides/wallet-integration.md)
is coordinated in [Chain#383](https://github.com/Resilience-Network/Chain/issues/383)
under [Chain#25](https://github.com/Resilience-Network/Chain/issues/25).
The SDK's executable source remains pinned independently of later documentation
commits; updating a guide does not qualify a changed protocol or new runtime.
