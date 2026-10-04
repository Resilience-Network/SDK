# Resilience Network SDK

Standalone TypeScript client SDK for Resilience Network web wallets and dApps,
originating from [Chain issue #25 (FR-013)](https://github.com/Resilience-Network/Chain/issues/25).

The implementation provides canonical transaction/session codecs and typed
hashes checked against pinned Chain and independent vectors, plus bounded HTTP
JSON-RPC transport, validated Chain authorization/fee/simulation reads and raw
Ed25519/P-256 transaction signers and canonical review data. Typed transaction/receipt observations and receipt commitments are implemented.
Single-send submission and bounded same-ID reconciliation are available.
Explicit funded DIRECT activation, grant controls and both native session schemes
are exposed through the [lifecycle API](docs/reference/lifecycle.md) with canonical
approval and coordinated nonces. Bounded WebAuthn representation parsers are
available alongside explicit browser ceremony collection. Authoritative verifier
conformance has an [executable Node reference](docs/reference/webauthn-rp-reference.md); actual engine, production RP durability and release qualification remain separate gates.

## Development

Use Node.js 24.21.0 (see `.nvmrc`), npm and Python 3.11 or newer:

```sh
npm ci
npm run check
```

`check` verifies formatting, strict TypeScript, docs, unit/vector/mutation tests
and the installed package import/types boundary. `npm run test:differential`
additionally compares with the pinned native Go package (see [testing](docs/guides/testing.md)).
Hosted CI is manual while workflows are paused; local equivalents are mandatory.

## Available codecs and hashes

Use `@resilience-network/sdk/core` for bytes, checked integers and Keccak, and
`@resilience-network/sdk/session` for transactions, authorization and grant codecs.
The root entry reexports these and the RPC clients. Protocol integers are `bigint`; public keys use
wire widths of 32 bytes for Ed25519 and 64 bytes X||Y for P-256.

```ts
import { hexToBytes, bytesToHex } from "@resilience-network/sdk/core";
import { transactionCodec, transactionId } from "@resilience-network/sdk/session";

const transaction = transactionCodec.decode(hexToBytes(canonicalTransactionHex));
const id = transactionId(
  expectedChainContext,
  transaction.intent,
  transaction.envelope,
);
console.log(bytesToHex(id));
```

See the [canonical API and supported scope](docs/reference/canonical-api.md).
Successful decoding/hashing establishes a canonical representation, not valid
signatures, live authority, inclusion or action success.

## Available HTTP transport

Use `ChainRpcClient` for [typed methods and identity/context checks](docs/reference/rpc.md).
It requires expected chain/genesis/capability from trusted application configuration.

```ts
import { HttpRpcClient } from "@resilience-network/sdk/rpc";

const client = new HttpRpcClient({ url: "http://127.0.0.1:8545" });
const observation: unknown = await client.request("rsc_chainId");
```

Validate method results before use. The transport caps bytes, batches, deadlines
and read retries, matches IDs and exposes sanitized typed errors. Submissions get
one attempt; timeout is not proof of rejection. See the
[HTTP API and exact limits](docs/reference/http-rpc.md), including the pinned
node envelope conformance. [Receipt reads](docs/reference/receipts.md) retain
failed-included consumption and explicit unknown lookup results; funded network
qualification remains a separate gate.

## Available raw signers

`signDirectTransaction` and `signRootTransaction` use explicitly owned external
Ed25519 adapters; `signSessionTransaction` additionally supports raw prehashed
P-256. They validate signatures, collect exactly the ROOT threshold and guard
async mutations/cancellation. An optional canonical approval callback binds
review to the exact public signing inputs before any key callback. See [the signer API](docs/reference/signers.md)
for exact digest contracts, ownership, examples and limits. They do not establish
current authority, coordinate nonces or submit transactions.

## Available canonical review

`@resilience-network/sdk/display` derives frozen permission, intent and transaction
review fields from exact canonical bytes/hash bindings. Every supported field,
zero cap, recipient/proof and authority boundary is explicit. See the
[review API](docs/reference/display.md) for mapping, exact base-unit formatting
and limits. Structure-only review does not establish live authority or signature
validity.

## Planned capabilities

- WebAuthn registration/authentication helpers with explicit trust boundaries.
- Authoritative RP verifier/store and actual browser-engine conformance.
- Reviewed combined passkey-login/native-session example and release qualification.

P-256 session verification already exists in Chain. WebAuthn assertions sign a
different message: DER conversion alone cannot make a passkey assertion a valid
native session signature. The [authorization decision](docs/decisions/0001-passkey-authorization-boundary.md)
explains the selected external key/application authentication boundary.

## Available WebAuthn representation parsers

`@resilience-network/sdk/webauthn` parses bounded canonical ES256 COSE keys,
registration/assertion authenticator data, `none` attestation objects, original
clientDataJSON and minimal DER signature representations. See the
[parser API](docs/reference/webauthn-parsers.md) for exact bounds and unsupported
forms. Authoritative challenge/origin/RP/UV/signature verification and one-use
storage still require the application RP; parsing does not grant Chain authority.

## Start here

- [Implementation plan](PLAN.md): scope, architecture, stages and acceptance gates.
- [Delivery roadmap](https://github.com/Resilience-Network/sdk/issues/13) and
  [tracking guide](docs/guides/project-tracking.md): milestone exit gates and
  actionable tasks with dependencies.
- [Documentation index](docs/README.md): development, sources and security.
- [Contributing](CONTRIBUTING.md) and [agent instructions](AGENTS.md).
- [Issues](https://github.com/Resilience-Network/sdk/issues): ownership and work status.

The proposed package name is `@resilience-network/sdk`; npm ownership and name
availability must be verified before release. The repository is private and
package publishing is disabled. No open-source license has been selected.

[Nonce coordination](docs/reference/coordinator.md) composes external signing and
single-send/reconciliation with explicit authority reservations. Applications own
validated authority reads and durable cross-tab/process adapters.

Run the [disposable native session example](docs/guides/session-example.md) with
`RSC_CHAIN_DIR=/absolute/pinned/chain npm run example:session`.
Native adversity checks are separate: `npm run test:session-e2e`.

Browser helpers are documented in the [browser API](docs/reference/webauthn-browser.md).
They collect public responses for an application-owned verifier and never replace
external native root/session signers.
