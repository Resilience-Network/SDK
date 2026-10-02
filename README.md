# Resilience Network SDK

Standalone TypeScript client SDK for Resilience Network web wallets and dApps,
originating from [Chain issue #25 (FR-013)](https://github.com/Resilience-Network/Chain/issues/25).

The implementation provides canonical transaction/session codecs and typed
hashes checked against pinned Chain and independent vectors, plus bounded HTTP
JSON-RPC envelope transport. It is not a production wallet or a released npm
package. Typed RPC methods, signer lifecycle and browser passkey APIs remain
planned work.

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
The root entry reexports these and the RPC transport. Protocol integers are `bigint`; public keys use
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

```ts
import { HttpRpcClient } from "@resilience-network/sdk/rpc";

const client = new HttpRpcClient({ url: "http://127.0.0.1:8545" });
const observation: unknown = await client.request("rsc_chainId");
```

Validate method results before use. The transport caps bytes, batches, deadlines
and read retries, matches IDs and exposes sanitized typed errors. Submissions get
one attempt; timeout is not proof of rejection. See the
[HTTP API and exact limits](docs/reference/http-rpc.md), including the pinned
node's omitted-null-result interoperability gap and separate qualification gates.

## Planned capabilities

- Ed25519 root/direct signer interfaces and Ed25519/P-256 session interfaces.
- Bounded session grants, policy inspection, submission and revocation.
- Typed RPC reads, simulations, receipts and ambiguous-submission handling.
- WebAuthn registration/authentication helpers with explicit trust boundaries.
- Browser and disposable-localnet examples verified against independent vectors.

P-256 session verification already exists in Chain. WebAuthn assertions sign a
different message: DER conversion alone cannot make a passkey assertion a valid
native session signature. The [authorization decision](docs/decisions/0001-passkey-authorization-boundary.md)
explains the boundary and the unresolved product choice.

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
