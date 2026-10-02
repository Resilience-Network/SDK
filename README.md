# Resilience Network SDK

Standalone TypeScript client SDK for Resilience Network web wallets and dApps,
originating from [Chain issue #25 (FR-013)](https://github.com/Resilience-Network/Chain/issues/25).

This repository currently contains the build scaffold, contributor workflow and
implementation plan. It exports no client functionality yet and is not a
production wallet or a released npm package.

## Development

Use Node.js 24.21.0 (see `.nvmrc`), npm and Python 3.11 or newer:

```sh
npm ci
npm run check
```

`check` verifies formatting, strict TypeScript, repository documentation, build
output and the package import/types boundary. It does not claim browser,
cryptographic or live-network coverage. Hosted CI is manual while workflows
are paused; contributors must run the complete applicable suite locally.

## Planned capabilities

- Canonical Transaction V2 codecs, Keccak hashes and chain/genesis binding.
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
- [Documentation index](docs/README.md): development, sources and security.
- [Contributing](CONTRIBUTING.md) and [agent instructions](AGENTS.md).
- [Issues](https://github.com/Resilience-Network/sdk/issues): ownership and work status.

The proposed package name is `@resilience-network/sdk`; npm ownership and name
availability must be verified before release. The repository is private and
package publishing is disabled. No open-source license has been selected.
