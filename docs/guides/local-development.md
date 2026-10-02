# Local development

Use this guide to build and verify the canonical codec SDK. It does not provision
a live chain, store a private key or implement a wallet.

## Prerequisites

- Node.js 24.21.0, recorded in `.nvmrc`; npm is supplied with the runtime.
- Python 3.11+ for repository documentation checks.
- Git and GitHub CLI for the contribution workflow.

From the SDK repository:

```sh
nvm install
nvm use
npm ci
npm run check
```

Use another runtime manager if preferred, but honor the pinned Node version.
`engine-strict` rejects unsupported Node runtimes. `package-lock.json` records
exact dependency versions/integrity; use `npm ci` rather than updating the lock
as an incidental development step.

## Commands

- `npm run format`: format supported repository files.
- `npm run format:check`: inspect formatting without editing.
- `npm run typecheck`: strict TypeScript without emitting files.
- `npm run docs:check`: local Markdown file-link and source-pin checks.
- `npm run build`: remove only this repository's `dist/` and emit ESM/declarations.
- `npm test`: build and run unit, independent vector and deterministic mutation tests.
- `npm run test:differential`: build and compare with the pinned Go oracle;
  requires `RSC_CHAIN_DIR` and native Chain prerequisites (see [testing](testing.md)).
- `npm run package:check`: pack to an owned temporary directory, install into a
  clean consumer, verify import and TypeScript resolution, then remove that temp directory.
- `npm run check`: formatting, types, docs, unit/vector tests and packaging in sequence.

The tests establish the supported codec/hash scope, not live authorization,
transaction signing or browser behavior. Successful import establishes packaging
only. See [testing](testing.md) for exact gates and coverage limits.

## Working with Chain

Chain is an external source/test dependency pinned in
[protocol-source.json](../../protocol-source.json). A sibling checkout is
convenient for development, but neither builds nor docs require that path.
Use the pinned revision in a disposable checkout for future integration runs.
Do not change another checkout's branch or wipe its data to align an SDK example.

Native node builds and any Chain changes follow Chain's own contributor rules.
Localnet credentials are test-only, retained separately from production keys.
