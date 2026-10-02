# Local development

Use this guide to verify the repository scaffold. It does not provision a chain,
store a private key or implement a wallet.

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
- `npm run package:check`: pack to an owned temporary directory, install into a
  clean consumer, verify import and TypeScript resolution, then remove that temp directory.
- `npm run check`: all scaffold checks in sequence.

No feature test suite exists yet. The emitted module exports no public functions;
successful import verifies packaging only. Do not treat it as transaction signing
evidence. See [testing](testing.md) for feature gates.

## Working with Chain

Chain is an external source/test dependency pinned in
[protocol-source.json](../../protocol-source.json). A sibling checkout is
convenient for development, but neither builds nor docs require that path.
Use the pinned revision in a disposable checkout for future integration runs.
Do not change another checkout's branch or wipe its data to align an SDK example.

Native node builds and any Chain changes follow Chain's own contributor rules.
Localnet credentials are test-only, retained separately from production keys.
