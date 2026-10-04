# API and platform qualification profile v1

The private `0.0.0` candidate implements the six ESM entry points declared in
`package.json`: root, core, session, rpc, display and webauthn. There is no CommonJS
or legacy encoding adapter. [The versioned inventory](../../qualification/api-v1.json)
records all 95 root runtime exports, each subpath's exports and SHA-256 values of
all emitted declarations. Any export or type change fails qualification until
review updates this inventory; a hash change is a review trigger, not evidence
that a semantic change is harmless.

## API review and integration boundaries

- Core accepts checked canonical bytes and exact bigint quantities. Integer
  encoding, bounded ownership, explicit errors and original digest domains follow
  the [immutable native baseline](protocol-sources.md).
- Session exposes native codecs, external raw signer contracts, byte-bound review,
  nonce coordination and lifecycle. ROOT/DIRECT require Ed25519; SESSION supports
  Ed25519 and P-256 raw x/y points. WebAuthn assertions never substitute for a
  native session signature. Providers and durable atomic stores remain caller-owned.
- RPC validates trusted identity/context, typed reads and bounded observations.
  Simulation is advisory. One-send submission represents uncertain and rejected
  outcomes explicitly; finality is node-reported and does not supply a light client.
- Display derives immutable exact amount/authority fields from the authorized
  canonical bytes. It does not supply a UI approval or custody policy.
- WebAuthn provides bounded representations and explicitly invoked ceremonies.
  Parsing does not authenticate an application. The maintained RP conformance
  implementation is a development reference, excluded from the published archive.
- Errors are public nominal classes with documented code sets in their respective
  references. Callers use codes, never error-message parsing. Caller-controlled
  callback objects/messages are sanitized at reviewed boundaries. Node RPC errors
  retain their documented wire semantics rather than claiming all node payloads
  are trustworthy.

No backward compatibility is required at this development stage. Make a reviewed
breaking change, update documentation/inventory and independently checked vectors
where semantics require it; never silently add a migration, dual decoder or
legacy fallback. Stable versioning and publication require the release gates.

## Declared tested profile

The qualification runtime is exactly Node 24.21.0 on macOS arm64, npm 11.12.1,
TypeScript 7.0.2 and esbuild 0.28.2. Installed-tarball TypeScript resolution and
cold Node imports run through `npm run package:check`. Package engines permit
Node 24.21.0 through versions below 25; that range is an installation constraint,
not evidence that future minor versions or other operating systems passed.

Actual browser evidence uses installed Chrome 154.0.8037.95, headless on macOS
26.6.2 arm64 with isolated virtual CTAP2.1 credentials. It exercises all six
installed entry points and real ceremonies through the maintained verifier.
[Browser qualification](../guides/browser-qualification.md) describes this exact
scope. Other engines remain [#69](https://github.com/Resilience-Network/sdk/issues/69),
physical devices [#31](https://github.com/Resilience-Network/sdk/issues/31), and
independent audit [#34](https://github.com/Resilience-Network/sdk/issues/34).

## Executable budgets and evidence

Run `npm run test:api-qualification` after `npm ci` and `npm run check` using the
pinned runtime. It installs a newly packed archive into an owned temporary
consumer, compares actual exports and declarations to the reviewed inventory,
bundles every entry separately with minification and tree shaking disabled,
rejects unresolved external/browser Node imports, and measures actual codec and
both raw signing paths. Node cold imports fail on network or browser-global
access. Existing package/type checks and actual browser checks remain required;
a successful bundle is not a browser execution claim.

The predeclared per-entry ceilings are 600,000 uncompressed bytes and 150,000 gzip
bytes. The median per-operation ceilings are 2 ms for intent encode/decode plus
DIRECT digest and 100 ms for each Ed25519/P-256 SESSION signing/verified witness
plus transaction roundtrip. These are generous regression ceilings for this
local profile, not network, hardware-provider or production latency promises.
Five warmed batches use 100 codec operations or 10 signing operations each.
Results record both median and maximum batch averages, versions, source/revision,
cleanliness, archive/bundle/declaration hashes and actual dependency notices in
ignored `artifacts/api-qualification/latest.json`. A dirty result is development
evidence; reviewed candidate qualification requires a clean matching revision.

Runtime dependencies are exactly `@noble/curves@2.4.0` and
`@noble/hashes@2.4.0`. Their installed MIT license texts are checked and hashed;
package installation retains the dependencies' own notices. The SDK remains
private and UNLICENSED: those third-party notices do not authorize SDK publication.
The archive allowlist ships only dist, README and package metadata, excluding
keys, fixtures, verifier, browser/native harnesses and release tooling. License
and publication decisions remain [#35](https://github.com/Resilience-Network/sdk/issues/35)
and [#38](https://github.com/Resilience-Network/sdk/issues/38).
