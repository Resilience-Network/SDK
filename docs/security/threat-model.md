# SDK security boundaries

This initial threat model covers the planned client SDK. It is a design checklist,
not an audit report or a claim that any feature is implemented or qualified.

## Assets and trusted boundaries

Root/session private keys, exact reviewed transaction bytes, grant authority,
chain/genesis identity and user-visible permission limits are sensitive assets.
Wallet/signer adapters and the application origin control secrets and signing.
RPC responses, app metadata and network messages are untrusted inputs. A trusted
full-node connection is an explicit model; independent proof verification is deferred.

## Required controls

- Domain/replay: bind genesis/chain/account/grant/policy/epoch/nonce and message
  type exactly; reject unknown versions and context mismatches.
- Parsing/precision: enforce canonical widths/order, bounded collections and
  checked bigint arithmetic; reject malformed DER/CBOR and unvalidated EC points.
- Review/sign: derive the display from the actual canonical bytes, freeze signing
  inputs and detect async mutation. Untrusted app labels cannot redefine authority.
- Secrets: no private keys in RPC/logs/URLs, no default persistence, explicit signer
  ownership and reviewed storage/unlock adapters. JavaScript memory zeroization
  cannot promise removal of runtime copies or safety against XSS.
- State/nonce: reconcile uncertain submissions, distinguish action failure from
  rejection, serialize nonce use and observe finalized revocation.
- Passkeys: validate challenge/origin/RP/type/UV at an authoritative verifier,
  consume challenges once and expose the difference from raw session signatures.
  Synced authenticators and counter semantics need explicit treatment.
- Dependencies: pinned crypto implementations, independent vectors, dependency
  license inventory and reviewed release provenance; no unreviewed runtime hooks.

## Limits and release gates

A compromised origin/signer process, user-approved unrestricted authority or a
dishonest trusted RPC cannot be fixed by a client-side display alone. Simulation
is advisory; pending transactions are public. Use appropriate slippage/deadline
controls in market-sensitive applications.

Independent signing/parsing review, negative tests and end-to-end evidence are
release gates in [PLAN.md](../../PLAN.md). Any direct passkey authorization design
requires its own enforcement-boundary review and coordinated chain/contract scope.
