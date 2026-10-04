# Owned native localnet

The [harness](../../scripts/localnet/harness.mjs) builds and starts real native
Chain validators for SDK integration. It never invokes Chain's shared
localnet start/stop/reset scripts. [Smoke qualification](../../scripts/check_localnet.mjs),
[failure qualification](../../scripts/check_localnet_failures.mjs) and
[supervisor tests](../../tests/localnet-harness.test.mjs) are distinct executable gates.
[Capture tests](../../tests/localnet-logs.test.mjs) cover log evidence boundaries.

## Run

Use the pinned Node runtime and a clean immutable detached Chain checkout matching
[protocol-source.json](../../protocol-source.json). Rust and CGO-enabled Go are
required; existing native target caches are retained. From this SDK:

```sh
npm ci
RSC_CHAIN_DIR=/absolute/path/to/pinned-chain npm run test:localnet
RSC_CHAIN_DIR=/absolute/path/to/pinned-chain npm run test:localnet-failures
```

The first command builds `make build-crypto`, then native node/keygen binaries in
its owned runtime. It checks CGO=1 and runs Chain's static-link/release-loader check.
A public test genesis is generated with four validators, 20,000 RSC self-stake
per validator, fresh genesis time/keys, a separate owner funded with 1,000 RSC and
an unfunded recipient. The explicit test-only `overflowRecipient: true` option
adds a separate generated recipient with balance `2^256-1`. It lets supported
transfers fail execution (recipient overflow) after authorization, without a
contract/unsupported action or node source change. It is never enabled implicitly.
Keys are generated solely for this disposable network;
never use these files/accounts for valuable assets or another genesis.

The [native bootstrap oracle](../../tests/go-localnet-reference/genesis_test.go)
is exclusively installed with a unique test filename, calls production
`ApplyGenesisState`/`AssembleGenesisBlock` at the pinned source and computes the
expected genesis block/state/manifest identity before startup. Content is checked
before removing exactly that temporary file. A modified file is preserved and
fails the run. The checkout must be clean before/after native generation and after
successful integration; no production Chain source/golden is edited.

## Profile and checks

The default is four validators, one-second slots, 32 slots per epoch, minimum gas
price 1 gwei, 30 million gas limit, private loopback subnet bypass, no mDNS and
explicit earlier-validator bootstrap peers. RPC/P2P/WebSocket use unique leased
loopback ports. Releasing those leases before native bind has an unavoidable OS
race: a collision fails startup; it never stops another process or steals a port.
The programmatic harness permits an explicitly requested single-validator profile;
it never silently downgrades a failed four-validator run.

Shielded, names and liquid staking activate at height 1 in this local test profile.
The native node receives the existing experimental shielded acknowledgment;
CGO/static linkage and served shielded read APIs are verified. This is no claim
of full shielded wallet/proof lifecycle qualification or production approval.

Readiness defaults to 120 seconds for the network, bounded to 1–300 seconds;
individual RPCs have 2–3 second budgets. The integration callback has a separate
10-minute default budget (`workTimeoutMs`, 1 ms–1 hour); callback timeout/abort
races ignored promises, consumes late failures and still enters owned teardown. Require real RPC identity matching the
independently initialized genesis, finalized height at least 3 on every node,
and exact block hash/state-root agreement at one common height. The smoke command
also verifies the funded owner balance, shielded tree/pool reads, and actual SDK
root authority, advisory fees and absent transaction receipt observations on each
node. There is no mocked-node or empty-suite substitute for these checks.

`withNativeLocalnet(options, callback)` exposes the trusted expected identity,
endpoints, SDK clients, generic HTTP clients, public wallets, owned runtime/key
paths, abort signal and evidence object. Higher-level integration can use the
existing test-only key files through external signer adapters. The callback must
honor cancellation and avoid logging secrets; native full lifecycle acceptance is
separately owned by the lifecycle/integration tasks.

## Ownership and evidence

Each run creates a canonical temporary directory named `resilience-sdk-native-*`,
mode 0700, with an exclusive ownership marker containing a random ID, exact path,
source pin and disposable flag. It creates only fresh keys/config/data/signing state
inside that directory. Existing repositories' nodes, keys, wallets, databases,
locks and signing records are outside its ownership. It never scans process names,
loads stale PID files or removes shared `.localnet` directories.

Native commands and nodes run inside owned POSIX groups anchored by a separate
live [group supervisor](../../scripts/localnet/group-supervisor.mjs). Command
exit and supervisor closure are separate: command results remain available while
the supervisor holds the group identity for descendant teardown. The
[process controller](../../scripts/localnet/processes.mjs) signals only a live
spawned supervisor's group, allows five seconds for SIGTERM, then escalates to
SIGKILL with a two-second descriptor-closure bound. An exited supervisor is never
signaled by its old PID; unexpected supervisor exit fails containment acceptance.
The live anchor prevents group-ID reuse during normal teardown, consistent with
[POSIX group lifetime and ID reuse](https://pubs.opengroup.org/onlinepubs/009696699/basedefs/xbd_chap04.html).

The candidate runner can propagate a private descriptor through tracked group
supervisors to await their closure even if command stdout is ignored; forwarding
requires matching descriptor identity. Native teardown still owns its handles.
Owner IPC disconnect also starts supervisor-owned SIGTERM/5-second SIGKILL cleanup,
so killing an integration owner cannot silently abandon its detached validator
groups. This is bounded containment of tracked commands and descendants that stay
in their owned group. Commands deliberately creating untracked sessions or an
external SIGKILL of the supervisor alone are outside that containment contract;
retained descriptors or unexpected lease death fail rather than authorize stale
PID killing or runtime deletion. The Windows direct-child fallback remains
unqualified for descendants. Actual native evidence is currently macOS only.
Supervisor tests cover command exit with inherited-pipe descendants, stuck
termination, actual nonzero/spawn-failure results and an unrelated process that
stays running. Evidence records actual node PIDs separately from supervisor PIDs;
neither is later authorization to kill a process.

After all owned child handles close, successful runs remove only their fresh owned
runtime, checking the direct path is not a symlink, the canonical temporary-root
namespace and unchanged ownership marker/path/ID. This is planned disposal of a
fresh test network. A failure/interrupt/ownership mismatch preserves the complete
restricted runtime, including signing watermarks/locks/databases/keys. Failed
teardown sets the top-level status to `failed` with `TEARDOWN_FAILED`, even when
integration activity succeeded; it never retains a passing status or disposes the
runtime. Supervisor command results and actual group/descriptor closure are
separate evidence, as covered by [outcome regressions](../../tests/localnet-outcome.test.mjs). A timeout
never deletes safety state. Keep retained failed directories for inspection and
explicit retirement; do not restart them under another genesis/configuration.

Public evidence is retained under ignored `test-results/localnet/<run-id>/`:
revision/toolchain/native CGO/static-build information and hashes, exact command
arguments, generated public genesis/configs, independently derived identity,
public validators/wallets, actual checks, node handles/PIDs, teardown status and
text logs. Each command entry records its actual `log` filename: node starts
use `node-N.log`, other commands use `command-N.log`. `logCapture` lists every
required file with captured byte size and SHA-256, or a sanitized failure code.
Capture refuses symlinks, nonregular sources, artifact replacements and logs over
8 MiB; it checks the actual read bound as well as file size. Qualification verifies
the copied bytes, manifest coverage and generated-key redaction. A required capture
failure rejects an otherwise successful run and preserves its restricted runtime.
The closure field describes actual supervised group/descriptor closure. A failed
cleanup procedure still rejects delivery and retains its runtime even if those
groups already closed. The native failure suite injects that post-closure error
without abandoning any child, then verifies failed status/TEARDOWN_FAILED, retained
safety state and unchanged external sentinel.
An early failed run may have no commands/logs; it is never passing native evidence.
Key files, databases and signing records are never copied into public artifacts. Exact generated private-key strings are redacted from copied logs;
callback errors use a fixed evidence code. These artifacts can still contain
local paths/network metadata and are owner-readable only. Treat callback logging
as a separate application responsibility. Do not count initial or failed evidence
as a final passing run.

Failure qualification executes real native setup failure, a ready-network failure,
a readiness deadline, a callback ignoring cancellation, actual SIGINT/SIGTERM and
an injected missing log (renamed in the owned runtime, preserving its bytes).
Each verifies the capture manifest and asserts stopped owned handles,
retained restricted runtime and unchanged external signing-state sentinel. Path,
port, process and tampering unit tests supplement this evidence. All runtime/PIDs
in evidence belong to that run; retained PIDs are historical references, never
later authorization to kill a process.

A working native harness qualifies startup/identity/progress/API/teardown behavior.
[Funded lifecycle qualification](../../scripts/check_lifecycle.mjs) separately checks
actual SDK activation/grant/transfer/revocation. [Session adversity qualification](../../scripts/check_session_end_to_end.mjs)
checks expiry/replay/included failure/concurrency and actual lost HTTP responses;
[the executable example](../../examples/session-localnet.mjs) demonstrates both schemes. Harness checks do not prove Byzantine resilience,
independent finality verification, browser/device behavior or security review.
