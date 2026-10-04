# Nonce coordination

[NonceCoordinator](../../src/session/coordinator.ts) composes application-owned
validated authority reads and external signing with one SDK submission and bounded
same-ID reconciliation. [Executable tests](../../tests/coordinator.test.mjs) define
concurrency, state binding and recovery behavior. This is trusted-node coordination,
not an independent authorization proof or a custody/key-storage service.

## Authority and flow

`NonceAuthoritySnapshot` supplies trusted expected chain/genesis, owner, mode,
key scheme, credential ID, epoch, policy hash, observed nonce, authority-state hash
and finalized height/block/state-root. Obtain these from consistent validated
[RPC observations](rpc.md). `authorityHash` must cover the exact canonical
root/grant/usage state being authorized; the coordinator cannot authenticate an
application callback that invents a snapshot. DIRECT uses epoch/credential/policy
zero and Ed25519; ROOT uses epoch/config hash and Ed25519; SESSION uses its exact
grant/epoch/policy/scheme. All integers are checked bigint uint64 and byte widths
are fixed. Sponsored signing is unsupported by the current external signer API.

`execute(options)` validates/copies the exact intent and chain domain before
awaiting. An application supplies a unique persisted `reservationId` (16–80
ASCII letters/digits/underscore/hyphen), `readAuthority(signal)`, `sign(request)`,
the SDK client and optional overall timeout/reconciliation options. Defaults:
30 seconds overall; maximum 300 seconds. The overall timeout includes storage,
reads, signing, submission and reconciliation. No next nonce is chosen, no signer
replacement/retry occurs, and contention throws `CoordinatorError("CONFLICT")`.

The flow reads authority, atomically reserves its slot, rereads authority before
signing, durably records `signing` before the key callback, validates the returned
canonical transaction against the exact intent/authority, persists signed bytes/ID,
rereads authority after signing, persists uncertainty, sends once and reconciles.
Callbacks receive a frozen object containing string-only `FrozenNonceSnapshot`,
canonical intent hex and the signal. Existing [signer helpers](signers.md) provide
canonical review and cryptographic verification; use them inside `sign`.

Rereads may advance finalized height with unchanged authority. They cannot change
nonce, epoch, scheme, grant/config, policy or authority hash, regress height or
contradict an equal-height block/state-root. Such changes fail rather than silently
refreshing already reviewed authority. Original options, returned mutable snapshots
and returned signed transaction are checked at asynchronous boundaries, including
callback failures. Once signing begins, cancellation/mutation/failure leaves the
record held. A callback can export a usable signature before rejecting/timing out;
absence of a returned transaction is not evidence that nothing was signed.

Successful and failed finalized inclusion both mark the reservation `consumed`.
A later flow requires a fresh observed greater nonce in that epoch; a ROOT epoch
advance permits its protocol nonce reset after a terminal reservation. Pending,
unknown, rejected and not-sent outcomes retain signed bytes and remain `uncertain`:
external code could already possess the signature, and rejection does not prove
that the same ID was never previously accepted. No automatic nonce reuse occurs.

## Storage and ownership

`nonceAuthorityKey(snapshot)` uses the SDK namespace, ChainDomain, owner and mode;
SESSION also includes grant ID. Epoch/config are excluded from the slot key so
changed authority cannot bypass a held older reservation. Different networks,
owners and grants have independent slots. The coordinator keeps one reservation
per slot and monotonically increasing revision/consumption records.

`MemoryNonceReservationStore(maximumAuthorities = 1024)` is atomic only for callers
sharing that exact adapter instance in one process. Its bound is 1–10,000 authorities;
records are retained, including terminal watermarks. New coordinator instances can
recover when they share the same adapter. New processes, tabs or lost in-memory
state have no shared guarantee. Memory records and frozen snapshots contain public
JSON strings/numbers, never private keys or signatures from a private-key API.
Signed transaction bytes are nevertheless authorization evidence; protect storage
against tampering/deletion and unnecessary disclosure.

For cross-tab/process/crash guarantees, inject `NonceReservationStore`:

- `read(key)` must be linearizable and return the complete current record or null.
- `compareExchange(key, expectedRecordOrNull, replacement)` must atomically compare
  the complete expected record and durably persist replacement before returning true.
- False means conflict; never silently retry against a newer expected record.
- Preserve signing/uncertain records and monotonic revisions across crashes.
  No lease expiry, deletion, lock stealing or resetting an active record is permitted.
- Bound storage operations in the adapter and consume late failures. If a deadline
  wins while a storage write is pending, it may still commit later; retain the same
  known reservation ID and inspect storage. Do not infer rollback from cancellation.

The SDK validates version, key, snapshot bounds, state, revision, canonical bytes
and transaction ID on reads/writes and sanitizes adapter errors. This validation
cannot replace the adapter's atomicity, durability or resistance to malicious
storage. An external adapter and authority/sign/client callbacks are application
trust boundaries. Do not mix independently initialized memory adapters for the
same account and then claim cross-tab serialization.

## Recovery and reset rules

`inspect(key)` returns a frozen public record. Low-level inspect/release/retirement
storage calls use the adapter's own completion bounds; `execute` and `reconcile`
add an overall SDK deadline. Preserve the app's key/reservation ID before invoking
callbacks, so timeout/crash does not lose ownership references.

`releaseUnsigned(key, reservationId)` allows only a matching `reserved` record;
`signing`, `signed`, `uncertain` and `consumed` cannot be released. The released
record remains persisted. No active-record deletion API exists.

`reconcile(key, reservationId, client, options)` recovers persisted signed/uncertain
bytes with reads only; it invokes neither signer nor submit. The stored ID is
checked and successful/failed finalized inclusion marks consumption. Unknown
remains held; missing/pruned history does not establish non-inclusion. The same
owner ID and whole-record compare/exchange prevent a stale recovery from
rewriting another flow's reservation. Overall budget includes the storage reads
and consumption write, even when callbacks ignore cancellation.

`retireObsolete(key, reservationId, freshSnapshot)` is an explicit recovery action
for held signing/signed/uncertain records. It requires a consistent fresh snapshot
showing strict nonce advancement in the same exact authority domain, or a strictly
newer ROOT epoch. These conditions make the older signature inadmissible; they
never identify which transaction consumed the nonce or prove this ID was absent.
The record becomes `obsolete`, retaining original bytes/snapshot and retirement
observation. Future flows cannot reuse the old nonce or regress behind that newer
observation. The method never sends, signs or automatically retires on timeout.

Transaction V2 has no DIRECT/ROOT intent expiry. A crash during signing with no
stored ID, unchanged nonce and unchanged ROOT epoch cannot safely reset this slot.
Retain evidence and resolve authority externally; an elapsed wall-clock lease is
insufficient. SESSION validity/revocation may provide additional application
recovery evidence, but this API does not infer it from a missing lookup.

These guarantees cover cooperating clients using one correct adapter. Another
wallet, process or signer that bypasses coordination can consume/revoke authority;
fresh state checks and final reconciliation detect observations, but cannot stop
external actors or make a signature atomic with chain execution.

External adapter/callback failures are reconstructed with bounded supported codes
and fixed messages. Modified SDK error instances, invalid codes, throwing code
getters and prototype traps do not forward caller messages, causes or objects.
Constructor inspection failures produce `INVALID_ARGUMENT`. This normalization
does not release signing/signed/uncertain reservations or imply safe resubmission.
