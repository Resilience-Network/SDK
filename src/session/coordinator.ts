import {
  bytesToHex,
  checkedUint,
  fixedBytes,
  hexToBytes,
  isZero,
  objectFields,
} from "../core/bytes.js";
import { chainDomain, transactionId } from "./hash.js";
import { transactionCodec, txIntentCodec } from "./transaction.js";
import type { ChainContext, Scheme, Transaction, TxIntent } from "./types.js";
import type { ChainRpcClient } from "../rpc/methods.js";
import type {
  ReconcileOptions,
  ReconciliationOutcome,
  SubmissionOutcome,
} from "../rpc/submission.js";
import { Deadline, systemClock } from "../rpc/deadline.js";
import { RpcClientError } from "../rpc/errors.js";

export type CoordinatorErrorCode =
  | "INVALID_ARGUMENT"
  | "INVALID_STORE"
  | "CONFLICT"
  | "STALE_AUTHORITY"
  | "MUTATED_INPUT"
  | "ADAPTER_FAILED"
  | "FLOW_FAILED"
  | "ABORTED"
  | "TIMEOUT";
/** Public reservation references only; never callback exceptions, bytes, keys or causes. */
export class CoordinatorError extends Error {
  override readonly name = "CoordinatorError";
  constructor(readonly code: CoordinatorErrorCode) {
    super(`Nonce coordination failed: ${code}`);
  }
}
/** Obtain from validated, consistent, trusted-node reads; this is not a proof. */
export interface NonceAuthoritySnapshot {
  readonly context: ChainContext;
  readonly owner: Uint8Array;
  readonly mode: 0 | 1 | 2;
  readonly keyScheme: Scheme;
  readonly credentialId: Uint8Array;
  readonly authEpoch: bigint;
  readonly policyHash: Uint8Array;
  readonly nonce: bigint;
  /** App-derived hash of the exact canonical authority/usage state being authorized. */
  readonly authorityHash: Uint8Array;
  readonly height: bigint;
  readonly blockHash: Uint8Array;
  readonly stateRoot: Uint8Array;
}
/** All nested values are immutable strings/numbers; safe to persist as JSON. */
export interface FrozenNonceSnapshot {
  readonly chainId: string;
  readonly genesisHash: string;
  readonly owner: string;
  readonly mode: 0 | 1 | 2;
  readonly keyScheme: Scheme;
  readonly credentialId: string;
  readonly authEpoch: string;
  readonly policyHash: string;
  readonly nonce: string;
  readonly authorityHash: string;
  readonly height: string;
  readonly blockHash: string;
  readonly stateRoot: string;
}
export interface NonceReservationRecord {
  readonly version: 1;
  readonly key: string;
  readonly revision: number;
  readonly reservationId: string;
  readonly state:
    | "reserved"
    | "signing"
    | "signed"
    | "uncertain"
    | "consumed"
    | "released"
    | "obsolete";
  readonly snapshot: FrozenNonceSnapshot;
  readonly canonicalTransaction: string | null;
  readonly transactionHash: string | null;
  readonly retirement: FrozenNonceSnapshot | null;
}
export interface NonceReservationStore {
  read(key: string): Promise<NonceReservationRecord | null>;
  /** Atomic full-record comparison and durable replacement BEFORE resolving true.
   * No expiry, deletion, lease stealing or retrying the update with a new expected value.
   * Reads must be linearizable. Preserve records across tab/process/crash boundaries.
   */
  compareExchange(
    key: string,
    expected: NonceReservationRecord | null,
    replacement: NonceReservationRecord,
  ): Promise<boolean>;
}
function requireValid(
  ok: unknown,
  code: CoordinatorErrorCode = "INVALID_ARGUMENT",
): asserts ok {
  if (!ok) throw new CoordinatorError(code);
}
function reconciliationConfig(options: Omit<ReconcileOptions, "signal">): string {
  try {
    objectFields(options, ["timeoutMs", "maxPolls", "pollIntervalMs"]);
    for (const [name, maximum] of [
      ["timeoutMs", 300000],
      ["maxPolls", 1000],
      ["pollIntervalMs", 60000],
    ] as const) {
      const value = options[name];
      if (value !== undefined)
        requireValid(Number.isSafeInteger(value) && value >= 1 && value <= maximum);
    }
    return JSON.stringify(options);
  } catch {
    throw new CoordinatorError("INVALID_ARGUMENT");
  }
}
function normalize(s: NonceAuthoritySnapshot): FrozenNonceSnapshot {
  try {
    objectFields(s, [
      "context",
      "owner",
      "mode",
      "keyScheme",
      "credentialId",
      "authEpoch",
      "policyHash",
      "nonce",
      "authorityHash",
      "height",
      "blockHash",
      "stateRoot",
    ]);
    objectFields(s.context, ["chainId", "genesisHash"]);
    for (const n of [s.context.chainId, s.authEpoch, s.nonce, s.height])
      checkedUint(n, 64);
    fixedBytes(s.owner, 20);
    for (const b of [
      s.context.genesisHash,
      s.credentialId,
      s.policyHash,
      s.authorityHash,
      s.blockHash,
      s.stateRoot,
    ])
      fixedBytes(b, 32);
    requireValid([0, 1, 2].includes(s.mode) && [1, 2].includes(s.keyScheme));
    requireValid(!isZero(s.owner) && !isZero(s.authorityHash));
    requireValid(
      s.mode === 2
        ? s.authEpoch > 0n && !isZero(s.credentialId) && !isZero(s.policyHash)
        : s.keyScheme === 1 &&
            isZero(s.policyHash) &&
            (s.mode === 0
              ? s.authEpoch === 0n && isZero(s.credentialId)
              : s.authEpoch > 0n && !isZero(s.credentialId)),
    );
    return Object.freeze({
      chainId: s.context.chainId.toString(),
      genesisHash: bytesToHex(s.context.genesisHash),
      owner: bytesToHex(s.owner),
      mode: s.mode,
      keyScheme: s.keyScheme,
      credentialId: bytesToHex(s.credentialId),
      authEpoch: s.authEpoch.toString(),
      policyHash: bytesToHex(s.policyHash),
      nonce: s.nonce.toString(),
      authorityHash: bytesToHex(s.authorityHash),
      height: s.height.toString(),
      blockHash: bytesToHex(s.blockHash),
      stateRoot: bytesToHex(s.stateRoot),
    });
  } catch (e) {
    if (e instanceof CoordinatorError) throw e;
    throw new CoordinatorError("INVALID_ARGUMENT");
  }
}
function context(s: FrozenNonceSnapshot): ChainContext {
  return { chainId: BigInt(s.chainId), genesisHash: hexToBytes(s.genesisHash, 32) };
}
function snapshotFromStored(s: FrozenNonceSnapshot): FrozenNonceSnapshot {
  try {
    objectFields(s, [
      "chainId",
      "genesisHash",
      "owner",
      "mode",
      "keyScheme",
      "credentialId",
      "authEpoch",
      "policyHash",
      "nonce",
      "authorityHash",
      "height",
      "blockHash",
      "stateRoot",
    ]);
    for (const k of ["chainId", "authEpoch", "nonce", "height"] as const)
      requireValid(
        typeof s[k] === "string" && s[k].length <= 20 && /^(0|[1-9][0-9]*)$/.test(s[k]),
        "INVALID_STORE",
      );
    const result = normalize({
      context: context(s),
      owner: hexToBytes(s.owner, 20),
      mode: s.mode,
      keyScheme: s.keyScheme,
      credentialId: hexToBytes(s.credentialId, 32),
      authEpoch: BigInt(s.authEpoch),
      policyHash: hexToBytes(s.policyHash, 32),
      nonce: BigInt(s.nonce),
      authorityHash: hexToBytes(s.authorityHash, 32),
      height: BigInt(s.height),
      blockHash: hexToBytes(s.blockHash, 32),
      stateRoot: hexToBytes(s.stateRoot, 32),
    });
    requireValid(
      Object.entries(result).every(
        ([field, value]) => s[field as keyof FrozenNonceSnapshot] === value,
      ),
      "INVALID_STORE",
    );
    return result;
  } catch {
    throw new CoordinatorError("INVALID_STORE");
  }
}
function key(s: FrozenNonceSnapshot): string {
  // Epoch/config deliberately excluded: an uncertain older domain still holds this authority.
  return `resilience-sdk-nonce-v1:${bytesToHex(chainDomain(context(s)))}:${s.owner}:${s.mode}${s.mode === 2 ? `:${s.credentialId}` : ""}`;
}
export function nonceAuthorityKey(snapshot: NonceAuthoritySnapshot): string {
  return key(normalize(snapshot));
}
function id(value: string): void {
  requireValid(typeof value === "string" && /^[a-zA-Z0-9_-]{16,80}$/.test(value));
}
function validateRecord(
  r: NonceReservationRecord | null,
  expectedKey: string,
): NonceReservationRecord | null {
  if (r === null) return null;
  try {
    objectFields(r, [
      "version",
      "key",
      "revision",
      "reservationId",
      "state",
      "snapshot",
      "canonicalTransaction",
      "transactionHash",
      "retirement",
    ]);
    const s = snapshotFromStored(r.snapshot);
    id(r.reservationId);
    requireValid(
      r.version === 1 &&
        r.key === expectedKey &&
        key(s) === expectedKey &&
        Number.isSafeInteger(r.revision) &&
        r.revision >= 1 &&
        r.revision < Number.MAX_SAFE_INTEGER &&
        [
          "reserved",
          "signing",
          "signed",
          "uncertain",
          "consumed",
          "released",
          "obsolete",
        ].includes(r.state),
      "INVALID_STORE",
    );
    let retirement: FrozenNonceSnapshot | null = null;
    if (r.state === "obsolete") {
      retirement = snapshotFromStored(r.retirement!);
      obsolete(s, retirement);
    } else requireValid(r.retirement === null, "INVALID_STORE");
    if (
      ["reserved", "signing", "released"].includes(r.state) ||
      (r.state === "obsolete" && r.canonicalTransaction === null)
    )
      requireValid(
        r.canonicalTransaction === null && r.transactionHash === null,
        "INVALID_STORE",
      );
    else {
      requireValid(
        typeof r.canonicalTransaction === "string" &&
          typeof r.transactionHash === "string",
        "INVALID_STORE",
      );
      const tx = transactionCodec.decode(hexToBytes(r.canonicalTransaction!));
      bindTransaction(tx, s);
      requireValid(
        bytesToHex(transactionCodec.encode(tx)) === r.canonicalTransaction &&
          bytesToHex(transactionId(context(s), tx.intent, tx.envelope)) ===
            r.transactionHash,
        "INVALID_STORE",
      );
    }
    return Object.freeze({ ...r, snapshot: s, retirement });
  } catch {
    throw new CoordinatorError("INVALID_STORE");
  }
}
function bindTransaction(tx: Transaction, s: FrozenNonceSnapshot): void {
  const e = tx.envelope;
  requireValid(
    bytesToHex(tx.intent.sender) === s.owner &&
      isZero(tx.intent.sponsor) &&
      e.mode === s.mode &&
      e.keyScheme === s.keyScheme &&
      bytesToHex(e.credentialId) === s.credentialId &&
      e.authEpoch.toString() === s.authEpoch &&
      bytesToHex(e.policyHash) === s.policyHash &&
      e.nonce.toString() === s.nonce,
    "STALE_AUTHORITY",
  );
  // Canonical encode also checks chain ID; transactionId checks genesis/context.
  transactionId(context(s), tx.intent, tx.envelope);
}
function obsolete(old: FrozenNonceSnapshot, next: FrozenNonceSnapshot): void {
  requireValid(
    key(old) === key(next) &&
      BigInt(next.height) >= BigInt(old.height) &&
      (next.height !== old.height ||
        (next.blockHash === old.blockHash && next.stateRoot === old.stateRoot)),
    "STALE_AUTHORITY",
  );
  requireValid(
    old.authEpoch === next.authEpoch
      ? old.credentialId === next.credentialId &&
          old.policyHash === next.policyHash &&
          old.keyScheme === next.keyScheme &&
          BigInt(next.nonce) > BigInt(old.nonce)
      : old.mode === 1 && BigInt(next.authEpoch) > BigInt(old.authEpoch),
    "STALE_AUTHORITY",
  );
}
function stable(old: FrozenNonceSnapshot, next: FrozenNonceSnapshot): void {
  const { height: _h, blockHash: _b, stateRoot: _r, ...a } = old;
  const { height: _hh, blockHash: _bb, stateRoot: _rr, ...b } = next;
  requireValid(
    JSON.stringify(a) === JSON.stringify(b) &&
      BigInt(next.height) >= BigInt(old.height) &&
      (next.height !== old.height ||
        (next.blockHash === old.blockHash && next.stateRoot === old.stateRoot)),
    "STALE_AUTHORITY",
  );
}
/** Atomic only within this adapter instance/process. No cross-tab/crash guarantee. */
export class MemoryNonceReservationStore implements NonceReservationStore {
  readonly #records = new Map<string, NonceReservationRecord>();
  constructor(readonly maximumAuthorities = 1024) {
    requireValid(
      Number.isSafeInteger(maximumAuthorities) &&
        maximumAuthorities >= 1 &&
        maximumAuthorities <= 10000,
    );
  }
  async read(k: string): Promise<NonceReservationRecord | null> {
    return this.#records.get(k) ?? null;
  }
  async compareExchange(
    k: string,
    expected: NonceReservationRecord | null,
    replacement: NonceReservationRecord,
  ): Promise<boolean> {
    const current = this.#records.get(k) ?? null;
    if (JSON.stringify(current) !== JSON.stringify(expected)) return false;
    requireValid(
      this.#records.has(k) || this.#records.size < this.maximumAuthorities,
      "CONFLICT",
    );
    this.#records.set(k, validateRecord(replacement, k)!);
    return true;
  }
}
export interface CoordinatedSigningRequest {
  readonly snapshot: FrozenNonceSnapshot;
  readonly intentCanonical: string;
  readonly signal: AbortSignal;
}
export interface CoordinatedTransactionOptions {
  readonly context: ChainContext;
  readonly intent: TxIntent;
  /** Unique per flow and persisted by the app before starting. Never reuse. */
  readonly reservationId: string;
  readonly readAuthority: (signal: AbortSignal) => Promise<NonceAuthoritySnapshot>;
  readonly sign: (request: CoordinatedSigningRequest) => Promise<Transaction>;
  readonly client: Pick<ChainRpcClient, "submitTransaction" | "reconcileTransaction">;
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
  readonly reconciliation?: Omit<ReconcileOptions, "signal">;
}
export interface CoordinatedTransactionOutcome {
  readonly reservation: NonceReservationRecord;
  readonly submission: SubmissionOutcome;
  readonly reconciliation: ReconciliationOutcome;
}
/** Rejects contention rather than choosing the next nonce or signing a replacement. */
export class NonceCoordinator {
  constructor(readonly store: NonceReservationStore) {
    requireValid(
      store !== null &&
        typeof store.read === "function" &&
        typeof store.compareExchange === "function",
    );
  }
  async #read(k: string): Promise<NonceReservationRecord | null> {
    try {
      return validateRecord(await this.store.read(k), k);
    } catch (e) {
      if (e instanceof CoordinatorError) throw e;
      throw new CoordinatorError("ADAPTER_FAILED");
    }
  }
  async #write(
    old: NonceReservationRecord | null,
    next: NonceReservationRecord,
  ): Promise<NonceReservationRecord> {
    const value = validateRecord(next, next.key)!;
    try {
      requireValid(await this.store.compareExchange(next.key, old, value), "CONFLICT");
    } catch (e) {
      if (e instanceof CoordinatorError) throw e;
      throw new CoordinatorError("ADAPTER_FAILED");
    }
    return value;
  }
  async inspect(authorityKey: string): Promise<NonceReservationRecord | null> {
    requireValid(
      typeof authorityKey === "string" &&
        authorityKey.length <= 256 &&
        authorityKey.startsWith("resilience-sdk-nonce-v1:"),
    );
    return this.#read(authorityKey);
  }
  /** Only an unsigned reservation may be released; never signing/signed/uncertain. */
  async releaseUnsigned(authorityKey: string, reservationId: string): Promise<void> {
    id(reservationId);
    const current = await this.inspect(authorityKey);
    requireValid(
      current?.reservationId === reservationId && current.state === "reserved",
      "CONFLICT",
    );
    await this.#write(current, {
      ...current,
      revision: current.revision + 1,
      state: "released",
    });
  }
  /** Explicit recovery only when older signatures are no longer admissible.
   * Does not prove this transaction was included or clear retained evidence.
   */
  async retireObsolete(
    authorityKey: string,
    reservationId: string,
    observation: NonceAuthoritySnapshot,
  ): Promise<NonceReservationRecord> {
    id(reservationId);
    const snapshot = normalize(observation);
    const unchanged = () => {
      try {
        requireValid(
          JSON.stringify(normalize(observation)) === JSON.stringify(snapshot),
          "MUTATED_INPUT",
        );
      } catch {
        throw new CoordinatorError("MUTATED_INPUT");
      }
    };
    requireValid(key(snapshot) === authorityKey, "STALE_AUTHORITY");
    const record = await this.inspect(authorityKey);
    unchanged();
    requireValid(
      record?.reservationId === reservationId &&
        ["signing", "signed", "uncertain"].includes(record.state),
      "CONFLICT",
    );
    obsolete(record.snapshot, snapshot);
    const retired = await this.#write(record, {
      ...record,
      revision: record.revision + 1,
      state: "obsolete",
      retirement: snapshot,
    });
    unchanged();
    return retired;
  }
  async #reserve(
    s: FrozenNonceSnapshot,
    reservationId: string,
  ): Promise<NonceReservationRecord> {
    const k = key(s),
      current = await this.#read(k);
    if (current) {
      requireValid(
        current.reservationId !== reservationId &&
          ["released", "consumed", "obsolete"].includes(current.state),
        "CONFLICT",
      );
      const old = current.retirement ?? current.snapshot;
      requireValid(
        BigInt(s.height) >= BigInt(old.height) &&
          (s.height !== old.height ||
            (s.blockHash === old.blockHash && s.stateRoot === old.stateRoot)),
        "STALE_AUTHORITY",
      );
      const sameEpoch = s.authEpoch === old.authEpoch;
      if (sameEpoch)
        requireValid(
          s.keyScheme === old.keyScheme &&
            s.credentialId === old.credentialId &&
            s.policyHash === old.policyHash,
          "STALE_AUTHORITY",
        );
      requireValid(
        sameEpoch
          ? BigInt(s.nonce) >=
              BigInt(old.nonce) + (current.state === "consumed" ? 1n : 0n)
          : s.mode === 1 && BigInt(s.authEpoch) > BigInt(old.authEpoch),
        "STALE_AUTHORITY",
      );
    }
    return this.#write(current, {
      version: 1,
      key: k,
      revision: (current?.revision ?? 0) + 1,
      reservationId,
      state: "reserved",
      snapshot: s,
      canonicalTransaction: null,
      transactionHash: null,
      retirement: null,
    });
  }
  async #settle(
    record: NonceReservationRecord,
    result: ReconciliationOutcome,
  ): Promise<NonceReservationRecord> {
    requireValid(
      bytesToHex(result.transactionHash) === record.transactionHash &&
        result.verification === "node-observation",
      "STALE_AUTHORITY",
    );
    if (result.status === "unknown") return record;
    requireValid(
      ["reported-finalized-success", "reported-finalized-failure"].includes(
        result.status,
      ) &&
        bytesToHex(result.receipt.transactionHash) === record.transactionHash &&
        result.receipt.counterDelta.nonceDelta === 1,
      "STALE_AUTHORITY",
    );
    return this.#write(record, {
      ...record,
      revision: record.revision + 1,
      state: "consumed",
    });
  }
  async execute(
    options: CoordinatedTransactionOptions,
  ): Promise<CoordinatedTransactionOutcome> {
    let intentBytes: string, expectedContext: string;
    try {
      objectFields(options, [
        "context",
        "intent",
        "reservationId",
        "readAuthority",
        "sign",
        "client",
        "signal",
        "timeoutMs",
        "reconciliation",
      ]);
      id(options.reservationId);
      intentBytes = bytesToHex(txIntentCodec.encode(options.intent));
      expectedContext = bytesToHex(chainDomain(options.context));
      requireValid(
        typeof options.readAuthority === "function" &&
          typeof options.sign === "function" &&
          typeof options.client?.submitTransaction === "function" &&
          typeof options.client?.reconcileTransaction === "function",
      );
      requireValid(
        isZero(options.intent.sponsor) &&
          options.intent.chainId === options.context.chainId,
      );
      objectFields(options.context, ["chainId", "genesisHash"]);
    } catch {
      throw new CoordinatorError("INVALID_ARGUMENT");
    }
    const timeout = options.timeoutMs ?? 30000;
    requireValid(Number.isSafeInteger(timeout) && timeout >= 1 && timeout <= 300000);
    const read = options.readAuthority,
      sign = options.sign,
      client = options.client,
      submit = client.submitTransaction,
      reconcile = client.reconcileTransaction,
      reservationId = options.reservationId,
      reconciliation = reconciliationConfig(options.reconciliation ?? {}),
      signal = options.signal;
    const guard = () => {
      try {
        requireValid(
          bytesToHex(txIntentCodec.encode(options.intent)) === intentBytes &&
            bytesToHex(chainDomain(options.context)) === expectedContext &&
            options.reservationId === reservationId &&
            options.readAuthority === read &&
            options.sign === sign &&
            options.client === client &&
            client.submitTransaction === submit &&
            client.reconcileTransaction === reconcile &&
            JSON.stringify(options.reconciliation ?? {}) === reconciliation &&
            options.signal === signal &&
            (options.timeoutMs ?? 30000) === timeout,
          "MUTATED_INPUT",
        );
      } catch {
        throw new CoordinatorError("MUTATED_INPUT");
      }
    };
    const deadline = new Deadline(systemClock, timeout, signal);
    const mutationGuards: (() => void)[] = [];
    const checkMutations = () => {
      guard();
      for (const check of mutationGuards) {
        try {
          check();
        } catch {
          throw new CoordinatorError("MUTATED_INPUT");
        }
      }
    };
    const awaitStep = async <T>(pending: Promise<T>): Promise<T> => {
      let value: T;
      try {
        value = await deadline.race(pending);
      } catch (error) {
        checkMutations();
        throw error;
      }
      deadline.check();
      checkMutations();
      return value;
    };
    let snapshot: FrozenNonceSnapshot, record: NonceReservationRecord;
    let original: NonceAuthoritySnapshot;
    const observedGuard = () => {
      requireValid(
        JSON.stringify(normalize(original)) === JSON.stringify(snapshot),
        "MUTATED_INPUT",
      );
    };
    try {
      deadline.check();
      guard();
      original = await awaitStep(read(deadline.controller.signal));
      snapshot = normalize(original);
      mutationGuards.push(observedGuard);
      requireValid(
        bytesToHex(chainDomain(context(snapshot))) === expectedContext &&
          snapshot.owner === bytesToHex(options.intent.sender),
        "STALE_AUTHORITY",
      );
      record = await awaitStep(this.#reserve(snapshot, reservationId));
      observedGuard();
      const beforeSigning = await awaitStep(read(deadline.controller.signal));
      const beforeFrozen = normalize(beforeSigning);
      stable(snapshot, beforeFrozen);
      mutationGuards.push(() =>
        requireValid(
          JSON.stringify(normalize(beforeSigning)) === JSON.stringify(beforeFrozen),
          "MUTATED_INPUT",
        ),
      );
      // Durable signing state BEFORE invoking a callback that could export usable signatures.
      record = await awaitStep(
        this.#write(record, {
          ...record,
          revision: record.revision + 1,
          state: "signing",
        }),
      );
      observedGuard();
      const request = Object.freeze({
        snapshot,
        intentCanonical: intentBytes,
        signal: deadline.controller.signal,
      });
      const signed = await awaitStep(sign(request));
      observedGuard();
      const bytes = transactionCodec.encode(signed),
        tx = transactionCodec.decode(bytes);
      const signedCanonical = bytesToHex(bytes);
      mutationGuards.push(() =>
        requireValid(
          bytesToHex(transactionCodec.encode(signed)) === signedCanonical,
          "MUTATED_INPUT",
        ),
      );
      bindTransaction(tx, snapshot);
      requireValid(
        bytesToHex(txIntentCodec.encode(tx.intent)) === intentBytes,
        "MUTATED_INPUT",
      );
      const transactionHash = bytesToHex(
        transactionId(context(snapshot), tx.intent, tx.envelope),
      );
      record = await awaitStep(
        this.#write(record, {
          ...record,
          revision: record.revision + 1,
          state: "signed",
          canonicalTransaction: bytesToHex(bytes),
          transactionHash,
        }),
      );
      observedGuard();
      // Freeze and recheck the same authority; do not silently refresh a reviewed nonce/epoch/policy.
      const next = await awaitStep(read(deadline.controller.signal));
      observedGuard();
      const nextFrozen = normalize(next);
      stable(snapshot, nextFrozen);
      mutationGuards.push(() =>
        requireValid(
          JSON.stringify(normalize(next)) === JSON.stringify(nextFrozen),
          "MUTATED_INPUT",
        ),
      );
      requireValid(
        bytesToHex(transactionCodec.encode(signed)) === record.canonicalTransaction,
        "MUTATED_INPUT",
      );
      record = await awaitStep(
        this.#write(record, {
          ...record,
          revision: record.revision + 1,
          state: "uncertain",
        }),
      );
      observedGuard();
      const submission = await awaitStep(
        submit.call(client, new Uint8Array(bytes), {
          signal: deadline.controller.signal,
        }),
      );
      observedGuard();
      requireValid(
        bytesToHex(submission.transactionHash) === transactionHash &&
          submission.verification === "node-observation",
        "STALE_AUTHORITY",
      );
      const result = await awaitStep(
        reconcile.call(client, new Uint8Array(bytes), {
          ...JSON.parse(reconciliation),
          signal: deadline.controller.signal,
        }),
      );
      observedGuard();
      record = await awaitStep(this.#settle(record, result));
      observedGuard();
      return { reservation: record, submission, reconciliation: result };
    } catch (e) {
      checkMutations();
      if (e instanceof CoordinatorError) throw e;
      if (e instanceof RpcClientError && ["ABORTED", "TIMEOUT"].includes(e.code))
        throw new CoordinatorError(e.code as "ABORTED" | "TIMEOUT");
      throw new CoordinatorError("FLOW_FAILED");
    } finally {
      deadline.dispose();
    }
  }
  /** Explicit read-only recovery using persisted bytes; never calls sign or submit. */
  async reconcile(
    authorityKey: string,
    reservationId: string,
    client: Pick<ChainRpcClient, "reconcileTransaction">,
    options: ReconcileOptions = {},
  ): Promise<{
    readonly reservation: NonceReservationRecord;
    readonly reconciliation: ReconciliationOutcome;
  }> {
    id(reservationId);
    const timeout = options.timeoutMs ?? 30000;
    requireValid(Number.isSafeInteger(timeout) && timeout >= 1 && timeout <= 300000);
    requireValid(typeof client?.reconcileTransaction === "function");
    const method = client.reconcileTransaction,
      signal = options.signal;
    const { signal: _signal, ...rest } = options;
    let config: string;
    try {
      config = reconciliationConfig(rest);
    } catch {
      throw new CoordinatorError("INVALID_ARGUMENT");
    }
    const unchanged = () => {
      const { signal: _current, ...current } = options;
      requireValid(
        options.signal === signal &&
          client.reconcileTransaction === method &&
          JSON.stringify(current) === config,
        "MUTATED_INPUT",
      );
    };
    const deadline = new Deadline(systemClock, timeout, signal);
    try {
      deadline.check();
      const record = await deadline.race(this.inspect(authorityKey));
      deadline.check();
      unchanged();
      requireValid(
        record?.reservationId === reservationId &&
          ["signed", "uncertain", "consumed"].includes(record.state),
        "CONFLICT",
      );
      const result = await deadline.race(
        method.call(client, hexToBytes(record.canonicalTransaction!), {
          ...JSON.parse(config),
          signal: deadline.controller.signal,
        }),
      );
      deadline.check();
      unchanged();
      requireValid(
        bytesToHex(result.transactionHash) === record.transactionHash &&
          result.verification === "node-observation",
        "STALE_AUTHORITY",
      );
      const settled =
        record.state === "consumed"
          ? record
          : await deadline.race(this.#settle(record, result));
      deadline.check();
      unchanged();
      return { reservation: settled, reconciliation: result };
    } catch (error) {
      unchanged();
      if (error instanceof CoordinatorError) throw error;
      if (
        error instanceof RpcClientError &&
        ["ABORTED", "TIMEOUT"].includes(error.code)
      )
        throw new CoordinatorError(error.code as "ABORTED" | "TIMEOUT");
      throw new CoordinatorError("FLOW_FAILED");
    } finally {
      deadline.dispose();
    }
  }
}
