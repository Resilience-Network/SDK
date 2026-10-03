import { checkedUint, isZero } from "../core/bytes.js";
import {
  authorizationEventCodec,
  authorizationEventsRoot,
  receiptCounterDeltaHash,
  transactionCodec,
  transactionId,
} from "../session/index.js";
import type {
  AuthorizationEvent,
  ChainContext,
  ReceiptCounterDelta,
  Transaction,
} from "../session/index.js";
import type { AuthorizationFinalityStatus } from "./contracts.js";
import type { RpcRequestOptions } from "./types.js";
import {
  amount,
  array,
  boolean,
  quantity,
  record,
  requireResult,
  sameBytes,
  wireBytes,
} from "./validate.js";

export interface TransactionLocation {
  blockHash: Uint8Array;
  blockNumber: bigint;
  transactionIndex: bigint;
}
export interface TransactionProjection {
  hash: Uint8Array;
  nonce: bigint;
  location: TransactionLocation | null;
  from: Uint8Array;
  to: Uint8Array | null;
  value: bigint;
  gasPrice: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  gas: bigint;
  input: Uint8Array;
  actionType: number;
  chainId: bigint;
  sponsor: Uint8Array | null;
  sponsorNonce: bigint | null;
}
export interface ReceiptLog {
  address: Uint8Array;
  topics: readonly Uint8Array[];
  data: Uint8Array;
  logIndex: bigint;
}
export interface TransactionReceipt extends TransactionLocation {
  transactionHash: Uint8Array;
  from: Uint8Array;
  to: Uint8Array | null;
  cumulativeGasUsed: bigint;
  gasUsed: bigint;
  contractAddress: Uint8Array | null;
  logs: readonly ReceiptLog[];
  logsBloom: Uint8Array;
  actionStatus: 0 | 1;
  failureCode: number;
  authorizationMode: 0 | 1 | 2;
  credentialId: Uint8Array;
  authorizationEpoch: bigint;
  authorizationNonce: bigint;
  policyHash: Uint8Array;
  sponsor: Uint8Array | null;
  authorizationGasUsed: bigint;
  actualFee: bigint;
  burnedFee: bigint;
  effectiveGasPrice: bigint;
  counterDeltaHash: Uint8Array;
  counterDelta: ReceiptCounterDelta;
  eventsRoot: Uint8Array;
  authorizationEvents: readonly AuthorizationEvent[];
}
export interface LookupOptions extends RpcRequestOptions {
  /** Optional locally signed canonical Transaction V2. Copied before dispatch. */ canonicalTransaction?: Uint8Array;
}
export type TransactionObservation =
  | {
      identity: AuthorizationFinalityStatus;
      transactionHash: Uint8Array;
      verification: "node-observation";
      status: "unknown";
      transaction: null;
    }
  | {
      identity: AuthorizationFinalityStatus;
      transactionHash: Uint8Array;
      verification: "node-observation";
      status: "reported-pending" | "reported-included";
      transaction: TransactionProjection;
    };
export type ReceiptObservation =
  | {
      identity: AuthorizationFinalityStatus;
      transactionHash: Uint8Array;
      verification: "node-observation";
      status: "unknown";
      receipt: null;
      transaction: TransactionProjection | null;
    }
  | {
      identity: AuthorizationFinalityStatus;
      transactionHash: Uint8Array;
      verification: "node-observation";
      status: "reported-included";
      receipt: TransactionReceipt;
      transaction: TransactionProjection;
    };

const addr = (v: unknown) => {
  const b = wireBytes(v, 20, 20);
  requireResult(!isZero(b));
  return b;
};
const nullableAddress = (v: unknown) => (v === null ? null : addr(v));
function shape(
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = [],
): Record<string, unknown> {
  requireResult(value !== null && typeof value === "object" && !Array.isArray(value));
  const r = value as Record<string, unknown>;
  requireResult(
    required.every((f) => Object.hasOwn(r, f)) &&
      Object.keys(r).every((f) => required.includes(f) || optional.includes(f)),
  );
  return r;
}
function boundedQuantity(v: unknown, bits: 8 | 16 | 32): bigint {
  const n = quantity(v);
  checkedUint(n, bits);
  return n;
}
function location(
  r: Record<string, unknown>,
  identity: AuthorizationFinalityStatus,
  checkObservedHead: boolean,
): TransactionLocation | null {
  const pending = r.blockHash === null;
  requireResult(
    (r.blockNumber === null) === pending && (r.transactionIndex === null) === pending,
  );
  if (pending) return null;
  const blockHash = wireBytes(r.blockHash, 32, 32),
    blockNumber = quantity(r.blockNumber),
    transactionIndex = boundedQuantity(r.transactionIndex, 32);
  requireResult(!isZero(blockHash));
  if (checkObservedHead) requireResult(blockNumber <= identity.state.height);
  if (checkObservedHead && blockNumber === identity.state.height)
    sameBytes(blockHash, identity.state.blockHash);
  return { blockHash, blockNumber, transactionIndex };
}
function sameNullable(a: Uint8Array | null, b: Uint8Array | null): void {
  requireResult((a === null) === (b === null));
  if (a && b) sameBytes(a, b);
}
export function transactionProjection(
  value: unknown,
  id: Uint8Array,
  identity: AuthorizationFinalityStatus,
  canonical?: Transaction,
  checkObservedHead = true,
): TransactionProjection | null {
  if (value === null) return null;
  const r = shape(
    value,
    [
      "hash",
      "nonce",
      "blockHash",
      "blockNumber",
      "transactionIndex",
      "from",
      "to",
      "value",
      "gasPrice",
      "maxFeePerGas",
      "maxPriorityFeePerGas",
      "gas",
      "input",
      "type",
      "chainId",
    ],
    ["sponsor", "sponsorNonce"],
  );
  const p: TransactionProjection = {
    hash: wireBytes(r.hash, 32, 32),
    nonce: quantity(r.nonce),
    location: location(r, identity, checkObservedHead),
    from: addr(r.from),
    to: nullableAddress(r.to),
    value: quantity(r.value, 256),
    gasPrice: quantity(r.gasPrice, 256),
    maxFeePerGas: quantity(r.maxFeePerGas, 256),
    maxPriorityFeePerGas: quantity(r.maxPriorityFeePerGas, 256),
    gas: quantity(r.gas),
    input: wireBytes(r.input, 65536),
    actionType: Number(boundedQuantity(r.type, 8)),
    chainId: quantity(r.chainId),
    sponsor: null,
    sponsorNonce: null,
  };
  sameBytes(p.hash, id);
  requireResult(
    p.chainId === identity.chainId &&
      p.maxPriorityFeePerGas <= p.maxFeePerGas &&
      p.gasPrice <= p.maxFeePerGas,
  );
  requireResult(p.actionType <= 0x11 || (p.actionType >= 0x80 && p.actionType <= 0x88));
  requireResult(Object.hasOwn(r, "sponsor") === Object.hasOwn(r, "sponsorNonce"));
  if (Object.hasOwn(r, "sponsor")) {
    p.sponsor = addr(r.sponsor);
    p.sponsorNonce = quantity(r.sponsorNonce);
    requireResult(!p.sponsor.every((b, i) => b === p.from[i]));
  }
  if (canonical) {
    const { intent: i, envelope: e } = canonical;
    sameBytes(p.from, i.sender);
    sameNullable(p.to, isZero(i.destination) ? null : i.destination);
    sameBytes(p.input, i.data);
    requireResult(
      p.nonce === e.nonce &&
        p.value === i.value &&
        p.gas === i.gasLimit &&
        p.maxFeePerGas === i.maxFeePerGas &&
        p.maxPriorityFeePerGas === i.maxPriorityFeePerGas &&
        p.actionType === i.actionType,
    );
    sameNullable(p.sponsor, isZero(i.sponsor) ? null : i.sponsor);
    requireResult(p.sponsorNonce === (isZero(i.sponsor) ? null : e.sponsorNonce));
  }
  return p;
}
export function canonicalLookup(
  bytes: Uint8Array | undefined,
  id: Uint8Array,
  context: ChainContext,
): Transaction | undefined {
  if (bytes === undefined) return undefined;
  const tx = transactionCodec.decode(bytes);
  sameBytes(transactionId(context, tx.intent, tx.envelope), id);
  return tx;
}
export function receiptProjection(
  value: unknown,
  id: Uint8Array,
  identity: AuthorizationFinalityStatus,
  tx: TransactionProjection | null,
  canonical?: Transaction,
  checkObservedHead = true,
): TransactionReceipt | null {
  if (value === null) return null;
  requireResult(tx !== null && tx.location !== null);
  const r = shape(
    value,
    [
      "transactionHash",
      "transactionIndex",
      "blockHash",
      "blockNumber",
      "from",
      "to",
      "cumulativeGasUsed",
      "gasUsed",
      "contractAddress",
      "logs",
      "logsBloom",
      "status",
      "authorizationMode",
      "credentialId",
      "authorizationEpoch",
      "authorizationNonce",
      "policyHash",
      "authorizationGasUsed",
      "actualFee",
      "burnedFee",
      "effectiveGasPrice",
      "counterDeltaHash",
      "actionStatus",
      "failureCode",
      "eventsRoot",
      "authorizationEvents",
    ],
    ["sponsor"],
  );
  const loc = location(r, identity, checkObservedHead);
  requireResult(loc !== null);
  sameBytes(loc.blockHash, tx.location.blockHash);
  requireResult(
    loc.blockNumber === tx.location.blockNumber &&
      loc.transactionIndex === tx.location.transactionIndex,
  );
  const from = addr(r.from),
    to = nullableAddress(r.to),
    transactionHash = wireBytes(r.transactionHash, 32, 32);
  sameBytes(transactionHash, id);
  sameBytes(from, tx.from);
  sameNullable(to, tx.to);
  const actionStatus = Number(boundedQuantity(r.actionStatus, 8)) as 0 | 1,
    failureCode = Number(boundedQuantity(r.failureCode, 16));
  requireResult(
    (actionStatus === 0 || actionStatus === 1) &&
      quantity(r.status) === BigInt(actionStatus) &&
      (failureCode <= 8 || failureCode === 0x100) &&
      (actionStatus === 1 ? failureCode === 0 : failureCode !== 0),
  );
  const authorizationMode = Number(boundedQuantity(r.authorizationMode, 8)) as
      0 | 1 | 2,
    credentialId = wireBytes(r.credentialId, 32, 32),
    authorizationEpoch = quantity(r.authorizationEpoch),
    authorizationNonce = quantity(r.authorizationNonce),
    policyHash = wireBytes(r.policyHash, 32, 32);
  requireResult(authorizationMode <= 2 && authorizationNonce === tx.nonce);
  requireResult(
    authorizationMode === 0
      ? isZero(credentialId) && isZero(policyHash) && authorizationEpoch === 0n
      : !isZero(credentialId) &&
          authorizationEpoch > 0n &&
          (authorizationMode === 2 ? !isZero(policyHash) : isZero(policyHash)),
  );
  const gasUsed = quantity(r.gasUsed),
    cumulativeGasUsed = quantity(r.cumulativeGasUsed),
    authorizationGasUsed = quantity(r.authorizationGasUsed),
    actualFee = amount(r.actualFee),
    burnedFee = amount(r.burnedFee),
    effectiveGasPrice = quantity(r.effectiveGasPrice, 256),
    sponsor = Object.hasOwn(r, "sponsor") ? addr(r.sponsor) : null;
  sameNullable(sponsor, tx.sponsor);
  requireResult(authorizationMode !== 2 || sponsor === null);
  requireResult(
    gasUsed <= tx.gas &&
      gasUsed <= cumulativeGasUsed &&
      authorizationGasUsed <= gasUsed &&
      burnedFee <= actualFee &&
      effectiveGasPrice <= tx.maxFeePerGas &&
      actualFee === gasUsed * effectiveGasPrice &&
      effectiveGasPrice === tx.gasPrice,
  );
  const eventsRoot = wireBytes(r.eventsRoot, 32, 32),
    authorizationEvents = array(r.authorizationEvents, 0, 2).map((v) => {
      const event = record(v, ["type", "data"]),
        decoded = authorizationEventCodec.decode(wireBytes(event.data, 303, 303));
      requireResult(Number(boundedQuantity(event.type, 16)) === decoded.type);
      sameBytes(decoded.transactionId, id);
      requireResult(
        decoded.blockHeight === loc.blockNumber &&
          decoded.actionStatus === actionStatus &&
          decoded.failureCode === failureCode,
      );
      if (decoded.type === 0x109 || decoded.type >= 0x10a)
        sameBytes(decoded.actor, from);
      else sameBytes(decoded.owner, from);
      return decoded;
    });
  sameBytes(authorizationEventsRoot(authorizationEvents), eventsRoot);
  let valueDelta = 0n;
  if (authorizationMode === 2) {
    requireResult(
      tx.actionType <= 7 &&
        authorizationEvents.length === (tx.actionType === 7 ? 2 : 1),
    );
    const attempt = authorizationEvents[0]!;
    requireResult(
      attempt.type === 0x107 &&
        attempt.authEpoch === authorizationEpoch &&
        attempt.sessionNonce === authorizationNonce + 1n &&
        attempt.amountA === actualFee,
    );
    sameBytes(attempt.grantId, credentialId);
    sameBytes(attempt.policyHash, policyHash);
    valueDelta = attempt.amountB;
    requireResult(actionStatus === 1 && tx.actionType !== 7 ? true : valueDelta === 0n);
    if (authorizationEvents[1]) {
      const cancel = authorizationEvents[1];
      requireResult(
        cancel.type === 0x108 &&
          cancel.authEpoch === authorizationEpoch &&
          cancel.amountA === actualFee &&
          cancel.amountB === 0n,
      );
      sameBytes(cancel.policyHash, policyHash);
    }
  } else {
    const expectedEvent: Record<number, number> = {
      8: 0x109,
      15: 0x10b,
      16: 0x10d,
      128: 0x100,
      129: 0x101,
      130: 0x102,
      131: 0x103,
      132: 0x104,
      133: 0x105,
      134: 0x106,
      135: 0x10a,
      136: 0x10c,
    };
    const expectedType = actionStatus === 1 ? expectedEvent[tx.actionType] : undefined;
    requireResult(authorizationEvents.length === (expectedType === undefined ? 0 : 1));
    if (expectedType !== undefined)
      requireResult(authorizationEvents[0]!.type === expectedType);
  }
  if (
    authorizationMode === 2 &&
    actionStatus === 1 &&
    [0, 1, 2, 3, 5].includes(tx.actionType)
  )
    requireResult(valueDelta === tx.value);
  const counterDelta: ReceiptCounterDelta = {
    version: 1,
    mode: authorizationMode,
    actionType: tx.actionType,
    nonceDelta: sponsor ? 2 : 1,
    attemptsDelta: authorizationMode === 2 ? 1 : 0,
    successesDelta:
      authorizationMode === 2 && actionStatus === 1 && tx.actionType !== 7 ? 1 : 0,
    claimsDelta:
      authorizationMode === 2 && actionStatus === 1 && tx.actionType === 6 ? 1 : 0,
    valueCategory:
      authorizationMode === 2 && actionStatus === 1 && tx.actionType !== 7
        ? [1, 1, 1, 2, 4, 3, 5][tx.actionType]!
        : 0,
    valueDelta,
    feeDelta: actualFee,
    succeeded: actionStatus === 1,
  };
  const counterDeltaHash = wireBytes(r.counterDeltaHash, 32, 32);
  sameBytes(receiptCounterDeltaHash(counterDelta), counterDeltaHash);
  if (canonical) {
    const e = canonical.envelope;
    requireResult(authorizationMode === e.mode && authorizationEpoch === e.authEpoch);
    sameBytes(credentialId, e.credentialId);
    sameBytes(policyHash, e.policyHash);
  }
  const logs = array(r.logs, 0, 4096).map((v, at) => {
    const l = record(v, [
      "address",
      "topics",
      "data",
      "blockNumber",
      "transactionHash",
      "transactionIndex",
      "blockHash",
      "logIndex",
      "removed",
    ]);
    sameBytes(wireBytes(l.transactionHash, 32, 32), id);
    sameBytes(wireBytes(l.blockHash, 32, 32), loc.blockHash);
    requireResult(
      quantity(l.blockNumber) === loc.blockNumber &&
        quantity(l.transactionIndex) === loc.transactionIndex &&
        quantity(l.logIndex) === BigInt(at) &&
        !boolean(l.removed),
    );
    return {
      address: addr(l.address),
      topics: array(l.topics, 0, 4).map((t) => wireBytes(t, 32, 32)),
      data: wireBytes(l.data, 65536),
      logIndex: BigInt(at),
    };
  });
  const logsBloom = wireBytes(r.logsBloom, 256, 256);
  requireResult(isZero(logsBloom));
  return {
    ...loc,
    transactionHash,
    from,
    to,
    cumulativeGasUsed,
    gasUsed,
    contractAddress: nullableAddress(r.contractAddress),
    logs,
    logsBloom,
    actionStatus,
    failureCode,
    authorizationMode,
    credentialId,
    authorizationEpoch,
    authorizationNonce,
    policyHash,
    sponsor,
    authorizationGasUsed,
    actualFee,
    burnedFee,
    effectiveGasPrice,
    counterDeltaHash,
    counterDelta,
    eventsRoot,
    authorizationEvents,
  };
}
