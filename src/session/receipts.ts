import {
  boundedArray,
  checkedNumber,
  codec,
  fixedBytes,
  isZero,
  objectFields,
  requireCondition,
} from "../core/bytes.js";
import { domainHash, keccak256 } from "../core/hash.js";

export interface ReceiptCounterDelta {
  version: 1;
  mode: 0 | 1 | 2;
  /** Pinned Chain action code; observing a delta does not enable its transaction grammar. */
  actionType: number;
  nonceDelta: number;
  attemptsDelta: number;
  successesDelta: number;
  claimsDelta: number;
  valueCategory: number;
  valueDelta: bigint;
  feeDelta: bigint;
  succeeded: boolean;
}
const category = (action: number) => [1, 1, 1, 2, 4, 3, 5, 0][action];
function canonical(condition: unknown): asserts condition {
  requireCondition(condition, "Invalid receipt commitment fields", "NON_CANONICAL");
}
function version(value: number): void {
  requireCondition(value === 1, "Unsupported receipt version", "UNSUPPORTED_VERSION");
}
function hash(value: Uint8Array, nonzero = false): void {
  fixedBytes(value, 32);
  canonical(!nonzero || !isZero(value));
}
function address(value: Uint8Array, nonzero = false): void {
  fixedBytes(value, 20);
  canonical(!nonzero || !isZero(value));
}
function deltaShape(v: ReceiptCounterDelta): void {
  objectFields(v, [
    "version",
    "mode",
    "actionType",
    "nonceDelta",
    "attemptsDelta",
    "successesDelta",
    "claimsDelta",
    "valueCategory",
    "valueDelta",
    "feeDelta",
    "succeeded",
  ]);
  version(v.version);
  checkedNumber(v.actionType, 255);
  canonical(v.mode === 0 || v.mode === 1 || v.mode === 2);
  canonical(v.actionType <= 0x11 || (v.actionType >= 0x80 && v.actionType <= 0x88));
  canonical(v.nonceDelta === 1 || v.nonceDelta === 2);
  for (const n of [v.attemptsDelta, v.successesDelta, v.claimsDelta])
    canonical(n === 0 || n === 1);
  checkedNumber(v.valueCategory, 5);
  canonical(typeof v.succeeded === "boolean");
  if (v.mode !== 2)
    canonical(
      v.attemptsDelta === 0 &&
        v.successesDelta === 0 &&
        v.claimsDelta === 0 &&
        v.valueCategory === 0 &&
        v.valueDelta === 0n,
    );
  else {
    canonical(
      v.attemptsDelta === 1 &&
        v.successesDelta === (v.succeeded && v.actionType !== 7 ? 1 : 0),
    );
    if (!v.succeeded || v.actionType === 7)
      canonical(v.claimsDelta === 0 && v.valueCategory === 0 && v.valueDelta === 0n);
    else
      canonical(
        v.valueCategory !== 0 &&
          v.valueCategory === category(v.actionType) &&
          v.claimsDelta === (v.actionType === 6 ? 1 : 0),
      );
  }
}
export const receiptCounterDeltaCodec = codec<ReceiptCounterDelta>(
  74,
  (w, v) => {
    deltaShape(v);
    w.number(v.version, 16);
    for (const n of [
      v.mode,
      v.actionType,
      v.nonceDelta,
      v.attemptsDelta,
      v.successesDelta,
      v.claimsDelta,
      v.valueCategory,
    ])
      w.number(n, 8);
    w.uint(v.valueDelta, 256);
    w.uint(v.feeDelta, 256);
    w.bool(v.succeeded);
  },
  (r) => ({
    version: r.number(16) as 1,
    mode: r.number(8) as 0 | 1 | 2,
    actionType: r.number(8),
    nonceDelta: r.number(8),
    attemptsDelta: r.number(8),
    successesDelta: r.number(8),
    claimsDelta: r.number(8),
    valueCategory: r.number(8),
    valueDelta: r.uint(256),
    feeDelta: r.uint(256),
    succeeded: r.bool(),
  }),
);
export function receiptCounterDeltaHash(value: ReceiptCounterDelta): Uint8Array {
  return domainHash(
    "RESILIENCE_RECEIPT_COUNTER_DELTA_V1",
    receiptCounterDeltaCodec.encode(value),
  );
}

export interface AuthorizationEvent {
  version: 1;
  type: number;
  owner: Uint8Array;
  actor: Uint8Array;
  grantId: Uint8Array;
  relatedId: Uint8Array;
  rootConfigHash: Uint8Array;
  policyHash: Uint8Array;
  authEpoch: bigint;
  rootNonce: bigint;
  sessionNonce: bigint;
  blockHeight: bigint;
  transactionId: Uint8Array;
  amountA: bigint;
  amountB: bigint;
  actionStatus: 0 | 1;
  failureCode: number;
}
function eventShape(v: AuthorizationEvent): void {
  objectFields(v, [
    "version",
    "type",
    "owner",
    "actor",
    "grantId",
    "relatedId",
    "rootConfigHash",
    "policyHash",
    "authEpoch",
    "rootNonce",
    "sessionNonce",
    "blockHeight",
    "transactionId",
    "amountA",
    "amountB",
    "actionStatus",
    "failureCode",
  ]);
  version(v.version);
  checkedNumber(v.type, 0x10d);
  canonical(v.type >= 0x100);
  address(v.owner, true);
  address(v.actor);
  hash(v.transactionId, true);
  for (const h of [v.grantId, v.relatedId, v.rootConfigHash, v.policyHash]) hash(h);
  canonical(v.blockHeight > 0n);
  canonical(v.actionStatus === 0 || v.actionStatus === 1);
  checkedNumber(v.failureCode, 65535);
  canonical(v.actionStatus === 1 ? v.failureCode === 0 : v.failureCode !== 0);
  canonical(v.type === 0x107 || v.actionStatus === 1);
  canonical(v.type === 0x109 || v.type >= 0x10a || isZero(v.actor));
  canonical(v.type === 0x103 || isZero(v.relatedId));
  if (v.type >= 0x10a)
    canonical(
      !isZero(v.actor) &&
        v.authEpoch > 0n &&
        v.sessionNonce > 0n &&
        !isZero(v.rootConfigHash),
    );
  else if (v.type === 0x100 || v.type === 0x105)
    canonical(!isZero(v.rootConfigHash) && v.authEpoch > 0n);
  else if (v.type === 0x101 || v.type === 0x103)
    canonical(
      !isZero(v.grantId) &&
        !isZero(v.policyHash) &&
        v.authEpoch > 0n &&
        (v.type !== 0x103 || !isZero(v.relatedId)),
    );
  else if ([0x102, 0x107, 0x108, 0x109].includes(v.type))
    canonical(
      !isZero(v.grantId) &&
        v.authEpoch > 0n &&
        (![0x107, 0x108].includes(v.type) || !isZero(v.policyHash)),
    );
  else canonical(v.authEpoch > 0n);
  canonical(v.type !== 0x109 || !isZero(v.actor));
}
export const authorizationEventCodec = codec<AuthorizationEvent>(
  303,
  (w, v) => {
    eventShape(v);
    w.number(v.version, 16);
    w.number(v.type, 16);
    w.fixed(v.owner, 20);
    w.fixed(v.actor, 20);
    for (const h of [v.grantId, v.relatedId, v.rootConfigHash, v.policyHash])
      w.fixed(h, 32);
    for (const n of [v.authEpoch, v.rootNonce, v.sessionNonce, v.blockHeight])
      w.uint(n, 64);
    w.fixed(v.transactionId, 32);
    w.uint(v.amountA, 256);
    w.uint(v.amountB, 256);
    w.number(v.actionStatus, 8);
    w.number(v.failureCode, 16);
  },
  (r) => ({
    version: r.number(16) as 1,
    type: r.number(16),
    owner: r.fixed(20),
    actor: r.fixed(20),
    grantId: r.fixed(32),
    relatedId: r.fixed(32),
    rootConfigHash: r.fixed(32),
    policyHash: r.fixed(32),
    authEpoch: r.uint(64),
    rootNonce: r.uint(64),
    sessionNonce: r.uint(64),
    blockHeight: r.uint(64),
    transactionId: r.fixed(32),
    amountA: r.uint(256),
    amountB: r.uint(256),
    actionStatus: r.number(8) as 0 | 1,
    failureCode: r.number(16),
  }),
);
export function authorizationEventsRoot(
  events: readonly AuthorizationEvent[],
): Uint8Array {
  boundedArray(events, 0, 2);
  const leaves = events.map((event) =>
    keccak256(authorizationEventCodec.encode(event)),
  );
  if (events.length === 2) {
    const a = events[0]!,
      b = events[1]!;
    canonical(
      a.type === 0x107 &&
        b.type === 0x108 &&
        a.blockHeight === b.blockHeight &&
        a.sessionNonce === b.sessionNonce,
    );
    for (const key of ["owner", "grantId", "transactionId"] as const)
      canonical(a[key].every((byte, at) => byte === b[key][at]));
  } else if (events.length === 1) canonical(events[0]!.type !== 0x108);
  return leaves.length === 0
    ? new Uint8Array(32)
    : leaves.length === 1
      ? leaves[0]!
      : keccak256(new Uint8Array([...leaves[0]!, ...leaves[1]!]));
}

export interface DecisionBucket {
  available: bigint;
  lastRefillHeight: bigint;
}
/** Internal Go seal preimage. Encoding/hash does not evaluate policy or grant node authority. */
export interface SessionDecisionCommitment {
  sender: Uint8Array;
  intentHash: Uint8Array;
  grantId: Uint8Array;
  authEpoch: bigint;
  sessionNonce: bigint;
  policyHash: Uint8Array;
  actionType: number;
  maximumFee: bigint;
  maximumDebit: bigint;
  reservedValue: bigint;
  valueCategory: number;
  feeBucketPresent: boolean;
  feeBucket: DecisionBucket;
  valueBucketPresent: boolean;
  valueBucket: DecisionBucket;
  matchedRulePresent: boolean;
  matchedRuleIndex: number;
  maxRuntimeCodeLength: number;
  constraintCount: number;
  inspectedCalldataBytes: number;
  merkleProofNodes: number;
  targetCodePresent: boolean;
  targetCodeAddress: Uint8Array;
  targetCodeDependency: Uint8Array;
  evaluationHeight: bigint;
}
function decisionShape(v: SessionDecisionCommitment): void {
  objectFields(v, [
    "sender",
    "intentHash",
    "grantId",
    "authEpoch",
    "sessionNonce",
    "policyHash",
    "actionType",
    "maximumFee",
    "maximumDebit",
    "reservedValue",
    "valueCategory",
    "feeBucketPresent",
    "feeBucket",
    "valueBucketPresent",
    "valueBucket",
    "matchedRulePresent",
    "matchedRuleIndex",
    "maxRuntimeCodeLength",
    "constraintCount",
    "inspectedCalldataBytes",
    "merkleProofNodes",
    "targetCodePresent",
    "targetCodeAddress",
    "targetCodeDependency",
    "evaluationHeight",
  ]);
  address(v.sender, true);
  address(v.targetCodeAddress);
  hash(v.intentHash, true);
  hash(v.grantId, true);
  hash(v.policyHash, true);
  hash(v.targetCodeDependency);
  checkedNumber(v.actionType, 7);
  canonical(v.authEpoch > 0n && v.maximumDebit >= v.maximumFee);
  canonical(
    v.valueCategory === category(v.actionType) &&
      v.matchedRulePresent === (v.actionType === 1 || v.actionType === 2),
  );
  canonical(v.matchedRulePresent || v.matchedRuleIndex === 0);
  canonical(v.actionType === 2 || v.maxRuntimeCodeLength === 0);
  canonical(
    v.actionType === 1 || (v.constraintCount === 0 && v.inspectedCalldataBytes === 0),
  );
  canonical(v.actionType === 0 || v.actionType === 5 || v.merkleProofNodes === 0);
  canonical(
    v.targetCodePresent
      ? v.actionType === 1 &&
          !isZero(v.targetCodeAddress) &&
          !isZero(v.targetCodeDependency)
      : isZero(v.targetCodeAddress) && isZero(v.targetCodeDependency),
  );
  objectFields(v.feeBucket, ["available", "lastRefillHeight"]);
  objectFields(v.valueBucket, ["available", "lastRefillHeight"]);
}
export const sessionDecisionCommitmentCodec = codec<SessionDecisionCommitment>(
  387,
  (w, v) => {
    decisionShape(v);
    w.fixed(v.sender, 20);
    w.fixed(v.intentHash, 32);
    w.fixed(v.grantId, 32);
    w.uint(v.authEpoch, 64);
    w.uint(v.sessionNonce, 64);
    w.fixed(v.policyHash, 32);
    w.number(v.actionType, 8);
    for (const n of [v.maximumFee, v.maximumDebit, v.reservedValue]) w.uint(n, 256);
    w.number(v.valueCategory, 8);
    for (const [present, bucket] of [
      [v.feeBucketPresent, v.feeBucket],
      [v.valueBucketPresent, v.valueBucket],
    ] as const) {
      w.bool(present);
      w.uint(bucket.available, 256);
      w.uint(bucket.lastRefillHeight, 64);
    }
    w.bool(v.matchedRulePresent);
    w.number(v.matchedRuleIndex, 16);
    w.number(v.maxRuntimeCodeLength, 32);
    w.number(v.constraintCount, 16);
    w.number(v.inspectedCalldataBytes, 32);
    w.number(v.merkleProofNodes, 8);
    w.bool(v.targetCodePresent);
    w.fixed(v.targetCodeAddress, 20);
    w.fixed(v.targetCodeDependency, 32);
    w.uint(v.evaluationHeight, 64);
  },
  (r) => ({
    sender: r.fixed(20),
    intentHash: r.fixed(32),
    grantId: r.fixed(32),
    authEpoch: r.uint(64),
    sessionNonce: r.uint(64),
    policyHash: r.fixed(32),
    actionType: r.number(8),
    maximumFee: r.uint(256),
    maximumDebit: r.uint(256),
    reservedValue: r.uint(256),
    valueCategory: r.number(8),
    feeBucketPresent: r.bool(),
    feeBucket: { available: r.uint(256), lastRefillHeight: r.uint(64) },
    valueBucketPresent: r.bool(),
    valueBucket: { available: r.uint(256), lastRefillHeight: r.uint(64) },
    matchedRulePresent: r.bool(),
    matchedRuleIndex: r.number(16),
    maxRuntimeCodeLength: r.number(32),
    constraintCount: r.number(16),
    inspectedCalldataBytes: r.number(32),
    merkleProofNodes: r.number(8),
    targetCodePresent: r.bool(),
    targetCodeAddress: r.fixed(20),
    targetCodeDependency: r.fixed(32),
    evaluationHeight: r.uint(64),
  }),
);
export function sessionDecisionCommitmentHash(
  value: SessionDecisionCommitment,
): Uint8Array {
  return domainHash(
    "RESILIENCE_SESSION_DECISION_V1",
    sessionDecisionCommitmentCodec.encode(value),
  );
}
