import {
  boundedArray,
  codec,
  compareBytes,
  isZero,
  objectFields,
  requireCondition,
  Reader,
  Writer,
} from "../core/bytes.js";
import { versionOne } from "./root.js";
import type {
  FeePolicy,
  LimitSet,
  Policy,
  RecipientSet,
  TokenBucket,
} from "./types.js";

function writeBucket(w: Writer, bucket: TokenBucket): void {
  objectFields(bucket, ["capacity", "refillPerBlock"]);
  requireCondition(bucket.capacity > 0n, "Zero token bucket capacity");
  w.uint(bucket.capacity, 256);
  w.uint(bucket.refillPerBlock, 256);
}
function readBucket(r: Reader): TokenBucket {
  return { capacity: r.uint(256), refillPerBlock: r.uint(256) };
}
function writeFee(w: Writer, fee: FeePolicy): void {
  objectFields(fee, [
    "maxGasLimit",
    "maxGasPrice",
    "maxFeePerTransaction",
    "lifetimeFeeLimit",
    "feeTokenBucket",
  ]);
  requireCondition(
    fee.maxGasLimit > 0n &&
      fee.maxGasPrice > 0n &&
      fee.maxFeePerTransaction > 0n &&
      fee.lifetimeFeeLimit > 0n,
    "Fee bounds must be nonzero",
  );
  w.uint(fee.maxGasLimit, 64);
  w.uint(fee.maxGasPrice, 256);
  w.uint(fee.maxFeePerTransaction, 256);
  w.uint(fee.lifetimeFeeLimit, 256);
  w.bool(fee.feeTokenBucket !== undefined);
  if (fee.feeTokenBucket !== undefined) writeBucket(w, fee.feeTokenBucket);
}
function readFee(r: Reader): FeePolicy {
  const fee: FeePolicy = {
    maxGasLimit: r.uint(64),
    maxGasPrice: r.uint(256),
    maxFeePerTransaction: r.uint(256),
    lifetimeFeeLimit: r.uint(256),
  };
  if (r.bool()) fee.feeTokenBucket = readBucket(r);
  return fee;
}
function writeLimits(w: Writer, limits: LimitSet): void {
  objectFields(limits, ["maxPerTransaction", "lifetimeLimit", "valueTokenBucket"]);
  w.uint(limits.maxPerTransaction, 256);
  w.uint(limits.lifetimeLimit, 256);
  w.bool(limits.valueTokenBucket !== undefined);
  if (limits.valueTokenBucket !== undefined) writeBucket(w, limits.valueTokenBucket);
}
function readLimits(r: Reader): LimitSet {
  const limits: LimitSet = {
    maxPerTransaction: r.uint(256),
    lifetimeLimit: r.uint(256),
  };
  if (r.bool()) limits.valueTokenBucket = readBucket(r);
  return limits;
}
function writeRecipients(w: Writer, set: RecipientSet): void {
  objectFields(set, ["kind", "recipients", "merkleRoot", "leafCount"]);
  requireCondition(
    set.kind === 0 || set.kind === 1,
    "Unsupported recipient kind",
    "UNSUPPORTED_FEATURE",
  );
  w.number(set.kind, 8);
  if (set.kind === 0) {
    objectFields(set, ["kind", "recipients"]);
    boundedArray(set.recipients, 1, 128);
    w.number(set.recipients.length, 16);
    let previous: Uint8Array | undefined;
    for (const recipient of set.recipients) {
      w.fixed(recipient, 20);
      requireCondition(!isZero(recipient), "Zero recipient");
      requireCondition(
        !previous || compareBytes(previous, recipient) < 0,
        "Recipients not strictly sorted",
        "NON_CANONICAL",
      );
      previous = recipient;
    }
  } else {
    objectFields(set, ["kind", "merkleRoot", "leafCount"]);
    w.fixed(set.merkleRoot, 32);
    requireCondition(
      !isZero(set.merkleRoot) && set.leafCount > 0,
      "Invalid Merkle recipient fields",
      "NON_CANONICAL",
    );
    w.number(set.leafCount, 32);
  }
}
function readRecipients(r: Reader): RecipientSet {
  const kind = r.number(8);
  if (kind === 1) return { kind, merkleRoot: r.fixed(32), leafCount: r.number(32) };
  requireCondition(kind === 0, "Unsupported recipient kind", "UNSUPPORTED_FEATURE");
  const count = r.number(16);
  requireCondition(
    count > 0 && count <= 128,
    "Recipient count exceeds limit",
    "LIMIT_EXCEEDED",
  );
  return { kind, recipients: Array.from({ length: count }, () => r.fixed(20)) };
}

export function writePolicy(w: Writer, policy: Policy): void {
  objectFields(policy, ["version", "actionMask", "maxAttempts", "fee", "transfer"]);
  versionOne(policy.version);
  requireCondition(
    policy.actionMask === 1n,
    "Only transfer policies are implemented",
    "UNSUPPORTED_FEATURE",
  );
  requireCondition(policy.maxAttempts > 0n, "Zero max attempts");
  w.number(policy.version, 16);
  w.uint(policy.actionMask, 64);
  w.uint(policy.maxAttempts, 64);
  writeFee(w, policy.fee);
  w.bool(true);
  const transfer = policy.transfer;
  objectFields(transfer, [
    "recipients",
    "limits",
    "allowZeroValue",
    "allowSelfTransfer",
  ]);
  writeRecipients(w, transfer.recipients);
  writeLimits(w, transfer.limits);
  w.bool(transfer.allowZeroValue);
  w.bool(transfer.allowSelfTransfer);
  for (let index = 0; index < 6; index++) w.bool(false);
}

export function readPolicy(r: Reader): Policy {
  versionOne(r.number(16));
  const actionMask = r.uint(64),
    maxAttempts = r.uint(64),
    fee = readFee(r);
  requireCondition(
    r.bool(),
    "Only transfer policies are implemented",
    "UNSUPPORTED_FEATURE",
  );
  const transfer = {
    recipients: readRecipients(r),
    limits: readLimits(r),
    allowZeroValue: r.bool(),
    allowSelfTransfer: r.bool(),
  };
  for (let index = 0; index < 6; index++)
    requireCondition(!r.bool(), "Unsupported policy section", "UNSUPPORTED_FEATURE");
  return { version: 1, actionMask, maxAttempts, fee, transfer };
}
export const policyCodec = codec<Policy>(16_384, writePolicy, readPolicy);
