import {
  CodecError,
  Writer,
  bytesToHex,
  compareBytes,
  decodeUint256,
  hexToBytes,
  isZero,
} from "../core/bytes.js";
import {
  grantId as deriveGrantId,
  policyHash,
  rootConfigHash,
  rootConfigCodec,
  rootKeyId,
  policyCodec,
  validateSessionPublicKey,
} from "../session/index.js";
import type { Policy, RootConfig, TokenBucket } from "../session/types.js";
import { AUTHORIZATION_CAPABILITY, RpcContractError } from "./contracts.js";
import type {
  AuthorizationFinalityStatus,
  BucketState,
  DecodedPolicy,
  ExpectedChainIdentity,
  FinalizedState,
  PolicyPreview,
  RootAuthorityObservation,
  SessionGrantObservation,
  SessionNonceObservation,
  SessionUsageObservation,
  UsageCounters,
} from "./contracts.js";

export function requireResult(condition: unknown): asserts condition {
  if (!condition) throw new RpcContractError("INVALID_RESULT");
}
export function resultGuard<T>(read: () => T): T {
  try {
    return read();
  } catch (error) {
    if (error instanceof RpcContractError) throw error;
    if (
      error instanceof CodecError &&
      (error.code === "UNSUPPORTED_VERSION" || error.code === "UNSUPPORTED_FEATURE")
    )
      throw new RpcContractError("UNSUPPORTED_RESULT");
    throw new RpcContractError("INVALID_RESULT");
  }
}
export function inputGuard<T>(read: () => T): T {
  try {
    return read();
  } catch {
    throw new RpcContractError("INVALID_ARGUMENT");
  }
}
export function record(
  value: unknown,
  fields: readonly string[],
): Record<string, unknown> {
  requireResult(value !== null && typeof value === "object" && !Array.isArray(value));
  const item = value as Record<string, unknown>;
  requireResult(
    Object.keys(item).length === fields.length &&
      fields.every((field) => Object.hasOwn(item, field)),
  );
  return item;
}
export function array(value: unknown, minimum: number, maximum: number): unknown[] {
  requireResult(
    Array.isArray(value) && value.length >= minimum && value.length <= maximum,
  );
  return value;
}
export function integer(value: unknown, maximum: number): number {
  requireResult(
    typeof value === "number" &&
      Number.isSafeInteger(value) &&
      value >= 0 &&
      value <= maximum,
  );
  return value;
}
export function boolean(value: unknown): boolean {
  requireResult(typeof value === "boolean");
  return value;
}
export function quantity(value: unknown, bits: 64 | 256 = 64): bigint {
  requireResult(
    typeof value === "string" &&
      value.length <= bits / 4 + 2 &&
      /^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(value),
  );
  return BigInt(value);
}
export function wireBytes(value: unknown, maximum: number, width?: number): Uint8Array {
  requireResult(typeof value === "string");
  const bytes = hexToBytes(value, maximum);
  requireResult(width === undefined || bytes.length === width);
  return bytes;
}
export function amount(value: unknown): bigint {
  return decodeUint256(wireBytes(value, 32, 32));
}
export function sameBytes(a: Uint8Array, b: Uint8Array): void {
  requireResult(compareBytes(a, b) === 0);
}
export function fixedInput(
  value: Uint8Array,
  width: number,
  nonzero = false,
): Uint8Array {
  requireResult(
    value instanceof Uint8Array &&
      value.length === width &&
      (!nonzero || !isZero(value)),
  );
  return new Uint8Array(value);
}
export function state(value: unknown): FinalizedState {
  const s = record(value, ["blockHash", "height", "stateRoot", "finality"]);
  requireResult(s.finality === "finalized");
  return {
    blockHash: wireBytes(s.blockHash, 32, 32),
    height: quantity(s.height),
    stateRoot: wireBytes(s.stateRoot, 32, 32),
    finality: "finalized",
  };
}
export function sameState(a: FinalizedState, b: FinalizedState): boolean {
  return (
    a.height === b.height &&
    compareBytes(a.blockHash, b.blockHash) === 0 &&
    compareBytes(a.stateRoot, b.stateRoot) === 0
  );
}
export function identity(
  value: unknown,
  expected: ExpectedChainIdentity,
): AuthorizationFinalityStatus {
  const r = record(value, [
    "state",
    "chainId",
    "genesisHash",
    "authorizationCapability",
  ]);
  const chainId = quantity(r.chainId),
    genesisHash = wireBytes(r.genesisHash, 32, 32);
  requireResult(typeof r.authorizationCapability === "string");
  if (
    chainId !== expected.chainId ||
    compareBytes(genesisHash, expected.genesisHash) !== 0 ||
    r.authorizationCapability !== expected.authorizationCapability
  )
    throw new RpcContractError("CHAIN_IDENTITY_MISMATCH");
  return {
    state: state(r.state),
    chainId,
    genesisHash,
    authorizationCapability: AUTHORIZATION_CAPABILITY,
  };
}
function bucket(value: unknown): TokenBucket | undefined {
  if (value === null) return undefined;
  const b = record(value, ["capacity", "refillPerBlock"]);
  return { capacity: amount(b.capacity), refillPerBlock: amount(b.refillPerBlock) };
}
export function policy(value: unknown): Policy {
  const p = record(value, ["version", "actionMask", "maxAttempts", "fee", "transfer"]);
  const f = record(p.fee, [
    "maxGasLimit",
    "maxGasPrice",
    "maxFeePerTransaction",
    "lifetimeFeeLimit",
    "tokenBucket",
  ]);
  const t = record(p.transfer, [
    "recipients",
    "limits",
    "allowZeroValue",
    "allowSelfTransfer",
  ]);
  const l = record(t.limits, ["maxPerTransaction", "lifetimeLimit", "tokenBucket"]);
  const r = record(t.recipients, ["kind", "inline", "merkleRoot", "leafCount"]);
  const kind = integer(r.kind, 1),
    leaves = integer(r.leafCount, 0xffff_ffff);
  const root = wireBytes(r.merkleRoot, 32, 32),
    recipients = array(r.inline, kind === 0 ? 1 : 0, kind === 0 ? 128 : 0).map((item) =>
      wireBytes(item, 20, 20),
    );
  if (kind === 0) requireResult(isZero(root) && leaves === 0);
  const valueBucket = bucket(l.tokenBucket),
    feeBucket = bucket(f.tokenBucket);
  const result: Policy = {
    version: integer(p.version, 0xffff) as 1,
    actionMask: quantity(p.actionMask),
    maxAttempts: quantity(p.maxAttempts),
    fee: {
      maxGasLimit: quantity(f.maxGasLimit),
      maxGasPrice: amount(f.maxGasPrice),
      maxFeePerTransaction: amount(f.maxFeePerTransaction),
      lifetimeFeeLimit: amount(f.lifetimeFeeLimit),
      ...(feeBucket ? { feeTokenBucket: feeBucket } : {}),
    },
    transfer: {
      recipients:
        kind === 0
          ? { kind, recipients }
          : { kind: 1, merkleRoot: root, leafCount: leaves },
      limits: {
        maxPerTransaction: amount(l.maxPerTransaction),
        lifetimeLimit: amount(l.lifetimeLimit),
        ...(valueBucket ? { valueTokenBucket: valueBucket } : {}),
      },
      allowZeroValue: boolean(t.allowZeroValue),
      allowSelfTransfer: boolean(t.allowSelfTransfer),
    },
  };
  policyCodec.encode(result);
  return result;
}
function config(value: unknown): RootConfig {
  const c = record(value, ["version", "threshold", "keys"]);
  const keys = array(c.keys, 1, 8).map((item) => {
    const k = record(item, ["keyScheme", "rootKeyId", "publicKey"]);
    const key = {
      keyScheme: integer(k.keyScheme, 255) as 1,
      publicKey: wireBytes(k.publicKey, 32, 32),
    };
    // The stored authority validator checks actual Ed25519 points as well as widths.
    requireResult(key.keyScheme === 1);
    validateSessionPublicKey(1, key.publicKey);
    sameBytes(wireBytes(k.rootKeyId, 32, 32), rootKeyId(key));
    return key;
  });
  const result = {
    version: integer(c.version, 0xffff) as 1,
    threshold: integer(c.threshold, 8),
    keys,
  };
  rootConfigCodec.encode(result);
  return result;
}
export function rootObservation(
  value: unknown,
  owner: Uint8Array,
): RootAuthorityObservation {
  const r = record(value, [
    "state",
    "owner",
    "authorizationMode",
    "authorizationRoot",
    "authority",
  ]);
  const observedOwner = wireBytes(r.owner, 20, 20);
  sameBytes(observedOwner, owner);
  const base = {
    state: state(r.state),
    owner: observedOwner,
    authorizationRoot: wireBytes(r.authorizationRoot, 32, 32),
  };
  const mode = integer(r.authorizationMode, 1);
  if (mode === 0) {
    requireResult(r.authority === null);
    return { ...base, authorizationMode: 0, authority: null };
  }
  const a = record(r.authority, [
    "canonical",
    "version",
    "authEpoch",
    "rootNonce",
    "nextGrantSequence",
    "activeGrantCount",
    "securityReserve",
    "rootConfigHash",
    "rootConfig",
  ]);
  const rootConfig = config(a.rootConfig),
    authEpoch = quantity(a.authEpoch),
    securityReserve = amount(a.securityReserve),
    activeGrantCount = integer(a.activeGrantCount, 64);
  requireResult(
    integer(a.version, 0xffff) === 1 &&
      authEpoch > 0n &&
      (activeGrantCount === 0 || securityReserve >= 100_000_000_000_000_000n),
  );
  const authority = {
    canonical: wireBytes(a.canonical, 512),
    version: 1 as const,
    authEpoch,
    rootNonce: quantity(a.rootNonce),
    nextGrantSequence: quantity(a.nextGrantSequence),
    activeGrantCount,
    securityReserve,
    rootConfigHash: wireBytes(a.rootConfigHash, 32, 32),
    rootConfig,
  };
  sameBytes(authority.rootConfigHash, rootConfigHash(rootConfig));
  // Pinned state_codec.go omits Config.Version from the stored authority body.
  const w = new Writer(512);
  w.number(1, 16);
  w.uint(authEpoch, 64);
  w.uint(authority.rootNonce, 64);
  w.uint(authority.nextGrantSequence, 64);
  w.number(activeGrantCount, 32);
  w.fixed(rootConfigCodec.encode(rootConfig).slice(2));
  w.uint(securityReserve, 256);
  sameBytes(authority.canonical, w.finish());
  return { ...base, authorizationMode: 1, authority };
}
function bucketState(value: unknown): BucketState {
  const b = record(value, ["available", "lastRefillHeight"]);
  return {
    available: amount(b.available),
    lastRefillHeight: quantity(b.lastRefillHeight),
  };
}
export function usage(value: unknown): UsageCounters {
  const u = record(value, [
    "attempts",
    "successes",
    "externalValueSpent",
    "stakeValueLocked",
    "delegationValueLocked",
    "valueUnlocked",
    "rewardsClaimed",
    "feesPaid",
    "claims",
    "valueBuckets",
    "feeBucket",
  ]);
  const buckets = array(u.valueBuckets, 0, 1).map((item) => {
    const b = record(item, ["action", "available", "lastRefillHeight"]);
    requireResult(b.action === "TRANSFER");
    return {
      action: "TRANSFER" as const,
      available: amount(b.available),
      lastRefillHeight: quantity(b.lastRefillHeight),
    };
  });
  const result = {
    attempts: quantity(u.attempts),
    successes: quantity(u.successes),
    externalValueSpent: amount(u.externalValueSpent),
    stakeValueLocked: amount(u.stakeValueLocked),
    delegationValueLocked: amount(u.delegationValueLocked),
    valueUnlocked: amount(u.valueUnlocked),
    rewardsClaimed: amount(u.rewardsClaimed),
    feesPaid: amount(u.feesPaid),
    claims: quantity(u.claims),
    valueBuckets: buckets,
    feeBucket: u.feeBucket === null ? null : bucketState(u.feeBucket),
  };
  requireResult(
    result.successes <= result.attempts &&
      result.claims === 0n &&
      result.stakeValueLocked === 0n &&
      result.delegationValueLocked === 0n &&
      result.valueUnlocked === 0n &&
      result.rewardsClaimed === 0n,
  );
  return result;
}
export function writeUsage(w: Writer, u: UsageCounters): void {
  w.uint(u.attempts, 64);
  w.uint(u.successes, 64);
  for (const value of [
    u.externalValueSpent,
    u.stakeValueLocked,
    u.delegationValueLocked,
    u.valueUnlocked,
    u.rewardsClaimed,
    u.feesPaid,
  ])
    w.uint(value, 256);
  w.uint(u.claims, 64);
  w.number(u.valueBuckets.length, 16);
  for (const b of u.valueBuckets) {
    w.number(0, 8);
    w.uint(b.available, 256);
    w.uint(b.lastRefillHeight, 64);
  }
  w.bool(u.feeBucket !== null);
  if (u.feeBucket) {
    w.uint(u.feeBucket.available, 256);
    w.uint(u.feeBucket.lastRefillHeight, 64);
  }
}
export function sameUsage(a: UsageCounters, b: UsageCounters): void {
  const wa = new Writer(),
    wb = new Writer();
  writeUsage(wa, a);
  writeUsage(wb, b);
  sameBytes(wa.finish(), wb.finish());
}
export function grantObservation(
  value: unknown,
  owner: Uint8Array,
  id: Uint8Array,
  expected: ExpectedChainIdentity,
): SessionGrantObservation {
  const r = record(value, [
    "state",
    "owner",
    "grantId",
    "canonical",
    "authEpoch",
    "generationSequence",
    "keyScheme",
    "publicKey",
    "policyVersion",
    "policyHash",
    "policy",
    "createdHeight",
    "validAfterHeight",
    "validUntilHeight",
    "sessionNonce",
    "usage",
    "storageDeposit",
    "activeIndexPresent",
    "usableAtObservedBlock",
  ]);
  const keyScheme = integer(r.keyScheme, 2);
  requireResult(keyScheme === 1 || keyScheme === 2);
  const p = policy(r.policy);
  const g: SessionGrantObservation = {
    state: state(r.state),
    owner: wireBytes(r.owner, 20, 20),
    grantId: wireBytes(r.grantId, 32, 32),
    canonical: wireBytes(r.canonical, 17_408),
    authEpoch: quantity(r.authEpoch),
    generationSequence: quantity(r.generationSequence),
    keyScheme,
    publicKey: wireBytes(r.publicKey, 64, keyScheme === 1 ? 32 : 64),
    policyVersion: integer(r.policyVersion, 0xffff) as 1,
    policyHash: wireBytes(r.policyHash, 32, 32),
    policy: p,
    createdHeight: quantity(r.createdHeight),
    validAfterHeight: quantity(r.validAfterHeight),
    validUntilHeight: quantity(r.validUntilHeight),
    sessionNonce: quantity(r.sessionNonce),
    usage: usage(r.usage),
    storageDeposit: amount(r.storageDeposit),
    activeIndexPresent: true,
    usableAtObservedBlock: boolean(r.usableAtObservedBlock),
  };
  requireResult(
    r.activeIndexPresent === true &&
      g.authEpoch > 0n &&
      g.policyVersion === 1 &&
      g.validAfterHeight > g.createdHeight &&
      g.validUntilHeight > g.validAfterHeight &&
      g.validUntilHeight - g.createdHeight <= 432_000n &&
      g.createdHeight <= g.state.height &&
      g.sessionNonce === g.usage.attempts &&
      g.usage.attempts <= p.maxAttempts &&
      g.usage.feesPaid <= p.fee.lifetimeFeeLimit,
  );
  if (g.state.height < g.validAfterHeight || g.state.height >= g.validUntilHeight)
    requireResult(!g.usableAtObservedBlock);
  sameBytes(g.owner, owner);
  sameBytes(g.grantId, id);
  validateSessionPublicKey(keyScheme, g.publicKey);
  sameBytes(g.policyHash, policyHash(p));
  sameBytes(
    g.grantId,
    deriveGrantId(
      expected,
      owner,
      g.authEpoch,
      g.generationSequence,
      keyScheme,
      g.publicKey,
    ),
  );
  const checkBucket = (
    b: BucketState | null | undefined,
    configured: TokenBucket | undefined,
  ) => {
    requireResult(Boolean(b) === Boolean(configured));
    if (b && configured)
      requireResult(
        b.available <= configured.capacity &&
          b.lastRefillHeight >= g.createdHeight &&
          b.lastRefillHeight < g.validUntilHeight &&
          b.lastRefillHeight <= g.state.height,
      );
  };
  checkBucket(g.usage.valueBuckets[0], p.transfer.limits.valueTokenBucket);
  checkBucket(g.usage.feeBucket, p.fee.feeTokenBucket);
  // Reconstruct the complete stored value from validated views; reject disagreement.
  const w = new Writer(17_408);
  w.number(1, 16);
  w.fixed(g.grantId);
  w.fixed(g.owner);
  w.uint(g.authEpoch, 64);
  w.uint(g.generationSequence, 64);
  w.number(keyScheme, 8);
  w.fixed(g.publicKey);
  w.number(g.policyVersion, 16);
  w.fixed(g.policyHash);
  w.fixed(policyCodec.encode(p));
  for (const n of [
    g.createdHeight,
    g.validAfterHeight,
    g.validUntilHeight,
    g.sessionNonce,
  ])
    w.uint(n, 64);
  writeUsage(w, g.usage);
  w.uint(g.storageDeposit, 256);
  const canonical = w.finish();
  sameBytes(g.canonical, canonical);
  const calculatedDeposit = BigInt(canonical.length + 96) * 100_000_000_000_000n;
  requireResult(
    g.storageDeposit ===
      (calculatedDeposit > 1_000_000_000_000_000_000n
        ? calculatedDeposit
        : 1_000_000_000_000_000_000n),
  );
  return g;
}
export function nonceObservation(
  value: unknown,
  owner: Uint8Array,
  id: Uint8Array,
): SessionNonceObservation {
  const r = record(value, [
    "state",
    "owner",
    "grantId",
    "sessionNonce",
    "usableAtObservedBlock",
  ]);
  const result = {
    state: state(r.state),
    owner: wireBytes(r.owner, 20, 20),
    grantId: wireBytes(r.grantId, 32, 32),
    sessionNonce: quantity(r.sessionNonce),
    usableAtObservedBlock: boolean(r.usableAtObservedBlock),
  };
  sameBytes(result.owner, owner);
  sameBytes(result.grantId, id);
  return result;
}
export function usageObservation(
  value: unknown,
  owner: Uint8Array,
  id: Uint8Array,
): SessionUsageObservation {
  const r = record(value, ["state", "owner", "grantId", "policyHash", "usage"]);
  const result = {
    state: state(r.state),
    owner: wireBytes(r.owner, 20, 20),
    grantId: wireBytes(r.grantId, 32, 32),
    policyHash: wireBytes(r.policyHash, 32, 32),
    usage: usage(r.usage),
  };
  sameBytes(result.owner, owner);
  sameBytes(result.grantId, id);
  return result;
}
export function decodedPolicy(
  value: unknown,
  canonical: Uint8Array,
  preview: boolean,
): DecodedPolicy | PolicyPreview {
  const r = record(
    value,
    preview
      ? [
          "canonical",
          "policyHash",
          "policy",
          "enabledActions",
          "warnings",
          "securityNotice",
        ]
      : ["canonical", "policyHash", "policy"],
  );
  const p = policy(r.policy),
    result = {
      canonical: wireBytes(r.canonical, 16_384),
      policyHash: wireBytes(r.policyHash, 32, 32),
      policy: p,
    };
  sameBytes(result.canonical, canonical);
  sameBytes(result.canonical, policyCodec.encode(p));
  sameBytes(result.policyHash, policyHash(p));
  if (!preview) return result;
  const warnings: string[] = [];
  if (p.maxAttempts === (1n << 64n) - 1n)
    warnings.push("maximum attempt count is effectively unbounded");
  if (p.transfer.recipients.kind === 1)
    warnings.push("recipient authorization requires a position-bound Merkle proof");
  requireResult(
    array(r.enabledActions, 1, 1)[0] === "TRANSFER" &&
      array(r.warnings, warnings.length, warnings.length).every(
        (w, i) => w === warnings[i],
      ) &&
      r.securityNotice ===
        "Preview is derived from the same canonical bytes and hash that session signatures bind.",
  );
  return {
    ...result,
    enabledActions: ["TRANSFER"],
    warnings,
    securityNotice: r.securityNotice,
  };
}
export function toQuantity(value: bigint): string {
  return `0x${value.toString(16)}`;
}
export function inputBytes(value: Uint8Array, maximum: number): Uint8Array {
  requireResult(
    value instanceof Uint8Array && value.length > 0 && value.length <= maximum,
  );
  return new Uint8Array(value);
}
export { bytesToHex };
