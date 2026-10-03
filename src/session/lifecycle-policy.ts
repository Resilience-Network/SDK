import {
  checkedUint,
  compareBytes,
  fixedBytes,
  isZero,
  objectFields,
  requireCondition,
} from "../core/bytes.js";
import { createGrantCodec } from "./actions.js";
import { policyCodec } from "./policy.js";
import { recipientProofCodec } from "./root.js";
import { recipientLeafHash, recipientNodeHash } from "./hash.js";
import type {
  GrantSpec,
  ChainContext,
  RecipientProof,
  TxIntent,
  TokenBucket,
} from "./types.js";
import type { FundedGrantSnapshot, BucketState } from "../rpc/contracts.js";
export const MINIMUM_SECURITY_RESERVE = 100_000_000_000_000_000n;
export const MAX_SESSION_LIFETIME_BLOCKS = 432_000n;
export type GrantParameters = Omit<GrantSpec, "storageDeposit">;
/** Exact pinned stored-grant + trie/index size; transfer-only policy grammar. */
export function requiredGrantStorageDeposit(parameters: GrantParameters): bigint {
  const encoded = createGrantCodec.encode({
    version: 1,
    grant: { ...parameters, storageDeposit: 1n },
  });
  const policy = policyCodec.decode(policyCodec.encode(parameters.policy));
  // Stored grant adds 118 bytes to action-data layout, plus canonical initial usage.
  // usage: attempts/successes/claims(24), six uint256 totals(192), count(2), fee-tag(1), optional buckets.
  const usageSize =
    219 +
    (policy.transfer.limits.valueTokenBucket ? 41 : 0) +
    (policy.fee.feeTokenBucket ? 40 : 0);
  const deposit = BigInt(encoded.length + 118 + usageSize + 96) * 100_000_000_000_000n;
  return deposit > 1_000_000_000_000_000_000n ? deposit : 1_000_000_000_000_000_000n;
}
function same(a: Uint8Array, b: Uint8Array): boolean {
  return compareBytes(a, b) === 0;
}
function add(a: bigint, b: bigint): bigint {
  return checkedUint(a + b, 256);
}
export function refilledBucketAvailable(
  config: TokenBucket,
  state: BucketState,
  height: bigint,
): bigint {
  objectFields(config, ["capacity", "refillPerBlock"]);
  objectFields(state, ["available", "lastRefillHeight"]);
  checkedUint(config.capacity, 256);
  checkedUint(config.refillPerBlock, 256);
  checkedUint(state.available, 256);
  checkedUint(state.lastRefillHeight, 64);
  checkedUint(height, 64);
  requireCondition(height >= state.lastRefillHeight, "Bucket refill height regressed");
  const refill = checkedUint(
    config.refillPerBlock * (height - state.lastRefillHeight),
    256,
  );
  const available = add(state.available, refill);
  return available > config.capacity ? config.capacity : available;
}
export function checkTransferRecipient(
  context: ChainContext,
  intent: TxIntent,
  snapshot: FundedGrantSnapshot,
  proof?: RecipientProof,
): void {
  const set = snapshot.grant.policy.transfer.recipients;
  if (set.kind === 0) {
    requireCondition(proof === undefined, "Unused recipient proof");
    requireCondition(
      set.recipients.some((r) => same(r, intent.destination)),
      "Recipient is outside grant",
    );
    return;
  }
  requireCondition(proof !== undefined, "Missing recipient proof");
  recipientProofCodec.encode(proof);
  requireCondition(
    proof.leafCount === set.leafCount && proof.leafIndex < proof.leafCount,
    "Recipient proof identity mismatch",
  );
  let hash = recipientLeafHash(context, 0, intent.destination);
  for (let level = 0; level < proof.siblings.length; level++) {
    const sibling = fixedBytes(proof.siblings[level]!, 32);
    hash =
      ((proof.leafIndex >>> level) & 1) === 0
        ? recipientNodeHash(context, 0, hash, sibling)
        : recipientNodeHash(context, 0, sibling, hash);
  }
  requireCondition(same(hash, set.merkleRoot), "Recipient proof root mismatch");
}
/** Advisory pre-sign screening at candidate height; native execution is authoritative. */
export function checkSessionTransfer(
  context: ChainContext,
  intent: TxIntent,
  snapshot: FundedGrantSnapshot,
  proof?: RecipientProof,
): void {
  const { root, grant: g, balance } = snapshot,
    p = g.policy,
    height = checkedUint(snapshot.identity.state.height + 1n, 64);
  requireCondition(
    root.authorizationMode === 1 &&
      g.authEpoch === root.authority.authEpoch &&
      g.usableAtObservedBlock &&
      height < g.validUntilHeight,
    "Grant is not active for candidate height",
  );
  requireCondition(
    intent.actionType === 0 && isZero(intent.sponsor) && same(intent.sender, g.owner),
    "Unsupported session transfer context",
  );
  requireCondition(
    g.sessionNonce < (1n << 64n) - 1n && g.usage.attempts < p.maxAttempts,
    "Grant attempt/nonce exhausted",
  );
  const maximumFee = checkedUint(intent.gasLimit * intent.maxFeePerGas, 256);
  requireCondition(
    intent.gasLimit <= p.fee.maxGasLimit &&
      intent.maxFeePerGas <= p.fee.maxGasPrice &&
      maximumFee <= p.fee.maxFeePerTransaction &&
      add(g.usage.feesPaid, maximumFee) <= p.fee.lifetimeFeeLimit,
    "Grant fee budget exceeded",
  );
  if (p.fee.feeTokenBucket) {
    requireCondition(g.usage.feeBucket !== null, "Missing fee bucket");
    requireCondition(
      maximumFee <=
        refilledBucketAvailable(p.fee.feeTokenBucket, g.usage.feeBucket, height),
      "Fee bucket exhausted",
    );
  }
  checkTransferRecipient(context, intent, snapshot, proof);
  requireCondition(
    (intent.value !== 0n || p.transfer.allowZeroValue) &&
      (!same(intent.sender, intent.destination) || p.transfer.allowSelfTransfer),
    "Zero/self transfer denied",
  );
  const limits = p.transfer.limits;
  requireCondition(
    intent.value <= limits.maxPerTransaction &&
      add(g.usage.externalValueSpent, intent.value) <= limits.lifetimeLimit,
    "Transfer value budget exceeded",
  );
  if (limits.valueTokenBucket) {
    const state = g.usage.valueBuckets[0];
    requireCondition(state !== undefined, "Missing transfer bucket");
    requireCondition(
      intent.value <=
        refilledBucketAvailable(
          limits.valueTokenBucket,
          { available: state.available, lastRefillHeight: state.lastRefillHeight },
          height,
        ),
      "Transfer bucket exhausted",
    );
  }
  const debit = add(maximumFee, intent.value);
  requireCondition(
    balance >= root.authority.securityReserve &&
      balance - root.authority.securityReserve >= debit,
    "Transfer would cross security reserve",
  );
}
