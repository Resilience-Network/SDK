import type { ChainContext, Policy, RootConfig, Scheme } from "../session/types.js";
import type { HttpRpcOptions } from "./types.js";

export const AUTHORIZATION_CAPABILITY = "resilience/tx-auth/2" as const;

/** Supply all identity fields from trusted deployment configuration. */
export interface ExpectedChainIdentity extends ChainContext {
  readonly authorizationCapability: typeof AUTHORIZATION_CAPABILITY;
}
export interface ChainRpcOptions extends HttpRpcOptions {
  readonly expected: ExpectedChainIdentity;
  /** Extra whole-read refreshes on changing finalized context only; 0–3. */
  readonly maxContextRefreshes?: number;
}
export interface FinalizedState {
  readonly blockHash: Uint8Array;
  readonly height: bigint;
  readonly stateRoot: Uint8Array;
  readonly finality: "finalized";
}
export interface AuthorizationFinalityStatus extends ExpectedChainIdentity {
  readonly state: FinalizedState;
}
export interface RootAuthority {
  readonly canonical: Uint8Array;
  readonly version: 1;
  readonly authEpoch: bigint;
  readonly rootNonce: bigint;
  readonly nextGrantSequence: bigint;
  readonly activeGrantCount: number;
  readonly securityReserve: bigint;
  readonly rootConfigHash: Uint8Array;
  readonly rootConfig: RootConfig;
}
export type RootAuthorityObservation = {
  readonly state: FinalizedState;
  readonly owner: Uint8Array;
  readonly authorizationRoot: Uint8Array;
} & (
  | { readonly authorizationMode: 0; readonly authority: null }
  | { readonly authorizationMode: 1; readonly authority: RootAuthority }
);
/** Root/account nonce/balance from one consistent trusted-node finalized bracket. */
export interface AccountAuthorizationSnapshot {
  readonly identity: AuthorizationFinalityStatus;
  readonly root: RootAuthorityObservation;
  readonly accountNonce: bigint;
  readonly balance: bigint;
}
export interface BucketState {
  readonly available: bigint;
  readonly lastRefillHeight: bigint;
}
export interface UsageCounters {
  readonly attempts: bigint;
  readonly successes: bigint;
  readonly externalValueSpent: bigint;
  readonly stakeValueLocked: bigint;
  readonly delegationValueLocked: bigint;
  readonly valueUnlocked: bigint;
  readonly rewardsClaimed: bigint;
  readonly feesPaid: bigint;
  readonly claims: bigint;
  readonly valueBuckets: readonly (BucketState & { readonly action: "TRANSFER" })[];
  readonly feeBucket: BucketState | null;
}
export interface SessionGrantObservation {
  readonly state: FinalizedState;
  readonly owner: Uint8Array;
  readonly grantId: Uint8Array;
  readonly canonical: Uint8Array;
  readonly authEpoch: bigint;
  readonly generationSequence: bigint;
  readonly keyScheme: Scheme;
  readonly publicKey: Uint8Array;
  readonly policyVersion: 1;
  readonly policyHash: Uint8Array;
  readonly policy: Policy;
  readonly createdHeight: bigint;
  readonly validAfterHeight: bigint;
  readonly validUntilHeight: bigint;
  readonly sessionNonce: bigint;
  readonly usage: UsageCounters;
  readonly storageDeposit: bigint;
  readonly activeIndexPresent: true;
  readonly usableAtObservedBlock: boolean;
}
/** Root/grant/balance observed in one finalized bracket; no independent proof. */
export interface FundedGrantSnapshot {
  readonly identity: AuthorizationFinalityStatus;
  readonly root: RootAuthorityObservation;
  readonly grant: SessionGrantObservation;
  readonly balance: bigint;
}
export interface SessionNonceObservation {
  readonly state: FinalizedState;
  readonly owner: Uint8Array;
  readonly grantId: Uint8Array;
  readonly sessionNonce: bigint;
  readonly usableAtObservedBlock: boolean;
}
export interface SessionUsageObservation {
  readonly state: FinalizedState;
  readonly owner: Uint8Array;
  readonly grantId: Uint8Array;
  readonly policyHash: Uint8Array;
  readonly usage: UsageCounters;
}
export interface AuthorizationSnapshot {
  readonly identity: AuthorizationFinalityStatus;
  readonly root: RootAuthorityObservation;
  readonly grant: SessionGrantObservation;
  readonly nonce: SessionNonceObservation;
  readonly usage: SessionUsageObservation;
}
export interface DecodedPolicy {
  readonly canonical: Uint8Array;
  readonly policyHash: Uint8Array;
  readonly policy: Policy;
}
export interface PolicyPreview extends DecodedPolicy {
  readonly enabledActions: readonly ["TRANSFER"];
  readonly warnings: readonly string[];
  readonly securityNotice: string;
}
/** Context brackets the query; fee handlers themselves do not report a state. */
export interface FeeSuggestions {
  readonly identity: AuthorizationFinalityStatus;
  readonly gasPrice: bigint;
  readonly maxPriorityFeePerGas: bigint;
  readonly advisory: true;
}
export interface FeeHistoryRequest {
  readonly blockCount: number;
  readonly newestBlock: bigint | "latest";
  readonly rewardPercentiles?: readonly number[];
}
export interface FeeHistory {
  readonly identity: AuthorizationFinalityStatus;
  readonly oldestBlock: bigint;
  readonly baseFeePerGas: readonly bigint[];
  readonly gasUsedRatio: readonly number[];
  readonly reward: readonly (readonly bigint[])[];
  readonly advisory: true;
}
export interface AuthorizationGasEstimate {
  readonly state: FinalizedState;
  readonly authorizationGas: bigint;
  readonly candidateHeight: bigint;
  readonly warning: string;
  readonly advisory: true;
}
export interface AuthorizedSimulation {
  readonly state: FinalizedState;
  readonly transactionHash: Uint8Array;
  readonly authorized: true;
  readonly candidateHeight: bigint;
  readonly actionStatus: 0 | 1;
  readonly failureCode: number;
  readonly gasUsed: bigint;
  readonly authorizationGasUsed: bigint;
  readonly actualFee: bigint;
  readonly burnedFee: bigint;
  readonly effectiveGasPrice: bigint;
  readonly sponsor: Uint8Array;
  readonly counterDeltaHash: Uint8Array;
  readonly eventsRoot: Uint8Array;
  readonly authorizationEvents: readonly {
    readonly type: number;
    readonly data: Uint8Array;
  }[];
  readonly contractAddress: Uint8Array;
  readonly warning: string;
  readonly advisory: true;
}

const messages = {
  INVALID_ARGUMENT: "Invalid typed RPC argument or options.",
  INVALID_RESULT: "RPC result violates the pinned method contract.",
  UNSUPPORTED_RESULT: "RPC result uses an unsupported protocol feature or version.",
  CHAIN_IDENTITY_MISMATCH:
    "RPC chain identity or authorization capability differs from expected configuration.",
  STATE_CONTEXT_MISMATCH: "RPC observations have inconsistent finalized state context.",
  OBSERVATION_ABORTED: "Typed RPC observation was cancelled.",
  OBSERVATION_TIMEOUT: "Typed RPC observation exceeded its overall deadline.",
} as const;
export type RpcContractErrorCode = keyof typeof messages;

/** No raw results, canonical payloads, remote text, endpoints or causes. */
export class RpcContractError extends Error {
  override readonly name = "RpcContractError";
  constructor(readonly code: RpcContractErrorCode) {
    super(messages[code]);
  }
}
