import type { AuthorizationFinalityStatus, RpcContractErrorCode } from "./contracts.js";
import type { RpcErrorCode, AuthorizationErrorFamily } from "./errors.js";
import type { ReceiptObservation, TransactionReceipt } from "./receipts.js";
import type { RpcRequestOptions } from "./types.js";

export interface SubmissionDiagnostic {
  readonly code: RpcErrorCode | RpcContractErrorCode;
  readonly rpcCode?: number;
  readonly authorizationFamily?: AuthorizationErrorFamily;
}
export interface SubmissionOutcome {
  readonly transactionHash: Uint8Array;
  readonly status: "reported-accepted" | "reported-rejected" | "unknown" | "not-sent";
  readonly sendAttempts: 0 | 1;
  readonly verification: "node-observation";
  readonly diagnostic?: SubmissionDiagnostic;
}
export interface ReconcileOptions extends RpcRequestOptions {
  /** Overall reconciliation budget, 1–300,000 ms; default 30,000. */
  readonly timeoutMs?: number;
  /** Logical poll count, 1–1,000; default 10. HTTP read/context retry bounds also apply. */
  readonly maxPolls?: number;
  /** Delay between polls, 1–60,000 ms; default 250. */
  readonly pollIntervalMs?: number;
}
export interface AuthorityNonceObservation {
  readonly identity: AuthorizationFinalityStatus;
  readonly mode: 0 | 1 | 2;
  readonly expectedNonce: bigint;
  readonly observedNonce: bigint | null;
  readonly authorityMatches: boolean;
  readonly comparison: "unchanged" | "advanced" | "behind" | "authority-changed";
  readonly sponsor: {
    readonly expectedNonce: bigint;
    readonly observedNonce: bigint;
  } | null;
}
export type ReconciliationOutcome = {
  readonly transactionHash: Uint8Array;
  readonly verification: "node-observation";
  readonly polls: number;
  readonly authority: AuthorityNonceObservation | null;
} & (
  | {
      readonly status: "reported-finalized-success" | "reported-finalized-failure";
      readonly receipt: TransactionReceipt;
      readonly identity: AuthorizationFinalityStatus;
    }
  | {
      readonly status: "unknown";
      readonly reason: "poll-limit" | "deadline" | "aborted" | "observation-error";
      readonly lastObservation: ReceiptObservation | null;
      readonly diagnostic?: SubmissionDiagnostic;
    }
);
