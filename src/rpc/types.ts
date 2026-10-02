export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

export type RpcParams = readonly JsonValue[] | { readonly [key: string]: JsonValue };

export interface RpcCall {
  readonly method: string;
  readonly params?: RpcParams;
}

export interface RpcRequestOptions {
  readonly signal?: AbortSignal;
}

export type RpcFetch = (url: string, init: RequestInit) => Promise<Response>;

/** Trusted scheduling dependency. now() is monotonic milliseconds. */
export interface RpcClock {
  now(): number;
  setTimeout(callback: () => void, delayMs: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface HttpRpcOptions {
  readonly url: string;
  readonly fetch?: RpcFetch;
  readonly clock?: RpcClock;
  /** Overall fetch/body/backoff budget, not a fresh timeout for every attempt. */
  readonly timeoutMs?: number;
  readonly maxRequestBytes?: number;
  readonly maxResponseBytes?: number;
  readonly maxBatchSize?: number;
  /** Extra attempts for the fixed read-only allowlist only. */
  readonly maxRetries?: number;
  readonly retryDelayMs?: number;
  readonly maxRetryDelayMs?: number;
}
