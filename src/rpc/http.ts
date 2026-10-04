import { Deadline, systemClock } from "./deadline.js";
import {
  RpcClientError,
  authorizationErrorFamily,
  createRpcFailure,
  reconstructRpcFailure,
} from "./errors.js";
import { encodeRequest, parseResponse } from "./json.js";
import type {
  HttpRpcOptions,
  JsonValue,
  RpcCall,
  RpcClock,
  RpcFetch,
  RpcParams,
  RpcRequestOptions,
} from "./types.js";

const MiB = 1 << 20;
const MAX_RESPONSE_CHUNKS = 65_536;
const RETRY_STATUSES = new Set([429, 502, 503, 504]);
const aliasReads = [
  "chainId",
  "blockNumber",
  "getBalance",
  "getTransactionCount",
  "getCode",
  "getStorageAt",
  "getBlockByNumber",
  "getBlockByHash",
  "getTransactionByHash",
  "getTransactionReceipt",
  "gasPrice",
  "maxPriorityFeePerGas",
  "feeHistory",
  "syncing",
] as const;

/** Fixed allowlist; unknown methods and submission aliases are single-attempt. */
export const RETRYABLE_RPC_METHODS: readonly string[] = Object.freeze([
  ...aliasReads.flatMap((method) => [`eth_${method}`, `rsc_${method}`]),
  "rsc_getRootAuthority",
  "rsc_getSessionGrant",
  "rsc_getSessionNonce",
  "rsc_getSessionUsage",
  "rsc_getAuthorizationFinalityStatus",
  "rsc_getAuthorizationProof",
  "rsc_decodePolicy",
  "rsc_previewPolicy",
]);
const retryableMethods = new Set(RETRYABLE_RPC_METHODS);

export type RpcOutcome =
  | { readonly ok: true; readonly result: unknown }
  | { readonly ok: false; readonly error: RpcClientError };

interface Config {
  url: string;
  fetch: RpcFetch;
  clock: RpcClock;
  timeoutMs: number;
  maxRequestBytes: number;
  maxResponseBytes: number;
  maxBatchSize: number;
  maxRetries: number;
  retryDelayMs: number;
  maxRetryDelayMs: number;
}

function bounded(
  value: number | undefined,
  fallback: number,
  min: number,
  max: number,
): number {
  const result = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(result) || result < min || result > max)
    throw createRpcFailure("INVALID_OPTIONS");
  return result;
}

function configure(options: HttpRpcOptions): Config {
  try {
    const url = new URL(options.url);
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      typeof options.url !== "string"
    )
      throw new Error();
    const fetch =
      options.fetch === undefined ? globalThis.fetch?.bind(globalThis) : options.fetch;
    const clock = options.clock === undefined ? systemClock : options.clock;
    if (
      typeof fetch !== "function" ||
      typeof clock.now !== "function" ||
      typeof clock.setTimeout !== "function" ||
      typeof clock.clearTimeout !== "function"
    )
      throw new Error();
    const config = {
      url: url.href,
      fetch,
      clock,
      timeoutMs: bounded(options.timeoutMs, 10_000, 1, 120_000),
      maxRequestBytes: bounded(options.maxRequestBytes, 2 * MiB, 1, 2 * MiB),
      maxResponseBytes: bounded(options.maxResponseBytes, 2 * MiB, 1, 16 * MiB),
      maxBatchSize: bounded(options.maxBatchSize, 32, 1, 32),
      maxRetries: bounded(options.maxRetries, 2, 0, 3),
      retryDelayMs: bounded(options.retryDelayMs, 100, 1, 5_000),
      maxRetryDelayMs: bounded(options.maxRetryDelayMs, 1_000, 1, 5_000),
    };
    if (config.retryDelayMs > config.maxRetryDelayMs) throw new Error();
    return config;
  } catch {
    throw createRpcFailure("INVALID_OPTIONS");
  }
}

function discard(response: Response): void {
  try {
    void response.body?.cancel().catch(() => {});
  } catch {
    /* Best effort. */
  }
}

function object(value: JsonValue | undefined): value is Record<string, JsonValue> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function responses(
  value: JsonValue,
  ids: readonly number[],
  batch: boolean,
  attempts: number,
): RpcOutcome[] {
  const invalid = () => createRpcFailure("INVALID_RESPONSE", attempts);
  if (batch !== Array.isArray(value)) throw invalid();
  const list = batch ? (value as readonly JsonValue[]) : [value];
  if (list.length !== ids.length) throw invalid();
  const expected = new Set(ids);
  const found = new Map<number, RpcOutcome>();
  for (const item of list) {
    if (
      !object(item) ||
      !Object.hasOwn(item, "jsonrpc") ||
      !Object.hasOwn(item, "id") ||
      item.jsonrpc !== "2.0" ||
      typeof item.id !== "number" ||
      !expected.has(item.id) ||
      found.has(item.id)
    )
      throw invalid();
    const hasResult = Object.hasOwn(item, "result");
    const hasError = Object.hasOwn(item, "error");
    if (hasResult === hasError) throw invalid();
    if (hasResult) found.set(item.id, { ok: true, result: item.result });
    else {
      const error = item.error;
      if (
        !object(error) ||
        !Object.hasOwn(error, "code") ||
        !Object.hasOwn(error, "message") ||
        typeof error.code !== "number" ||
        !Number.isSafeInteger(error.code) ||
        typeof error.message !== "string"
      )
        throw invalid();
      found.set(item.id, {
        ok: false,
        error: createRpcFailure(
          "NODE_ERROR",
          attempts,
          undefined,
          error.code,
          error.code === -32000 ? authorizationErrorFamily(error.data) : undefined,
        ),
      });
    }
  }
  return ids.map((id) => found.get(id)!);
}

/** Generic envelope transport; results remain untrusted until method validation. */
export class HttpRpcClient {
  readonly #config: Config;
  #nextId = 1;

  constructor(options: HttpRpcOptions) {
    this.#config = configure(options);
  }

  async request(
    method: string,
    params: RpcParams = [],
    options: RpcRequestOptions = {},
  ): Promise<unknown> {
    const [outcome] = await this.#execute([{ method, params }], false, options);
    if (!outcome!.ok) throw outcome!.error;
    return outcome!.result;
  }

  async batch(
    calls: readonly RpcCall[],
    options: RpcRequestOptions = {},
  ): Promise<readonly RpcOutcome[]> {
    return this.#execute(calls, true, options);
  }

  async #execute(
    calls: readonly RpcCall[],
    batch: boolean,
    options: RpcRequestOptions,
  ): Promise<RpcOutcome[]> {
    const config = this.#config;
    let signal: AbortSignal | undefined;
    let aborted = false;
    try {
      if (!options || typeof options !== "object") throw new Error();
      signal = options.signal;
      if (
        signal !== undefined &&
        (typeof signal.aborted !== "boolean" ||
          typeof signal.addEventListener !== "function" ||
          typeof signal.removeEventListener !== "function")
      )
        throw new Error();
      aborted = signal?.aborted ?? false;
    } catch {
      throw createRpcFailure("INVALID_REQUEST");
    }
    if (aborted) throw createRpcFailure("ABORTED");
    const ids: number[] = [];
    const methods: string[] = [];
    let body: string;
    try {
      if (
        !Array.isArray(calls) ||
        calls.length < 1 ||
        calls.length > config.maxBatchSize
      )
        throw createRpcFailure("REQUEST_LIMIT");
      const requests = calls.map((call) => {
        if (!call || typeof call !== "object")
          throw createRpcFailure("INVALID_REQUEST");
        const methodDescriptor = Object.getOwnPropertyDescriptor(call, "method");
        const paramsDescriptor = Object.getOwnPropertyDescriptor(call, "params");
        if (
          !methodDescriptor ||
          !("value" in methodDescriptor) ||
          (paramsDescriptor && !("value" in paramsDescriptor))
        )
          throw createRpcFailure("INVALID_REQUEST");
        const method: unknown = methodDescriptor.value;
        const params: unknown =
          paramsDescriptor?.value === undefined ? [] : paramsDescriptor.value;
        if (
          typeof method !== "string" ||
          !/^[a-zA-Z][a-zA-Z0-9_.]{0,127}$/.test(method) ||
          method.startsWith("rpc.")
        )
          throw createRpcFailure("INVALID_REQUEST");
        if (!params || typeof params !== "object")
          throw createRpcFailure("INVALID_REQUEST");
        if (!Number.isSafeInteger(this.#nextId))
          throw createRpcFailure("REQUEST_LIMIT");
        const id = this.#nextId++;
        ids.push(id);
        methods.push(method);
        return { jsonrpc: "2.0", id, method, params };
      });
      body = encodeRequest(batch ? requests : requests[0], config.maxRequestBytes);
    } catch (error) {
      throw reconstructRpcFailure(error, "INVALID_REQUEST", 0, [
        "INVALID_REQUEST",
        "REQUEST_LIMIT",
      ]);
    }
    const canRetry = methods.every((method) => retryableMethods.has(method));
    let deadline: Deadline;
    try {
      deadline = new Deadline(config.clock, config.timeoutMs, signal);
    } catch (error) {
      throw reconstructRpcFailure(error, "INVALID_REQUEST", 0);
    }
    try {
      for (;;) {
        deadline.check();
        deadline.attempts++;
        try {
          const response = await this.#attempt(body, deadline);
          deadline.check();
          return responses(response, ids, batch, deadline.attempts);
        } catch (error) {
          deadline.check();
          const failure = reconstructRpcFailure(
            error,
            "NETWORK_ERROR",
            deadline.attempts,
          );
          const transient =
            failure.kind === "transport" ||
            (failure.kind === "http" && RETRY_STATUSES.has(failure.httpStatus!));
          if (!canRetry || !transient || deadline.attempts > config.maxRetries)
            throw failure;
          let delay = Math.min(
            config.retryDelayMs * 2 ** (deadline.attempts - 1),
            config.maxRetryDelayMs,
          );
          if (error !== null && typeof error === "object" && httpHints.has(error)) {
            const hinted = retryDelay(
              httpHints.get(error)!,
              delay,
              config.maxRetryDelayMs,
            );
            if (hinted === undefined) throw failure;
            delay = hinted;
          }
          await deadline.delay(delay);
        }
      }
    } catch (error) {
      throw reconstructRpcFailure(error, "NETWORK_ERROR", deadline.attempts);
    } finally {
      try {
        deadline.dispose();
      } catch (error) {
        throw reconstructRpcFailure(error, "NETWORK_ERROR", deadline.attempts);
      }
    }
  }

  async #attempt(body: string, deadline: Deadline): Promise<JsonValue> {
    const controller = new AbortController();
    const signal = deadline.controller.signal;
    const onAbort = () => controller.abort();
    signal.addEventListener("abort", onAbort, { once: true });
    try {
      deadline.check();
      let response: Response;
      try {
        const pending = this.#config.fetch(this.#config.url, {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body,
          signal: controller.signal,
          redirect: "error",
          credentials: "omit",
          cache: "no-store",
          referrerPolicy: "no-referrer",
        });
        // Dispose a response that arrives after cancellation, even with a non-cooperative injected fetch.
        void pending.then(
          (late) => {
            if (signal.aborted) discard(late);
          },
          () => {},
        );
        response = await deadline.race(pending);
      } catch {
        deadline.check();
        throw createRpcFailure("NETWORK_ERROR", deadline.attempts);
      }
      if (signal.aborted) {
        discard(response);
        deadline.check();
      }
      if (
        !response ||
        !Number.isInteger(response.status) ||
        response.status < 0 ||
        response.status > 599 ||
        typeof response.headers?.get !== "function"
      )
        throw createRpcFailure("INVALID_RESPONSE", deadline.attempts);
      if (response.status < 200 || response.status > 299) {
        discard(response);
        throw httpFailure(
          deadline.attempts,
          response.status,
          response.headers.get("Retry-After"),
        );
      }
      return parseResponse(await this.#read(response, deadline), deadline.attempts);
    } finally {
      signal.removeEventListener("abort", onAbort);
      controller.abort();
    }
  }

  async #read(response: Response, deadline: Deadline): Promise<string> {
    const limit = this.#config.maxResponseBytes;
    const declared = response.headers.get("Content-Length");
    if (declared !== null && /^\d+$/.test(declared) && Number(declared) > limit) {
      discard(response);
      throw createRpcFailure("RESPONSE_LIMIT", deadline.attempts);
    }
    if (!response.body) throw createRpcFailure("INVALID_RESPONSE", deadline.attempts);
    let reader: ReadableStreamDefaultReader<Uint8Array>;
    try {
      reader = response.body.getReader();
    } catch {
      throw createRpcFailure("INVALID_RESPONSE", deadline.attempts);
    }
    let buffer = new Uint8Array(Math.min(limit, 8_192));
    let size = 0;
    let chunks = 0;
    let complete = false;
    try {
      for (;;) {
        deadline.check();
        let part: ReadableStreamReadResult<Uint8Array>;
        try {
          part = await deadline.race(reader.read());
        } catch {
          deadline.check();
          throw createRpcFailure("NETWORK_ERROR", deadline.attempts);
        }
        if (part.done) {
          complete = true;
          break;
        }
        if (!(part.value instanceof Uint8Array))
          throw createRpcFailure("INVALID_RESPONSE", deadline.attempts);
        if (++chunks > MAX_RESPONSE_CHUNKS || part.value.byteLength > limit - size)
          throw createRpcFailure("RESPONSE_LIMIT", deadline.attempts);
        const next = size + part.value.byteLength;
        if (next > buffer.byteLength) {
          const grown = new Uint8Array(
            Math.min(limit, Math.max(next, buffer.byteLength * 2)),
          );
          grown.set(buffer.subarray(0, size));
          buffer = grown;
        }
        buffer.set(part.value, size);
        size = next;
      }
      deadline.check();
      try {
        return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
          buffer.subarray(0, size),
        );
      } catch {
        throw createRpcFailure("INVALID_JSON", deadline.attempts);
      }
    } finally {
      if (!complete) {
        try {
          void reader.cancel().catch(() => {});
        } catch {
          /* Best effort. */
        }
      }
      try {
        reader.releaseLock();
      } catch {
        /* A non-cooperative stream may retain a pending read. */
      }
    }
  }
}

const httpHints = new WeakMap<object, string | null>();
function httpFailure(
  attempts: number,
  status: number,
  retryAfter: string | null,
): RpcClientError {
  const error = createRpcFailure("HTTP_ERROR", attempts, status);
  httpHints.set(error, retryAfter);
  return error;
}
function retryDelay(
  hint: string | null,
  fallback: number,
  max: number,
): number | undefined {
  if (hint === null) return fallback;
  // Dates/invalid hints or hints beyond our bound prevent a retry.
  if (!/^\d+$/.test(hint)) return undefined;
  const milliseconds = Number(hint) * 1000;
  if (!Number.isSafeInteger(milliseconds) || milliseconds > max) return undefined;
  return Math.max(fallback, milliseconds);
}
