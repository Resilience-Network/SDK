export type RpcErrorKind =
  | "input"
  | "limit"
  | "transport"
  | "http"
  | "parse"
  | "protocol"
  | "node"
  | "cancelled"
  | "timeout";

const definitions = {
  INVALID_OPTIONS: ["input", "Invalid RPC transport options."],
  INVALID_REQUEST: ["input", "Invalid RPC request."],
  REQUEST_LIMIT: ["limit", "RPC request exceeds a configured limit."],
  RESPONSE_LIMIT: ["limit", "RPC response exceeds a configured limit."],
  NETWORK_ERROR: ["transport", "RPC transport failed."],
  HTTP_ERROR: ["http", "RPC endpoint returned an unsuccessful HTTP status."],
  INVALID_JSON: ["parse", "RPC response is not supported JSON."],
  INVALID_RESPONSE: ["protocol", "Invalid JSON-RPC response envelope."],
  NODE_ERROR: ["node", "RPC node returned an error."],
  ABORTED: ["cancelled", "RPC request was cancelled."],
  TIMEOUT: ["timeout", "RPC request exceeded its deadline."],
} as const satisfies Record<string, readonly [RpcErrorKind, string]>;

export type RpcErrorCode = keyof typeof definitions;

/** Diagnostics deliberately exclude endpoints, payloads, remote messages and causes. */
export class RpcClientError extends Error {
  override readonly name = "RpcClientError";
  readonly kind: RpcErrorKind;
  readonly requestMayHaveReachedNode: boolean;

  constructor(
    readonly code: RpcErrorCode,
    readonly attempts: number = 0,
    readonly httpStatus: number | undefined = undefined,
    readonly rpcCode: number | undefined = undefined,
  ) {
    const [kind, message] = definitions[code];
    super(message);
    this.kind = kind;
    this.requestMayHaveReachedNode = attempts > 0;
  }
}
