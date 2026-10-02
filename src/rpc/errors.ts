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

export type AuthorizationErrorFamily =
  | "AUTH_MALFORMED"
  | "AUTH_UNKNOWN_CREDENTIAL"
  | "AUTH_UNSUPPORTED_VERSION"
  | "AUTH_LIMIT_EXCEEDED"
  | "AUTH_ACTION_DENIED"
  | "AUTH_BAD_SIGNATURE";

/** Only fixed known family tokens survive; arbitrary node data is discarded. */
export function authorizationErrorFamily(
  data: unknown,
): AuthorizationErrorFamily | undefined {
  if (
    data === null ||
    typeof data !== "object" ||
    Array.isArray(data) ||
    !Object.hasOwn(data, "family")
  )
    return undefined;
  const family = (data as Record<string, unknown>).family;
  return typeof family === "string" &&
    [
      "AUTH_MALFORMED",
      "AUTH_UNKNOWN_CREDENTIAL",
      "AUTH_UNSUPPORTED_VERSION",
      "AUTH_LIMIT_EXCEEDED",
      "AUTH_ACTION_DENIED",
      "AUTH_BAD_SIGNATURE",
    ].includes(family)
    ? (family as AuthorizationErrorFamily)
    : undefined;
}

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
    readonly authorizationFamily: AuthorizationErrorFamily | undefined = undefined,
  ) {
    const [kind, message] = definitions[code];
    super(message);
    this.kind = kind;
    this.requestMayHaveReachedNode = attempts > 0;
  }
}
