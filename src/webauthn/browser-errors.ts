export type WebAuthnBrowserErrorCode =
  | "INVALID_ARGUMENT"
  | "INVALID_CONTEXT"
  | "UNSUPPORTED"
  | "CANCELLED"
  | "TIMEOUT"
  | "DENIED_OR_UNAVAILABLE"
  | "ALREADY_REGISTERED"
  | "INVALID_RESPONSE"
  | "BROWSER_FAILED";

const sanitizedCodes = new Set<string>([
  "INVALID_ARGUMENT",
  "INVALID_CONTEXT",
  "UNSUPPORTED",
  "CANCELLED",
  "TIMEOUT",
  "DENIED_OR_UNAVAILABLE",
  "ALREADY_REGISTERED",
  "INVALID_RESPONSE",
  "BROWSER_FAILED",
]);

export class WebAuthnBrowserError extends Error {
  constructor(public readonly code: WebAuthnBrowserErrorCode) {
    super("WebAuthn ceremony failed");
    this.name = "WebAuthnBrowserError";
  }
}

export function insist(
  condition: unknown,
  code: WebAuthnBrowserErrorCode,
): asserts condition {
  if (!condition) throw new WebAuthnBrowserError(code);
}

export function browserFailure(
  error: unknown,
  fallback: WebAuthnBrowserErrorCode = "BROWSER_FAILED",
): WebAuthnBrowserError {
  try {
    if (error instanceof WebAuthnBrowserError) {
      const code = error.code;
      return new WebAuthnBrowserError(
        typeof code === "string" && sanitizedCodes.has(code) ? code : fallback,
      );
    }
    const name = (error as { name?: unknown } | null)?.name;
    const codes: Record<string, WebAuthnBrowserErrorCode> = {
      AbortError: "CANCELLED",
      NotAllowedError: "DENIED_OR_UNAVAILABLE",
      NotSupportedError: "UNSUPPORTED",
      SecurityError: "INVALID_CONTEXT",
      InvalidStateError: "ALREADY_REGISTERED",
    };
    return new WebAuthnBrowserError(
      typeof name === "string" && Object.hasOwn(codes, name) ? codes[name]! : fallback,
    );
  } catch {
    return new WebAuthnBrowserError(fallback);
  }
}

export function representation<T>(work: () => T): T {
  try {
    return work();
  } catch (error) {
    throw browserFailure(error, "INVALID_RESPONSE");
  }
}
