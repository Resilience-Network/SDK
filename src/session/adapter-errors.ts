/** Classification is observation of hostile adapter data, not trusted metadata. */
export function adapterErrorCode<Code extends string>(
  error: unknown,
  kind: abstract new (...args: never[]) => Error,
  codes: ReadonlySet<string>,
): Code | undefined {
  try {
    if (error instanceof kind) {
      const code = (error as Error & { code?: unknown }).code;
      if (typeof code === "string" && codes.has(code)) return code as Code;
    }
  } catch {}
  return undefined;
}
