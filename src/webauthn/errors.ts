export type WebAuthnParseErrorCode =
  | "INVALID_ARGUMENT"
  | "LIMIT_EXCEEDED"
  | "INVALID_CBOR"
  | "UNSUPPORTED_COSE"
  | "INVALID_POINT"
  | "INVALID_AUTHENTICATOR_DATA"
  | "UNSUPPORTED_EXTENSION"
  | "UNSUPPORTED_ATTESTATION"
  | "INVALID_CLIENT_DATA"
  | "INVALID_DER";

export class WebAuthnParseError extends Error {
  constructor(public readonly code: WebAuthnParseErrorCode) {
    super("Invalid or unsupported WebAuthn representation");
    this.name = "WebAuthnParseError";
  }
}

export function demand(
  condition: unknown,
  code: WebAuthnParseErrorCode,
): asserts condition {
  if (!condition) throw new WebAuthnParseError(code);
}

export function guarded<T>(work: () => T): T {
  try {
    return work();
  } catch (error) {
    if (error instanceof WebAuthnParseError) throw error;
    throw new WebAuthnParseError("INVALID_ARGUMENT");
  }
}

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object,
  arrayLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, "length")!.get!,
  arrayBuffer = Object.getOwnPropertyDescriptor(typedArrayPrototype, "buffer")!.get!,
  bufferLength = Object.getOwnPropertyDescriptor(
    ArrayBuffer.prototype,
    "byteLength",
  )!.get!;

export function ownedBytes(input: Uint8Array, maximum: number, minimum = 1) {
  demand(input instanceof Uint8Array, "INVALID_ARGUMENT");
  // Intrinsics ignore shadow properties and reject proxies/shared backing stores.
  const length = arrayLength.call(input) as number;
  bufferLength.call(arrayBuffer.call(input));
  demand(length <= maximum, "LIMIT_EXCEEDED");
  demand(length >= minimum, "INVALID_ARGUMENT");
  // Uint8Array construction copies Buffer too; Buffer.slice would alias input.
  return new Uint8Array(input);
}

export const WEBAUTHN_PARSE_LIMITS = Object.freeze({
  clientDataBytes: 8192,
  authenticatorDataBytes: 8192,
  attestationObjectBytes: 16384,
  credentialIdBytes: 1023,
  coseKeyBytes: 1024,
  derSignatureBytes: 72,
  challengeBytes: 1024,
  cborDepth: 4,
  cborItems: 128,
  cborContainerEntries: 32,
  jsonDepth: 4,
  jsonItems: 128,
  jsonContainerEntries: 32,
});
