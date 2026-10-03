import { ownedBytes, WEBAUTHN_PARSE_LIMITS as limits } from "./errors.js";
import { parseClientDataJSON } from "./client-data.js";
import {
  parseNoneAttestationObject,
  parseAuthenticatorData,
  derToP256Signature,
} from "./parsers.js";
import { insist, representation } from "./browser-errors.js";

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
export function encodeBase64url(bytes: Uint8Array): string {
  let result = "",
    accumulator = 0,
    bits = 0;
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      result += alphabet[(accumulator >>> bits) & 63];
    }
    accumulator &= (1 << bits) - 1;
  }
  if (bits) result += alphabet[accumulator << (6 - bits)];
  return result;
}

const bufferLength = Object.getOwnPropertyDescriptor(
  ArrayBuffer.prototype,
  "byteLength",
)!.get!;
function buffer(input: unknown, maximum: number, minimum = 1): Uint8Array {
  // Native brand check accepts cross-realm ordinary ArrayBuffers, never SharedArrayBuffer.
  const length = bufferLength.call(input) as number;
  insist(length >= minimum && length <= maximum, "INVALID_RESPONSE");
  return ownedBytes(new Uint8Array(input as ArrayBuffer), maximum, minimum);
}
function object(value: unknown): Record<string, unknown> {
  insist(value !== null && typeof value === "object", "INVALID_RESPONSE");
  return value as Record<string, unknown>;
}
function common(value: unknown) {
  const credential = object(value),
    response = object(credential.response);
  insist(credential.type === "public-key", "INVALID_RESPONSE");
  const rawId = buffer(credential.rawId, limits.credentialIdBytes),
    id = encodeBase64url(rawId);
  insist(credential.id === id, "INVALID_RESPONSE");
  insist(
    typeof credential.getClientExtensionResults === "function",
    "INVALID_RESPONSE",
  );
  const extensions = object(credential.getClientExtensionResults());
  insist(Reflect.ownKeys(extensions).length === 0, "INVALID_RESPONSE");
  const attachment = credential.authenticatorAttachment;
  insist(
    attachment === undefined ||
      attachment === null ||
      attachment === "platform" ||
      attachment === "cross-platform",
    "INVALID_RESPONSE",
  );
  const client = parseClientDataJSON(
    buffer(response.clientDataJSON, limits.clientDataBytes),
  );
  insist(!client.crossOrigin && client.topOrigin === undefined, "INVALID_RESPONSE");
  return {
    credential,
    response,
    rawId,
    client,
    base: {
      id,
      rawId: id,
      type: "public-key" as const,
      clientExtensionResults: Object.freeze({}),
      ...(attachment === undefined
        ? {}
        : { authenticatorAttachment: attachment as AuthenticatorAttachment | null }),
    },
  };
}
export interface SerializedPasskeyRegistration {
  readonly id: string;
  readonly rawId: string;
  readonly type: "public-key";
  readonly authenticatorAttachment?: AuthenticatorAttachment | null;
  readonly clientExtensionResults: Readonly<Record<string, never>>;
  readonly response: {
    readonly clientDataJSON: string;
    readonly attestationObject: string;
    readonly transports: readonly AuthenticatorTransport[];
  };
}
export interface SerializedPasskeyAssertion {
  readonly id: string;
  readonly rawId: string;
  readonly type: "public-key";
  readonly authenticatorAttachment?: AuthenticatorAttachment | null;
  readonly clientExtensionResults: Readonly<Record<string, never>>;
  readonly response: {
    readonly clientDataJSON: string;
    readonly authenticatorData: string;
    readonly signature: string;
    readonly userHandle: string | null;
  };
}
const transports = new Set(["usb", "nfc", "ble", "internal", "hybrid", "smart-card"]);

/** Public transport data only. Registration is awaiting key-possession proof at the RP. */
export function serializePasskeyRegistration(
  value: unknown,
): SerializedPasskeyRegistration {
  return representation(() => {
    const { response, rawId, client, base } = common(value);
    insist(client.type === "webauthn.create", "INVALID_RESPONSE");
    const bytes = buffer(response.attestationObject, limits.attestationObjectBytes),
      parsed = parseNoneAttestationObject(bytes);
    const credentialId = parsed.authenticator.credential!.credentialId;
    insist(
      encodeBase64url(credentialId) === encodeBase64url(rawId),
      "INVALID_RESPONSE",
    );
    insist(
      parsed.authenticator.userPresent && parsed.authenticator.userVerified,
      "INVALID_RESPONSE",
    );
    const observed =
      typeof response.getTransports === "function"
        ? (response.getTransports() as unknown)
        : [];
    insist(Array.isArray(observed), "INVALID_RESPONSE");
    const count = observed.length;
    insist(Number.isSafeInteger(count) && count >= 0 && count <= 8, "INVALID_RESPONSE");
    const copied: AuthenticatorTransport[] = [];
    for (let index = 0; index < count; index++) {
      const transport = observed[index];
      insist(
        typeof transport === "string" &&
          transports.has(transport) &&
          !copied.includes(transport as AuthenticatorTransport),
        "INVALID_RESPONSE",
      );
      copied.push(transport as AuthenticatorTransport);
    }
    return Object.freeze({
      ...base,
      response: Object.freeze({
        clientDataJSON: encodeBase64url(client.original),
        attestationObject: encodeBase64url(bytes),
        transports: Object.freeze(copied),
      }),
    });
  });
}

/** Does not verify the signature, account binding, RP, challenge, expiry or counter. */
export function serializePasskeyAssertion(value: unknown): SerializedPasskeyAssertion {
  return representation(() => {
    const { response, client, base } = common(value);
    insist(client.type === "webauthn.get", "INVALID_RESPONSE");
    const auth = parseAuthenticatorData(
      buffer(response.authenticatorData, limits.authenticatorDataBytes),
      "authentication",
    );
    insist(auth.userPresent && auth.userVerified, "INVALID_RESPONSE");
    const signature = buffer(response.signature, limits.derSignatureBytes);
    derToP256Signature(signature);
    const userHandle =
      response.userHandle === null
        ? null
        : encodeBase64url(buffer(response.userHandle, 64));
    return Object.freeze({
      ...base,
      response: Object.freeze({
        clientDataJSON: encodeBase64url(client.original),
        authenticatorData: encodeBase64url(auth.original),
        signature: encodeBase64url(signature),
        userHandle,
      }),
    });
  });
}
