import { p256 } from "@noble/curves/nist.js";
import { readCbor } from "./cbor.js";
import {
  demand,
  guarded,
  ownedBytes,
  WEBAUTHN_PARSE_LIMITS as limits,
} from "./errors.js";

export type WebAuthnCeremony = "registration" | "authentication";

export interface ParsedP256PublicKey {
  readonly algorithm: -7;
  readonly publicKey: Uint8Array;
  readonly coseKey: Uint8Array;
}

export interface ParsedAuthenticatorData {
  readonly original: Uint8Array;
  readonly rpIdHash: Uint8Array;
  readonly flags: number;
  readonly userPresent: boolean;
  readonly userVerified: boolean;
  readonly backupEligible: boolean;
  readonly backupState: boolean;
  readonly signCount: number;
  readonly credential?: {
    readonly aaguid: Uint8Array;
    readonly credentialId: Uint8Array;
    readonly key: ParsedP256PublicKey;
  };
}

function cose(input: Uint8Array): ParsedP256PublicKey {
  const value = readCbor(input);
  demand(value instanceof Map && value.size === 5, "UNSUPPORTED_COSE");
  demand(
    value.get(1) === 2 && value.get(3) === -7 && value.get(-1) === 1,
    "UNSUPPORTED_COSE",
  );
  const x = value.get(-2),
    y = value.get(-3);
  demand(
    x instanceof Uint8Array &&
      x.length === 32 &&
      y instanceof Uint8Array &&
      y.length === 32,
    "UNSUPPORTED_COSE",
  );
  const point = new Uint8Array(65);
  point[0] = 4;
  point.set(x, 1);
  point.set(y, 33);
  try {
    p256.Point.fromBytes(point).assertValidity();
  } catch {
    demand(false, "INVALID_POINT");
  }
  return { algorithm: -7, publicKey: point.slice(1), coseKey: input.slice() };
}

/** Representation parsing only; this does not verify a ceremony or key possession. */
export function parseCoseP256PublicKey(input: Uint8Array): ParsedP256PublicKey {
  return guarded(() => cose(ownedBytes(input, limits.coseKeyBytes)));
}

export function parseAuthenticatorData(
  input: Uint8Array,
  ceremony: WebAuthnCeremony,
): ParsedAuthenticatorData {
  return guarded(() => {
    demand(
      ceremony === "registration" || ceremony === "authentication",
      "INVALID_ARGUMENT",
    );
    const original = ownedBytes(input, limits.authenticatorDataBytes, 37),
      flags = original[32]!,
      attested = (flags & 0x40) !== 0,
      backupEligible = (flags & 8) !== 0,
      backupState = (flags & 16) !== 0;
    demand((flags & 0x22) === 0, "INVALID_AUTHENTICATOR_DATA");
    demand(!backupState || backupEligible, "INVALID_AUTHENTICATOR_DATA");
    demand((flags & 0x80) === 0, "UNSUPPORTED_EXTENSION");
    demand(attested === (ceremony === "registration"), "INVALID_AUTHENTICATOR_DATA");
    const result = {
      original,
      rpIdHash: original.slice(0, 32),
      flags,
      userPresent: (flags & 1) !== 0,
      userVerified: (flags & 4) !== 0,
      backupEligible,
      backupState,
      signCount: new DataView(original.buffer).getUint32(33, false),
    };
    if (!attested) {
      demand(original.length === 37, "INVALID_AUTHENTICATOR_DATA");
      return result;
    }
    demand(original.length >= 55, "INVALID_AUTHENTICATOR_DATA");
    const length = new DataView(original.buffer).getUint16(53, false);
    demand(length > 0, "INVALID_AUTHENTICATOR_DATA");
    demand(length <= limits.credentialIdBytes, "LIMIT_EXCEEDED");
    demand(55 + length < original.length, "INVALID_AUTHENTICATOR_DATA");
    const keyBytes = original.slice(55 + length);
    demand(keyBytes.length <= limits.coseKeyBytes, "LIMIT_EXCEEDED");
    return {
      ...result,
      credential: {
        aaguid: original.slice(37, 53),
        credentialId: original.slice(55, 55 + length),
        key: cose(keyBytes),
      },
    };
  });
}

export interface ParsedNoneAttestation {
  readonly format: "none";
  readonly authenticator: ParsedAuthenticatorData;
}

/** No attestation trust or key-possession claim follows from a `none` object. */
export function parseNoneAttestationObject(input: Uint8Array): ParsedNoneAttestation {
  return guarded(() => {
    const object = readCbor(ownedBytes(input, limits.attestationObjectBytes));
    demand(object instanceof Map && object.size === 3, "UNSUPPORTED_ATTESTATION");
    demand(object.get("fmt") === "none", "UNSUPPORTED_ATTESTATION");
    const statement = object.get("attStmt"),
      data = object.get("authData");
    demand(statement instanceof Map && statement.size === 0, "UNSUPPORTED_ATTESTATION");
    demand(data instanceof Uint8Array, "UNSUPPORTED_ATTESTATION");
    return {
      format: "none",
      authenticator: parseAuthenticatorData(data, "registration"),
    };
  });
}

/** Strict DER -> r||s conversion only; the signature's message/domain is unchanged. */
export function derToP256Signature(input: Uint8Array): Uint8Array {
  return guarded(() => {
    const der = ownedBytes(input, limits.derSignatureBytes, 8);
    demand(der[0] === 0x30 && der[1] === der.length - 2, "INVALID_DER");
    let offset = 2;
    const output = new Uint8Array(64);
    for (const position of [0, 32]) {
      demand(der[offset++] === 2, "INVALID_DER");
      const length = der[offset++]!;
      demand(
        length >= 1 && length <= 33 && offset + length <= der.length,
        "INVALID_DER",
      );
      const encoded = der.subarray(offset, offset + length);
      offset += length;
      demand((encoded[0]! & 0x80) === 0, "INVALID_DER");
      let scalar = encoded;
      if (encoded[0] === 0 && encoded.length > 1) {
        demand((encoded[1]! & 0x80) !== 0, "INVALID_DER");
        scalar = encoded.subarray(1);
      }
      demand(scalar.length <= 32, "INVALID_DER");
      let value = 0n;
      for (const byte of scalar) value = (value << 8n) | BigInt(byte);
      demand(value > 0n && value < p256.Point.Fn.ORDER, "INVALID_DER");
      output.set(scalar, position + 32 - scalar.length);
    }
    demand(offset === der.length, "INVALID_DER");
    return output;
  });
}
