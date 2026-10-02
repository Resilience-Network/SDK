import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import {
  CodecError,
  fixedBytes,
  requireCondition,
  compareBytes,
  objectFields,
} from "../core/bytes.js";
import { domainHash } from "../core/hash.js";
import type { RootKey, Scheme } from "./types.js";

export function sessionPublicKeyBytes(scheme: Scheme, key: Uint8Array): Uint8Array {
  requireCondition(
    scheme === 1 || scheme === 2,
    "Unsupported session key scheme",
    "UNSUPPORTED_FEATURE",
  );
  return fixedBytes(key, scheme === 1 ? 32 : 64);
}

export function validateSessionPublicKey(scheme: Scheme, key: Uint8Array): void {
  const bytes = sessionPublicKeyBytes(scheme, key);
  try {
    if (scheme === 1) {
      const point = ed25519.Point.fromBytes(bytes, false);
      requireCondition(
        !point.isSmallOrder() && compareBytes(point.toBytes(), bytes) === 0,
        "Invalid Ed25519 point",
      );
    } else {
      const point = new Uint8Array(65);
      point[0] = 4;
      point.set(bytes, 1);
      p256.Point.fromBytes(point).assertValidity();
    }
  } catch {
    throw new CodecError("MALFORMED", "Invalid session public key point");
  }
}

export function rootKeyId(key: RootKey): Uint8Array {
  objectFields(key, ["keyScheme", "publicKey"]);
  requireCondition(key.keyScheme === 1, "ROOT requires Ed25519", "UNSUPPORTED_FEATURE");
  return domainHash(
    "RESILIENCE_ROOT_KEY_ID_V1",
    Uint8Array.of(key.keyScheme),
    fixedBytes(key.publicKey, 32),
  );
}

export function sessionKeyFingerprint(scheme: Scheme, key: Uint8Array): Uint8Array {
  return domainHash(
    "RESILIENCE_SESSION_KEY_V1",
    Uint8Array.of(scheme),
    sessionPublicKeyBytes(scheme, key),
  );
}
