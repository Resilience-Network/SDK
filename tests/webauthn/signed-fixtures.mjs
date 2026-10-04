// Independent Node/OpenSSL WebAuthn message fixtures; private KeyObjects stay in memory.
import {
  generateKeyPairSync,
  createHash,
  sign,
  randomBytes,
  verify,
} from "node:crypto";
const hash = (value) => createHash("sha256").update(value).digest(),
  b64 = (value) => Buffer.from(value).toString("base64url");
function head(major, n) {
  if (n < 24) return Buffer.of((major << 5) | n);
  if (n < 256) return Buffer.of((major << 5) | 24, n);
  if (n < 65536) return Buffer.of((major << 5) | 25, n >>> 8, n & 255);
  throw Error("fixture range");
}
export function fixtureCbor(value) {
  if (typeof value === "number")
    return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), value]);
  if (typeof value === "string") {
    const bytes = Buffer.from(value);
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  const entries = [...value]
    .map(([key, value]) => [fixtureCbor(key), fixtureCbor(value)])
    .sort(([a], [b]) => Buffer.compare(a, b));
  return Buffer.concat([head(5, entries.length), ...entries.flat()]);
}
export function signedFixture({
  backupEligible = false,
  backupState = false,
  counter = 5,
} = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    }),
    jwk = publicKey.export({ format: "jwk" }),
    rawId = randomBytes(32),
    userHandle = randomBytes(32),
    id = b64(rawId),
    coseMap = new Map([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, Buffer.from(jwk.x, "base64url")],
      [-3, Buffer.from(jwk.y, "base64url")],
    ]),
    cose = fixtureCbor(coseMap);
  function response(challenge, registration, overrides = {}) {
    const client = Buffer.from(
      overrides.clientText ??
        JSON.stringify({
          type: registration ? "webauthn.create" : "webauthn.get",
          challenge: challenge.challenge,
          origin: challenge.origin,
          ...overrides.client,
        }),
    );
    const flags =
        overrides.flags ??
        5 | (registration ? 64 : 0) | (backupEligible ? 8 : 0) | (backupState ? 16 : 0),
      auth = Buffer.alloc(registration ? 55 + rawId.length : 37);
    hash(overrides.rpId ?? challenge.rpId).copy(auth);
    auth[32] = flags;
    auth.writeUInt32BE(overrides.counter ?? (registration ? counter : counter + 1), 33);
    if (registration) {
      auth.writeUInt16BE(rawId.length, 53);
      rawId.copy(auth, 55);
    }
    const signedData = Buffer.concat([auth, hash(client)]),
      signature = registration ? undefined : sign("sha256", signedData, privateKey);
    if (!registration && !verify("sha256", signedData, publicKey, signature))
      throw Error("independent fixture signature failed");
    return {
      id,
      rawId: id,
      type: "public-key",
      clientExtensionResults: {},
      response: registration
        ? {
            clientDataJSON: b64(client),
            attestationObject: b64(
              fixtureCbor(
                new Map([
                  ["fmt", overrides.format ?? "none"],
                  ["attStmt", overrides.statement ?? new Map()],
                  ["authData", Buffer.concat([auth, overrides.cose ?? cose])],
                ]),
              ),
            ),
            transports: ["internal"],
          }
        : {
            clientDataJSON: b64(client),
            authenticatorData: b64(auth),
            signature: b64(signature),
            userHandle: overrides.nullHandle ? null : b64(userHandle),
          },
    };
  }
  return {
    id,
    userHandle,
    cose,
    coseMap,
    backupEligible,
    backupState,
    counter,
    registration: (challenge, overrides) => response(challenge, true, overrides),
    assertion: (challenge, overrides) => response(challenge, false, overrides),
  };
}
export const responseBody = (value) =>
  new Uint8Array(Buffer.from(JSON.stringify(value)));
