import assert from "node:assert/strict";
import test from "node:test";
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { p256 } from "@noble/curves/nist.js";
import * as sdk from "../dist/index.js";
import * as webauthn from "../dist/webauthn/index.js";
import { readCbor } from "../dist/webauthn/cbor.js";
import { context, intent } from "./helpers.mjs";

const rawFixture = readFileSync(new URL("./webauthn/parser-v1.json", import.meta.url)),
  fixtures = JSON.parse(rawFixture),
  provenance = JSON.parse(
    readFileSync(new URL("./webauthn/parser-v1.provenance.json", import.meta.url)),
  ),
  bytes = (hex) => Uint8Array.from(Buffer.from(hex, "hex")),
  cose = bytes(fixtures.w3c.cose),
  w3cKey = bytes(fixtures.w3c.publicKey),
  order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const error = (code) => (e) => {
  assert(e instanceof sdk.WebAuthnParseError);
  if (code) assert.equal(e.code, code);
  assert(!e.message.includes("SECRET"));
  return true;
};
const head = (major, n) => {
  n = BigInt(n);
  if (n < 24n) return Buffer.of((major << 5) | Number(n));
  for (const [width, extra] of [
    [1, 24],
    [2, 25],
    [4, 26],
    [8, 27],
  ]) {
    if (n < 1n << BigInt(width * 8)) {
      const body = Buffer.alloc(width);
      let value = n;
      for (let i = width - 1; i >= 0; i--) {
        body[i] = Number(value & 255n);
        value >>= 8n;
      }
      return Buffer.concat([Buffer.of((major << 5) | extra), body]);
    }
  }
  throw Error("test encoder range");
};
// Independent test encoder, not a production/parser roundtrip oracle.
const cbor = (value) => {
  if (typeof value === "number" || typeof value === "bigint")
    return value >= 0 ? head(0, value) : head(1, -1n - BigInt(value));
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), value]);
  if (typeof value === "string") {
    const b = Buffer.from(value);
    return Buffer.concat([head(3, b.length), b]);
  }
  if (Array.isArray(value))
    return Buffer.concat([head(4, value.length), ...value.map(cbor)]);
  if (value instanceof Map) {
    const entries = [...value]
      .map(([key, v]) => [cbor(key), cbor(v)])
      .sort(([a], [b]) => Buffer.compare(a, b));
    return Buffer.concat([head(5, entries.length), ...entries.flat()]);
  }
  return Buffer.of(value === null ? 0xf6 : value ? 0xf5 : 0xf4);
};
const keyMap = () =>
  new Map([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, w3cKey.slice(0, 32)],
    [-3, w3cKey.slice(32)],
  ]);
const authenticator = (flags = 0x45, id = Buffer.alloc(16, 11), key = cose) => {
  const prefix = Buffer.alloc(37, 0);
  prefix.fill(7, 0, 32);
  prefix[32] = flags;
  prefix.writeUInt32BE(0xffffffff, 33);
  if (!(flags & 0x40)) return prefix;
  const size = Buffer.alloc(2);
  size.writeUInt16BE(id.length);
  return Buffer.concat([prefix, Buffer.alloc(16, 3), size, id, key]);
};
const attestation = (
  data = authenticator(),
  format = "none",
  statement = new Map(),
  extra = [],
) =>
  cbor(
    new Map([["fmt", format], ["attStmt", statement], ["authData", data], ...extra]),
  );
const client = (overrides = {}) =>
  Buffer.from(
    JSON.stringify({
      type: "webauthn.get",
      challenge: Buffer.alloc(32, 8).toString("base64url"),
      origin: "https://wallet.example",
      crossOrigin: false,
      ...overrides,
    }),
  );
const encodeDer = (...values) => {
  const parts = values.map((value) => {
    let hex = value.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    let b = Buffer.from(hex, "hex");
    if (b[0] & 128) b = Buffer.concat([Buffer.of(0), b]);
    return Buffer.concat([Buffer.of(2, b.length), b]);
  });
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.of(0x30, body.length), body]);
};

test("parser provenance binds W3C public point and independent OpenSSL generation source", () => {
  assert.equal(
    createHash("sha256").update(rawFixture).digest("hex"),
    provenance.fixtureSha256,
  );
  assert.equal(
    createHash("sha256")
      .update(
        readFileSync(
          new URL("../scripts/generate_webauthn_parser_fixtures.mjs", import.meta.url),
        ),
      )
      .digest("hex"),
    provenance.generatorSha256,
  );
  assert.equal(fixtures.version, 1);
  assert.equal(fixtures.signatures.length, 8);
  assert.equal(webauthn.parseCoseP256PublicKey, sdk.parseCoseP256PublicKey);
  assert.equal(cbor(keyMap()).toString("hex"), fixtures.w3c.cose);
});
test("W3C ES256 public-key representation is exact, valid and owned", () => {
  const input = Buffer.from(cose),
    parsed = sdk.parseCoseP256PublicKey(input);
  assert.equal(parsed.algorithm, -7);
  assert.deepEqual(parsed.publicKey, w3cKey);
  assert.deepEqual(parsed.coseKey, cose);
  input.fill(0);
  parsed.publicKey.fill(0);
  assert.deepEqual(parsed.coseKey, cose);
  assert.deepEqual(sdk.parseCoseP256PublicKey(cose).publicKey, w3cKey);
});
test("COSE rejects unsupported/missing/extra parameters, wrong widths and invalid points", () => {
  for (const [label, change, code] of [
    ["missing algorithm", (m) => m.delete(3), "UNSUPPORTED_COSE"],
    ["RSA", (m) => m.set(1, 3), "UNSUPPORTED_COSE"],
    ["other algorithm", (m) => m.set(3, -257), "UNSUPPORTED_COSE"],
    ["other curve", (m) => m.set(-1, 2), "UNSUPPORTED_COSE"],
    ["compressed point", (m) => m.set(-3, true), "UNSUPPORTED_COSE"],
    ["extra key ops", (m) => m.set(4, [2]), "UNSUPPORTED_COSE"],
    ["short x", (m) => m.set(-2, new Uint8Array(31)), "UNSUPPORTED_COSE"],
    ["long y", (m) => m.set(-3, new Uint8Array(33)), "UNSUPPORTED_COSE"],
    ["field overflow", (m) => m.set(-2, new Uint8Array(32).fill(255)), "INVALID_POINT"],
    [
      "off curve",
      (m) => {
        m.set(-2, new Uint8Array(32));
        m.set(-3, new Uint8Array(32));
      },
      "INVALID_POINT",
    ],
  ]) {
    const m = keyMap();
    change(m);
    assert.throws(() => sdk.parseCoseP256PublicKey(cbor(m)), error(code), label);
  }
});
test("all COSE truncations and trailing bytes fail without a fallback decoder", () => {
  for (let i = 0; i < cose.length; i++)
    assert.throws(() => sdk.parseCoseP256PublicKey(cose.slice(0, i)), error());
  assert.throws(
    () => sdk.parseCoseP256PublicKey(Buffer.concat([cose, Buffer.of(0)])),
    error("INVALID_CBOR"),
  );
  assert.throws(
    () => sdk.parseCoseP256PublicKey(new Uint8Array(1025)),
    error("LIMIT_EXCEEDED"),
  );
});
test("CBOR enforces CTAP2 ordering, unique keys, minimal widths and supported types", () => {
  for (const hex of [
    "1817",
    "1900ff",
    "1a0000ffff",
    "1b00000000ffffffff",
    "581700",
    "9fff",
    "bfff",
    "c001",
    "f90000",
    "f7",
    "ff",
    "a201020103",
    "a203260102",
    "a161ff00",
    "a1f501",
    "a14000",
  ])
    assert.throws(() => readCbor(bytes(hex)), error("INVALID_CBOR"), hex);
  const map = readCbor(
    cbor(
      new Map([
        [-1, 1],
        [255, 2],
      ]),
    ),
  );
  assert.deepEqual([...map.keys()], [255, -1]);
  assert.equal(readCbor(cbor((1n << 64n) - 1n)), (1n << 64n) - 1n);
});
test("CBOR depth/container/item bounds accept exact boundary and reject one beyond", () => {
  assert.deepEqual(readCbor(cbor([[[[]]]])), [[[[]]]]);
  assert.throws(() => readCbor(cbor([[[[[]]]]])), error("LIMIT_EXCEEDED"));
  assert.throws(() => readCbor(bytes("9821")), error("LIMIT_EXCEEDED"));
  assert.throws(() => readCbor(bytes("5bffffffffffffffff")), error("LIMIT_EXCEEDED"));
  const boundary = Array.from({ length: 32 }, (_, i) =>
    Array(i === 31 ? 2 : 3).fill(0),
  );
  assert.equal(readCbor(cbor(boundary)).length, 32); // 128 keys/values/containers.
  boundary[31].push(0);
  assert.throws(() => readCbor(cbor(boundary)), error("LIMIT_EXCEEDED"));
});
test("authenticator parsing preserves original bytes and observational flags without verification", () => {
  const input = authenticator(),
    parsed = sdk.parseAuthenticatorData(input, "registration");
  assert.deepEqual(parsed.original, Uint8Array.from(input));
  assert.equal(parsed.signCount, 0xffffffff);
  assert.equal(parsed.userPresent, true);
  assert.equal(parsed.userVerified, true);
  assert.deepEqual(parsed.credential.key.publicKey, w3cKey);
  input.fill(0);
  parsed.original.fill(0);
  assert.deepEqual(parsed.rpIdHash, new Uint8Array(32).fill(7));
  assert.equal(parsed.credential.credentialId.length, 16);
  const absent = sdk.parseAuthenticatorData(authenticator(0), "authentication");
  assert.equal(absent.userPresent, false);
  assert.equal(absent.userVerified, false);
  assert.equal(absent.credential, undefined);
  assert.equal(absent.verified, undefined);
  const backup = sdk.parseAuthenticatorData(authenticator(0x1d), "authentication");
  assert.equal(backup.backupEligible, true);
  assert.equal(backup.backupState, true);
});
test("authenticator structures reject truncation, incompatible flags and trailing data", () => {
  const full = authenticator();
  for (let i = 0; i < full.length; i++)
    assert.throws(
      () => sdk.parseAuthenticatorData(full.slice(0, i), "registration"),
      error(),
    );
  for (const flags of [0x02, 0x20, 0x10])
    assert.throws(
      () => sdk.parseAuthenticatorData(authenticator(flags), "authentication"),
      error("INVALID_AUTHENTICATOR_DATA"),
    );
  assert.throws(
    () => sdk.parseAuthenticatorData(authenticator(0x85), "authentication"),
    error("UNSUPPORTED_EXTENSION"),
  );
  assert.throws(
    () => sdk.parseAuthenticatorData(authenticator(5), "registration"),
    error("INVALID_AUTHENTICATOR_DATA"),
  );
  assert.throws(
    () => sdk.parseAuthenticatorData(full, "authentication"),
    error("INVALID_AUTHENTICATOR_DATA"),
  );
  assert.throws(
    () => sdk.parseAuthenticatorData(full, "guess"),
    error("INVALID_ARGUMENT"),
  );
  assert.throws(
    () =>
      sdk.parseAuthenticatorData(
        Buffer.concat([authenticator(5), Buffer.of(0)]),
        "authentication",
      ),
    error("INVALID_AUTHENTICATOR_DATA"),
  );
  assert.throws(
    () => sdk.parseAuthenticatorData(new Uint8Array(8193), "registration"),
    error("LIMIT_EXCEEDED"),
  );
});
test("attested credential ID 1023 is accepted, 1024 and zero reject explicitly", () => {
  assert.equal(
    sdk.parseAuthenticatorData(
      authenticator(0x45, Buffer.alloc(1023, 1)),
      "registration",
    ).credential.credentialId.length,
    1023,
  );
  assert.throws(
    () =>
      sdk.parseAuthenticatorData(
        authenticator(0x45, Buffer.alloc(1024)),
        "registration",
      ),
    error("LIMIT_EXCEEDED"),
  );
  assert.throws(
    () =>
      sdk.parseAuthenticatorData(authenticator(0x45, Buffer.alloc(0)), "registration"),
    error("INVALID_AUTHENTICATOR_DATA"),
  );
});
test("none attestation only parses supported exact structure and proves no key possession", () => {
  const full = attestation(),
    parsed = sdk.parseNoneAttestationObject(full);
  assert.equal(parsed.format, "none");
  assert.deepEqual(parsed.authenticator.credential.key.publicKey, w3cKey);
  assert.equal(parsed.verified, undefined);
  for (const bad of [
    attestation(undefined, "packed"),
    attestation(undefined, "none", new Map([["sig", Buffer.of(1)]])),
    attestation(undefined, "none", new Map(), [["extra", true]]),
    cbor(
      new Map([
        ["fmt", "none"],
        ["attStmt", new Map()],
      ]),
    ),
  ])
    assert.throws(
      () => sdk.parseNoneAttestationObject(bad),
      error("UNSUPPORTED_ATTESTATION"),
    );
  for (let i = 0; i < full.length; i++)
    assert.throws(() => sdk.parseNoneAttestationObject(full.slice(0, i)), error());
  assert.throws(
    () => sdk.parseNoneAttestationObject(new Uint8Array(16385)),
    error("LIMIT_EXCEEDED"),
  );
});
test("independent OpenSSL DER/P1363 fixtures preserve padding and both s values", () => {
  const publicKey = createPublicKey({ key: fixtures.publicKey, format: "jwk" }),
    message = Buffer.from(fixtures.message, "base64url");
  let high = 0,
    low = 0;
  for (const f of fixtures.signatures) {
    const converted = sdk.derToP256Signature(bytes(f.der));
    assert.equal(Buffer.from(converted).toString("hex"), f.raw);
    assert(verify("sha256", message, publicKey, bytes(f.der)));
    assert(
      verify(
        "sha256",
        message,
        { key: publicKey, dsaEncoding: "ieee-p1363" },
        converted,
      ),
    );
    const s = BigInt("0x" + f.raw.slice(64));
    if (s > order / 2n) high++;
    else low++;
  }
  assert.equal(high, 4);
  assert.equal(low, 4);
});
test("DER representation conversion cannot turn an unrelated signature into native SessionDigest", () => {
  const publicKey = Buffer.concat([
    Buffer.from(fixtures.publicKey.x, "base64url"),
    Buffer.from(fixtures.publicKey.y, "base64url"),
  ]);
  const digest = sdk.sessionDigest(context, intent, {
    grantId: new Uint8Array(32).fill(1),
    authEpoch: 1n,
    policyHash: new Uint8Array(32).fill(2),
    nonce: 0n,
  });
  for (const f of fixtures.signatures)
    assert.equal(
      p256.verify(
        sdk.derToP256Signature(bytes(f.der)),
        digest,
        Buffer.concat([Buffer.of(4), publicKey]),
        { prehash: false, lowS: false },
      ),
      false,
    );
});
test("DER scalar boundaries preserve exact values and reject zero/order/negative/nonminimal", () => {
  const valid = sdk.derToP256Signature(encodeDer(1n, order - 1n));
  assert.equal(valid.length, 64);
  assert.equal(valid[31], 1);
  assert.equal(BigInt("0x" + Buffer.from(valid.slice(32)).toString("hex")), order - 1n);
  for (const [r, s] of [
    [0n, 1n],
    [1n, 0n],
    [order, 1n],
    [1n, order],
    [1n << 256n, 1n],
  ])
    assert.throws(() => sdk.derToP256Signature(encodeDer(r, s)), error());
  for (const hex of [
    "3006020180020101",
    "300702020001020101",
    "308106020101020101",
    "300702810101020101",
    "30800201010201010000",
    "30060201010201010300",
    "3106020101020101",
    "3006020101030101",
    "3006020001020101",
  ])
    assert.throws(() => sdk.derToP256Signature(bytes(hex)), error(), hex);
  for (const f of fixtures.signatures) {
    const der = bytes(f.der);
    for (let i = 0; i < der.length; i++)
      assert.throws(() => sdk.derToP256Signature(der.slice(0, i)), error());
  }
  assert.throws(
    () => sdk.derToP256Signature(new Uint8Array(73)),
    error("LIMIT_EXCEEDED"),
  );
});
test("client data preserves original JSON and reports cross-origin observations without authority", () => {
  const input = Buffer.from(
      ' { "type":"webauthn.get", "challenge":"AQ", "origin":"https://wallet.example", "extra":{"verified":true} }\n',
    ),
    parsed = sdk.parseClientDataJSON(input);
  assert.deepEqual(parsed.original, Uint8Array.from(input));
  assert.deepEqual(parsed.challenge, Uint8Array.of(1));
  input.fill(0);
  assert.equal(parsed.origin, "https://wallet.example");
  assert.equal(parsed.crossOrigin, false);
  assert.equal(parsed.verified, undefined);
  const observed = sdk.parseClientDataJSON(
    client({
      type: "webauthn.create",
      crossOrigin: true,
      topOrigin: "https://another.example",
    }),
  );
  assert.equal(observed.crossOrigin, true);
  assert.equal(observed.topOrigin, "https://another.example");
});
test("client JSON rejects duplicate decoded keys, malformed text and unsafe types", () => {
  for (const input of [
    Buffer.from('{"type":"webauthn.get","ty\\u0070e":"webauthn.create"}'),
    Buffer.from(
      '{"type":"webauthn.get","challenge":"AQ","origin":"x","extra":{"a":1,"a":2}}',
    ),
    Buffer.from('{"type":"webauthn.get",}'),
    Buffer.from("[]"),
    Buffer.from("null"),
    Buffer.from("{}"),
    Buffer.from('{"type":"webauthn.get","challenge":"AQ","origin":"\\ud800"}'),
    Buffer.of(0xff),
    Buffer.from("\ufeff{}"),
    Buffer.from('{"x":1e999}'),
    Buffer.from('{"x":9007199254740993}'),
  ])
    assert.throws(() => sdk.parseClientDataJSON(input), error("INVALID_CLIENT_DATA"));
  for (const fields of [
    { type: "not-a-ceremony" },
    { challenge: 1 },
    { origin: null },
    { crossOrigin: 1 },
    { topOrigin: false },
  ])
    assert.throws(
      () => sdk.parseClientDataJSON(client(fields)),
      error("INVALID_CLIENT_DATA"),
    );
});
test("base64url challenge representation rejects padding/aliases and exact size boundaries", () => {
  for (const challenge of ["", "AQ==", "A+", "A/", "A", "AR", "AAF", "AQ\n"])
    assert.throws(() => sdk.parseClientDataJSON(client({ challenge })), error());
  assert.equal(
    sdk.parseClientDataJSON(
      client({ challenge: Buffer.alloc(1024, 255).toString("base64url") }),
    ).challenge.length,
    1024,
  );
  assert.throws(
    () =>
      sdk.parseClientDataJSON(
        client({ challenge: Buffer.alloc(1025).toString("base64url") }),
      ),
    error("LIMIT_EXCEEDED"),
  );
});
test("client JSON depth/count/bytes bounds and prototype names are handled safely", () => {
  assert(sdk.parseClientDataJSON(client({ extra: [[[]]] })));
  assert.throws(
    () => sdk.parseClientDataJSON(client({ extra: [[[[]]]] })),
    error("LIMIT_EXCEEDED"),
  );
  assert.throws(
    () => sdk.parseClientDataJSON(client({ extra: Array(33).fill(0) })),
    error("LIMIT_EXCEEDED"),
  );
  const base = client();
  assert(
    sdk.parseClientDataJSON(
      Buffer.concat([base, Buffer.alloc(8192 - base.length, 32)]),
    ),
  );
  assert.throws(
    () =>
      sdk.parseClientDataJSON(
        Buffer.concat([base, Buffer.alloc(8193 - base.length, 32)]),
      ),
    error("LIMIT_EXCEEDED"),
  );
  const proto = client().toString().slice(0, -1) + ',"__proto__":{"polluted":true}}';
  assert(sdk.parseClientDataJSON(Buffer.from(proto)));
  assert.equal({}.polluted, undefined);
  const items = Array.from({ length: 29 }, () => [0, 0, 0]);
  items[28].push(0); // 128 total values/keys/containers including required fields.
  assert(sdk.parseClientDataJSON(client({ extra: items })));
  items[28].push(0);
  assert.throws(
    () => sdk.parseClientDataJSON(client({ extra: items })),
    error("LIMIT_EXCEEDED"),
  );
});
test("public parser errors sanitize hostile inputs and never accept shared binary state", () => {
  const calls = [
    sdk.parseCoseP256PublicKey,
    (v) => sdk.parseAuthenticatorData(v, "registration"),
    sdk.parseNoneAttestationObject,
    sdk.derToP256Signature,
    sdk.parseClientDataJSON,
  ];
  const hostile = new Proxy(new Uint8Array(100), {
    get() {
      throw Error("SECRET input getter");
    },
  });
  for (const parse of calls) {
    for (const input of [
      null,
      "SECRET bytes",
      [],
      {},
      hostile,
      new Uint8Array(new SharedArrayBuffer(100)),
    ])
      assert.throws(() => parse(input), error("INVALID_ARGUMENT"));
  }
});
test("intrinsic byte bounds reject shadowed lengths and hidden shared backing stores", () => {
  const large = new Uint8Array(65536);
  large.fill(32);
  large.set(client());
  Object.defineProperty(large, "length", { value: 1 });
  assert.throws(() => sdk.parseClientDataJSON(large), error("LIMIT_EXCEEDED"));
  const shared = new Uint8Array(new SharedArrayBuffer(37));
  Object.defineProperty(shared, "buffer", { value: new ArrayBuffer(37) });
  assert.throws(
    () => sdk.parseAuthenticatorData(shared, "authentication"),
    error("INVALID_ARGUMENT"),
  );
  const valid = Uint8Array.from(client());
  Object.defineProperty(valid, "length", {
    get() {
      throw Error("SECRET length getter");
    },
  });
  Object.defineProperty(valid, "buffer", {
    get() {
      throw Error("SECRET buffer getter");
    },
  });
  assert.equal(sdk.parseClientDataJSON(valid).type, "webauthn.get");
});
test("seeded byte mutations/truncation corpus returns bounded representations or typed errors", () => {
  const pairs = [
    [sdk.parseCoseP256PublicKey, cose],
    [(b) => sdk.parseAuthenticatorData(b, "registration"), authenticator()],
    [sdk.parseNoneAttestationObject, attestation()],
    [sdk.derToP256Signature, bytes(fixtures.signatures[0].der)],
    [sdk.parseClientDataJSON, client()],
  ];
  let seed = 0x13579bdf,
    accepted = 0,
    rejected = 0;
  const next = () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed;
  };
  for (let i = 0; i < 5000; i++) {
    const [parse, baseline] = pairs[i % pairs.length];
    let value = Uint8Array.from(baseline);
    if (i % 3 === 0) value = value.slice(0, next() % value.length);
    else if (i % 3 === 1) value[next() % value.length] ^= 1 + (next() % 255);
    else value = Uint8Array.from([...value, next() & 255]);
    try {
      parse(value);
      accepted++;
    } catch (e) {
      assert(error()(e));
      rejected++;
    }
  }
  assert(accepted > 100);
  assert(rejected > 1000);
  assert.equal(accepted + rejected, 5000);
});
