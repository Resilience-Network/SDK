import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import * as sdk from "../dist/webauthn/index.js";

const fixture = JSON.parse(
    readFileSync(new URL("./webauthn/parser-v1.json", import.meta.url)),
  ),
  challenge = Uint8Array.from({ length: 32 }, (_, i) => i),
  id = Uint8Array.of(1, 2, 3),
  rpId = "wallet.example",
  origin = "https://wallet.example",
  buf = (value) => Uint8Array.from(value).buffer,
  base = () => ({ rpId, origin, challenge: challenge.slice() }),
  regOptions = () => ({
    ...base(),
    rpName: "Wallet",
    userHandle: Uint8Array.of(42),
    userName: "Opaque account",
    userDisplayName: "Account",
  }),
  getOptions = () => ({ ...base(), allowCredentialIds: [id.slice()] }),
  sha = (value) => createHash("sha256").update(value).digest();
function head(major, n) {
  if (n < 24) return Buffer.of((major << 5) | n);
  if (n < 256) return Buffer.of((major << 5) | 24, n);
  return Buffer.of((major << 5) | 25, n >>> 8, n & 255);
}
function cbor(value) {
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), value]);
  if (typeof value === "string") {
    const b = Buffer.from(value);
    return Buffer.concat([head(3, b.length), b]);
  }
  const entries = [...value]
    .map(([key, value]) => [cbor(key), cbor(value)])
    .sort(([a], [b]) => Buffer.compare(a, b));
  return Buffer.concat([head(5, entries.length), ...entries.flat()]);
}
function credential(registration, overrides = {}) {
  const client = Buffer.from(
    JSON.stringify({
      type: registration ? "webauthn.create" : "webauthn.get",
      challenge: Buffer.from(challenge).toString("base64url"),
      origin,
    }),
  );
  const auth = Buffer.alloc(registration ? 55 + id.length : 37);
  sha(rpId).copy(auth);
  auth[32] = registration ? 0x45 : 5;
  if (registration) {
    auth.writeUInt16BE(id.length, 53);
    Buffer.from(id).copy(auth, 55);
  }
  const authWithKey = registration
    ? Buffer.concat([auth, Buffer.from(fixture.w3c.cose, "hex")])
    : auth;
  const response = registration
    ? {
        clientDataJSON: buf(client),
        attestationObject: buf(
          cbor(
            new Map([
              ["fmt", "none"],
              ["attStmt", new Map()],
              ["authData", authWithKey],
            ]),
          ),
        ),
        getTransports: () => ["internal", "hybrid"],
      }
    : {
        clientDataJSON: buf(client),
        authenticatorData: buf(auth),
        signature: buf(Buffer.from(fixture.signatures[0].der, "hex")),
        userHandle: null,
      };
  return {
    id: Buffer.from(id).toString("base64url"),
    rawId: buf(id),
    type: "public-key",
    authenticatorAttachment: "platform",
    response,
    getClientExtensionResults: () => ({}),
    ...overrides,
  };
}
function environment(t, methods = {}) {
  const saved = new Map(),
    calls = [];
  const window = {};
  window.self = window;
  window.top = window;
  const values = {
    isSecureContext: true,
    PublicKeyCredential: class {},
    window,
    location: { origin },
    navigator: {
      credentials: {
        create: async (options) => {
          calls.push(["create", options]);
          return credential(true);
        },
        get: async (options) => {
          calls.push(["get", options]);
          return credential(false);
        },
        ...methods,
      },
    },
  };
  for (const [key, value] of Object.entries(values)) {
    saved.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, {
      value,
      writable: true,
      configurable: true,
    });
  }
  t.after(() => {
    for (const [key, descriptor] of saved)
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else delete globalThis[key];
  });
  return calls;
}
const failure = (code) => (error) => {
  assert(error instanceof sdk.WebAuthnBrowserError);
  assert.equal(error.code, code);
  assert(!error.message.includes("private-sentinel"));
  return true;
};
const reject = (promise, code) => assert.rejects(promise, failure(code));
const invalid = (work) => assert.throws(work, failure("INVALID_RESPONSE"));

test("call-time capabilities require secure browser API and do not prompt", (t) => {
  const calls = environment(t);
  assert.deepEqual(sdk.webAuthnCapabilities(), {
    secureContext: true,
    registrationAvailable: true,
    authenticationAvailable: true,
  });
  assert.equal(calls.length, 0);
  globalThis.navigator.credentials.get = undefined;
  assert.equal(sdk.webAuthnCapabilities().authenticationAvailable, false);
  globalThis.isSecureContext = false;
  assert.equal(sdk.webAuthnCapabilities().registrationAvailable, false);
});
test("create/get use only explicit ES256/UV/none account-bound options and owned server data", async (t) => {
  const calls = environment(t),
    options = regOptions();
  const pending = sdk.createPasskeyCredential(options);
  options.challenge.fill(255);
  options.userHandle.fill(255);
  const result = await pending;
  assert(Object.isFrozen(result));
  assert(Object.isFrozen(result.response));
  assert(Object.isFrozen(result.response.transports));
  const created = calls[0][1];
  assert.deepEqual(new Uint8Array(created.publicKey.challenge), challenge);
  assert.deepEqual(new Uint8Array(created.publicKey.user.id), Uint8Array.of(42));
  assert.deepEqual(created.publicKey.pubKeyCredParams, [
    { type: "public-key", alg: -7 },
  ]);
  assert.equal(created.publicKey.attestation, "none");
  assert.equal(created.publicKey.authenticatorSelection.userVerification, "required");
  assert.equal(created.publicKey.extensions, undefined);
  assert.equal(created.signal.aborted, false);
  const assertion = await sdk.getPasskeyAssertion(getOptions());
  assert.equal(assertion.response.userHandle, null);
  assert.equal(calls[1][1].publicKey.userVerification, "required");
  assert.equal(calls.length, 2);
  assert.equal("verified" in result, false);
  assert.equal("onChainAuthorized" in assertion, false);
});
test("insecure, unsupported, wrong origin and iframe context fail without prompting", async (t) => {
  const calls = environment(t);
  globalThis.isSecureContext = false;
  await reject(sdk.createPasskeyCredential(regOptions()), "INVALID_CONTEXT");
  globalThis.isSecureContext = true;
  globalThis.PublicKeyCredential = undefined;
  await reject(sdk.getPasskeyAssertion(getOptions()), "UNSUPPORTED");
  globalThis.PublicKeyCredential = class {};
  globalThis.location.origin = "https://other.example";
  await reject(sdk.getPasskeyAssertion(getOptions()), "INVALID_CONTEXT");
  globalThis.location.origin = origin;
  globalThis.window.top = {};
  await reject(sdk.createPasskeyCredential(regOptions()), "INVALID_CONTEXT");
  assert.equal(calls.length, 0);
});
test("invalid options and unsupported profile fields fail before prompting", async (t) => {
  const calls = environment(t);
  for (const patch of [
    { challenge: new Uint8Array(31) },
    { challenge: new Uint8Array(33) },
    { timeoutMs: 0 },
    { timeoutMs: 180001 },
    { timeoutMs: 1.5 },
    { rpId: "https://wallet.example" },
    { rpId: "example.other" },
    { origin: origin + "/" },
    { origin: "http://wallet.example" },
    { pubKeyCredParams: [{ alg: -8 }] },
    { extensions: {} },
    { userVerification: "preferred" },
    { developmentLoopback: "true" },
    { signal: {} },
    { allowCredentialIds: [] },
    { allowCredentialIds: Array.from({ length: 33 }, () => id) },
    { allowCredentialIds: [id, id] },
    { allowCredentialIds: [new Uint8Array(1024)] },
  ])
    await reject(
      sdk.getPasskeyAssertion({ ...getOptions(), ...patch }),
      "INVALID_ARGUMENT",
    );
  for (const patch of [
    { userHandle: new Uint8Array() },
    { userHandle: new Uint8Array(65) },
    { rpName: "" },
    { userName: "x".repeat(257) },
    { userDisplayName: "bad\u0000name" },
    { excludeCredentialIds: [id, id] },
  ])
    await reject(
      sdk.createPasskeyCredential({ ...regOptions(), ...patch }),
      "INVALID_ARGUMENT",
    );
  assert.equal(calls.length, 0);
});
test("HTTP loopback requires explicit development permission and still secure API context", async (t) => {
  const calls = environment(t);
  globalThis.location.origin = "http://localhost:8080";
  const options = {
    ...getOptions(),
    rpId: "localhost",
    origin: "http://localhost:8080",
  };
  await reject(sdk.getPasskeyAssertion(options), "INVALID_ARGUMENT");
  globalThis.navigator.credentials.get = async () => {
    throw Object.assign(new Error("private-sentinel"), { name: "NotAllowedError" });
  };
  await reject(
    sdk.getPasskeyAssertion({ ...options, developmentLoopback: true }),
    "DENIED_OR_UNAVAILABLE",
  );
  assert.equal(calls.length, 0);
});
test("pre-abort and abort between scheduling and prompt call never prompt", async (t) => {
  const calls = environment(t),
    controller = new AbortController();
  controller.abort("private-sentinel");
  await reject(
    sdk.getPasskeyAssertion({ ...getOptions(), signal: controller.signal }),
    "CANCELLED",
  );
  const next = new AbortController(),
    pending = sdk.createPasskeyCredential({ ...regOptions(), signal: next.signal });
  next.abort("private-sentinel");
  await reject(pending, "CANCELLED");
  assert.equal(calls.length, 0);
});
test("in-flight cancellation aborts browser signal and ignores late success", async (t) => {
  let release, observed;
  environment(t, {
    get: (options) => {
      observed = options.signal;
      return new Promise((resolve) => (release = resolve));
    },
  });
  const controller = new AbortController(),
    pending = sdk.getPasskeyAssertion({ ...getOptions(), signal: controller.signal });
  await Promise.resolve();
  controller.abort("private-sentinel");
  await reject(pending, "CANCELLED");
  assert.equal(observed.aborted, true);
  release(credential(false));
  await Promise.resolve();
});
test("controlled timeout aborts a hung prompt and cleans up timer", async (t) => {
  let observed;
  environment(t, {
    create: (options) => {
      observed = options.signal;
      return new Promise(() => {});
    },
  });
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const pending = sdk.createPasskeyCredential({ ...regOptions(), timeoutMs: 1000 });
  await Promise.resolve();
  t.mock.timers.tick(999);
  assert.equal(observed.aborted, false);
  t.mock.timers.tick(1);
  await reject(pending, "TIMEOUT");
  assert.equal(observed.aborted, true);
});
test("late completion past monotonic deadline cannot return success before timer dispatch", async (t) => {
  let release,
    now = 0;
  environment(t, { get: () => new Promise((resolve) => (release = resolve)) });
  t.mock.method(performance, "now", () => now);
  const pending = sdk.getPasskeyAssertion({ ...getOptions(), timeoutMs: 1000 });
  await Promise.resolve();
  now = 1000;
  release(credential(false));
  await reject(pending, "TIMEOUT");
});
test("browser denial/error names have bounded sanitized classifications and no retry", async (t) => {
  let calls = 0;
  environment(t, {
    get: async () => {
      calls++;
      throw current;
    },
  });
  let current;
  for (const [name, code] of [
    ["NotAllowedError", "DENIED_OR_UNAVAILABLE"],
    ["AbortError", "CANCELLED"],
    ["NotSupportedError", "UNSUPPORTED"],
    ["SecurityError", "INVALID_CONTEXT"],
    ["InvalidStateError", "ALREADY_REGISTERED"],
    ["UnknownError", "BROWSER_FAILED"],
  ]) {
    current = Object.assign(new Error("private-sentinel"), { name });
    await reject(sdk.getPasskeyAssertion(getOptions()), code);
  }
  current = new Proxy(
    {},
    {
      getPrototypeOf() {
        throw Error("private-sentinel");
      },
    },
  );
  await reject(sdk.getPasskeyAssertion(getOptions()), "BROWSER_FAILED");
  assert.equal(calls, 7);
});
test("serialization preserves original signed bytes and owns immutable transport output", () => {
  const value = credential(false),
    original = Buffer.from(value.response.clientDataJSON).toString("base64url"),
    signature = Buffer.from(value.response.signature).toString("base64url"),
    result = sdk.serializePasskeyAssertion(value);
  new Uint8Array(value.response.clientDataJSON).fill(0);
  new Uint8Array(value.response.signature).fill(0);
  assert.equal(result.response.clientDataJSON, original);
  assert.equal(result.response.signature, signature);
  assert(Object.isFrozen(result));
  assert(Object.isFrozen(result.response));
  const handle = credential(false);
  handle.response.userHandle = buf([42]);
  assert.equal(sdk.serializePasskeyAssertion(handle).response.userHandle, "Kg");
});
test("malformed credential identity, extensions, attachment and ceremony shapes fail explicitly", () => {
  for (const patch of [
    { id: "alias=" },
    { rawId: buf([]) },
    { rawId: buf(new Uint8Array(1024)) },
    { type: "password" },
    { response: null },
    { authenticatorAttachment: "hardware" },
    { getClientExtensionResults: () => ({ prf: {} }) },
    { getClientExtensionResults: undefined },
  ])
    invalid(() => sdk.serializePasskeyAssertion(credential(false, patch)));
  invalid(() => sdk.serializePasskeyAssertion(credential(true)));
  invalid(() => sdk.serializePasskeyRegistration(credential(false)));
  const registration = credential(true);
  registration.response.getTransports = () => ["internal", "internal"];
  invalid(() => sdk.serializePasskeyRegistration(registration));
  registration.response.getTransports = () => ["unknown-transport"];
  invalid(() => sdk.serializePasskeyRegistration(registration));
  const hostile = credential(false);
  Object.defineProperty(hostile, "response", {
    get() {
      throw new Proxy(
        {},
        {
          getPrototypeOf() {
            throw Error("private-sentinel");
          },
        },
      );
    },
  });
  invalid(() => sdk.serializePasskeyAssertion(hostile));
});
test("null, oversized, shared or spoofed response buffers never become transport records", () => {
  for (const field of [
    "clientDataJSON",
    "authenticatorData",
    "signature",
    "userHandle",
  ]) {
    for (const invalidBuffer of [
      null,
      new SharedArrayBuffer(100),
      {},
      new ArrayBuffer(20000),
    ]) {
      const value = credential(false);
      value.response[field] = invalidBuffer;
      if (field === "userHandle" && invalidBuffer === null) continue;
      invalid(() => sdk.serializePasskeyAssertion(value));
    }
  }
  const source = credential(false);
  Object.defineProperty(source.response.signature, "byteLength", { value: 1 });
  assert.doesNotThrow(() => sdk.serializePasskeyAssertion(source));
});
test("local projection rejects absent UV, cross-origin, invalid flags and DER", () => {
  for (const flags of [0, 1, 0x25, 0x85, 0x15]) {
    const value = credential(false);
    new Uint8Array(value.response.authenticatorData)[32] = flags;
    invalid(() => sdk.serializePasskeyAssertion(value));
  }
  for (const patch of [
    { crossOrigin: true },
    { topOrigin: origin },
    { type: "webauthn.create" },
  ]) {
    const value = credential(false),
      client = JSON.parse(Buffer.from(value.response.clientDataJSON).toString());
    value.response.clientDataJSON = buf(
      Buffer.from(JSON.stringify({ ...client, ...patch })),
    );
    invalid(() => sdk.serializePasskeyAssertion(value));
  }
  const value = credential(false);
  value.response.signature = buf([0x30, 6, 2, 1, 0, 2, 1, 1]);
  invalid(() => sdk.serializePasskeyAssertion(value));
});
test("ceremony binds returned challenge/origin/RP hash and known credential ID", async (t) => {
  let value = credential(false);
  environment(t, { get: async () => value });
  for (const patch of [{ challenge: "AQ" }, { origin: "https://other.example" }]) {
    value = credential(false);
    const client = JSON.parse(Buffer.from(value.response.clientDataJSON).toString());
    value.response.clientDataJSON = buf(
      Buffer.from(JSON.stringify({ ...client, ...patch })),
    );
    await reject(sdk.getPasskeyAssertion(getOptions()), "INVALID_RESPONSE");
  }
  value = credential(false);
  new Uint8Array(value.response.authenticatorData)[0] ^= 1;
  await reject(sdk.getPasskeyAssertion(getOptions()), "INVALID_RESPONSE");
  value = credential(false, { id: "BA", rawId: buf([4]) });
  await reject(sdk.getPasskeyAssertion(getOptions()), "INVALID_RESPONSE");
});

test("option accessors and inherited required fields fail without evaluation or prompting", async (t) => {
  const calls = environment(t);
  const accessor = getOptions();
  Object.defineProperty(accessor, "rpId", {
    get() {
      throw Error("private-sentinel");
    },
  });
  await reject(sdk.getPasskeyAssertion(accessor), "INVALID_ARGUMENT");
  await reject(
    sdk.getPasskeyAssertion(Object.create(getOptions())),
    "INVALID_ARGUMENT",
  );
  const options = getOptions();
  options.allowCredentialIds[Symbol.iterator] = function* () {
    yield Uint8Array.of(4);
  };
  await assert.doesNotReject(sdk.getPasskeyAssertion(options));
  assert.equal(calls.length, 1);
});

test("browser request mutation cannot widen the captured credential allow-list", async (t) => {
  environment(t, {
    get: async (options) => {
      new Uint8Array(options.publicKey.allowCredentials[0].id).fill(4);
      return credential(false, { id: "BAQE", rawId: buf([4, 4, 4]) });
    },
  });
  await reject(sdk.getPasskeyAssertion(getOptions()), "INVALID_RESPONSE");
});
