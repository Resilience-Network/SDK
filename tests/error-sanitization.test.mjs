import assert from "node:assert/strict";
import test from "node:test";
import {
  bytesToHex,
  CodecError,
  parseClientDataJSON,
  WebAuthnParseError,
  serializePasskeyAssertion,
  WebAuthnBrowserError,
} from "../dist/index.js";

const sentinel = "private-sentinel";
const boundaries = [
  [
    "core",
    () => new CodecError("LIMIT_EXCEEDED", sentinel),
    "LIMIT_EXCEEDED",
    "MALFORMED",
    (error) =>
      bytesToHex(
        new Proxy(new Uint8Array(1), {
          getPrototypeOf() {
            throw error;
          },
        }),
      ),
  ],
  [
    "parser",
    () => new WebAuthnParseError("INVALID_CLIENT_DATA"),
    "INVALID_CLIENT_DATA",
    "INVALID_ARGUMENT",
    (error) =>
      parseClientDataJSON(
        new Proxy(new Uint8Array(1), {
          getPrototypeOf() {
            throw error;
          },
        }),
      ),
  ],
  [
    "browser",
    () => new WebAuthnBrowserError("CANCELLED"),
    "CANCELLED",
    "INVALID_RESPONSE",
    (error) =>
      serializePasskeyAssertion({
        get response() {
          throw error;
        },
      }),
  ],
];
for (const [name, create, expected, fallback, work] of boundaries) {
  test(`${name} reconstructs typed errors without caller messages or causes`, () => {
    const original = create();
    original.message = sentinel;
    original.cause = sentinel;
    assert.throws(
      () => work(original),
      (error) => {
        assert.notEqual(error, original);
        assert.equal(error.code, expected);
        assert.ok(!error.message.includes(sentinel));
        assert.equal(error.cause, undefined);
        assert.ok(!error.stack.includes(sentinel));
        return true;
      },
    );
  });
  test(`${name} bounds invalid codes and hostile classification traps`, () => {
    const invalid = create();
    invalid.code = sentinel;
    const getter = create();
    Object.defineProperty(getter, "code", {
      get() {
        throw new Error(sentinel);
      },
    });
    const proxy = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error(sentinel);
        },
      },
    );
    for (const value of [invalid, getter, proxy])
      assert.throws(
        () => work(value),
        (error) => {
          assert.equal(error.code, fallback);
          assert.ok(!error.message.includes(sentinel));
          assert.equal(error.cause, undefined);
          return true;
        },
      );
  });
}
