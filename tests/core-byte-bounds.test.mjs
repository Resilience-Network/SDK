import assert from "node:assert/strict";
import test from "node:test";
import {
  bytesToHex,
  compareBytes,
  decodeUint64,
  keccak256,
  CodecError,
} from "../dist/core/index.js";
import {
  checkedBytes,
  fixedBytes,
  isZero,
  Reader,
  Writer,
  MAX_TRANSACTION_BYTES,
} from "../dist/core/bytes.js";

const invalid = (work, code = "MALFORMED") =>
  assert.throws(
    work,
    (error) =>
      error instanceof CodecError &&
      error.code === code &&
      !error.message.includes("private-sentinel"),
  );

test("intrinsic core limits reject oversized shadowed view before iteration", () => {
  const input = new Uint8Array(1_000_000);
  Object.defineProperty(input, "length", { value: 1 });
  for (const work of [
    () => bytesToHex(input),
    () => keccak256(input),
    () => checkedBytes(input, MAX_TRANSACTION_BYTES),
    () => compareBytes(input, new Uint8Array()),
    () => new Reader(input),
  ])
    invalid(work, "LIMIT_EXCEEDED");
});

test("fixed-width and layout shadows cannot control byte codecs or hashing", () => {
  const short = new Uint8Array(7);
  Object.defineProperty(short, "length", { value: 8 });
  invalid(() => decodeUint64(short));
  for (const field of ["length", "buffer", "byteLength", "byteOffset"]) {
    const value = new Uint8Array(8);
    Object.defineProperty(value, field, {
      get() {
        throw new Error("private-sentinel");
      },
    });
    invalid(() => fixedBytes(value, 8));
    invalid(() => new Writer(8).fixed(value));
  }
  class Shadow extends Uint8Array {
    get length() {
      throw new Error("private-sentinel");
    }
  }
  invalid(() => bytesToHex(new Shadow(8)));
});

test("shared, detached and proxied core byte views fail with typed errors", () => {
  const shared = new Uint8Array(new SharedArrayBuffer(8));
  const detached = new Uint8Array(8);
  structuredClone(detached.buffer, { transfer: [detached.buffer] });
  for (const value of [shared, detached, new Proxy(new Uint8Array(8), {}), {}, null]) {
    invalid(() => checkedBytes(value, 8));
    invalid(() => bytesToHex(value));
    invalid(() => isZero(value));
  }
});

test("core snapshots own Buffer/subarray bytes and ignore overridden iteration", () => {
  const backing = Buffer.from([9, 1, 2, 3, 9]);
  const value = backing.subarray(1, 4),
    owned = checkedBytes(value, 3);
  backing.fill(7);
  assert.deepEqual([...owned], [1, 2, 3]);
  const hostile = Uint8Array.of(1, 2, 3);
  hostile[Symbol.iterator] = function* () {
    yield 255;
  };
  hostile.every = () => true;
  assert.equal(bytesToHex(hostile), "0x010203");
  assert.equal(isZero(hostile), false);
  assert.equal(compareBytes(hostile, Uint8Array.of(1, 2, 3)), 0);
  assert.deepEqual(keccak256(hostile), keccak256(Uint8Array.of(1, 2, 3)));
  const reader = new Reader(value),
    writer = new Writer(7);
  value.fill(0);
  assert.deepEqual([...reader.fixed(3)], [7, 7, 7]);
  writer.bytes(owned, 3);
  owned.fill(0);
  assert.deepEqual([...writer.finish()], [0, 0, 0, 3, 1, 2, 3]);
});

test("exact core byte boundary and valid fixed width preserve encoding", () => {
  const deep = new Uint8Array(1);
  let prototype = Uint8Array.prototype;
  for (let i = 0; i < 33; i++) prototype = Object.create(prototype);
  Object.setPrototypeOf(deep, prototype);
  invalid(() => checkedBytes(deep, 1), "LIMIT_EXCEEDED");
  const value = new Uint8Array(MAX_TRANSACTION_BYTES);
  assert.equal(bytesToHex(value).length, MAX_TRANSACTION_BYTES * 2 + 2);
  invalid(
    () =>
      checkedBytes(new Uint8Array(MAX_TRANSACTION_BYTES + 1), MAX_TRANSACTION_BYTES),
    "LIMIT_EXCEEDED",
  );
  assert.equal(decodeUint64(Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 1)), 1n);
  assert.equal(decodeUint64(Buffer.from([0, 0, 0, 0, 0, 0, 0, 1])), 1n);
});
