export type CodecErrorCode =
  | "MALFORMED"
  | "NON_CANONICAL"
  | "LIMIT_EXCEEDED"
  | "UNSUPPORTED_VERSION"
  | "UNSUPPORTED_FEATURE"
  | "CONTEXT_MISMATCH";

export class CodecError extends Error {
  constructor(
    public readonly code: CodecErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "CodecError";
  }
}

export function requireCondition(
  condition: unknown,
  message: string,
  code: CodecErrorCode = "MALFORMED",
): asserts condition {
  if (!condition) throw new CodecError(code, message);
}

export const MAX_TRANSACTION_BYTES = 181 + 65_536 + 100 + 1_098 + 96;

export function checkedUint(value: bigint, bits: number): bigint {
  requireCondition(typeof value === "bigint", "Protocol integer must be bigint");
  requireCondition([8, 16, 32, 64, 256].includes(bits), "Unsupported integer width");
  requireCondition(
    value >= 0n && value < 1n << BigInt(bits),
    "Unsigned integer out of range",
  );
  return value;
}

export function checkedNumber(value: number, maximum: number): number {
  requireCondition(
    Number.isSafeInteger(value) && value >= 0 && value <= maximum,
    "Integer out of range",
  );
  return value;
}

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object,
  intrinsicLength = Object.getOwnPropertyDescriptor(
    typedArrayPrototype,
    "length",
  )!.get!,
  intrinsicBuffer = Object.getOwnPropertyDescriptor(
    typedArrayPrototype,
    "buffer",
  )!.get!,
  intrinsicBufferLength = Object.getOwnPropertyDescriptor(
    ArrayBuffer.prototype,
    "byteLength",
  )!.get!;

export function checkedBytes(value: Uint8Array, maximum: number): Uint8Array {
  checkedNumber(maximum, MAX_TRANSACTION_BYTES);
  try {
    requireCondition(value instanceof Uint8Array, "Expected Uint8Array");
    const length = intrinsicLength.call(value) as number;
    intrinsicBufferLength.call(intrinsicBuffer.call(value));
    requireCondition(length <= maximum, "Byte length exceeds limit", "LIMIT_EXCEEDED");
    // Some callers use this as a guard then inspect the original view. Reject
    // shadowed layout properties without invoking their getters in that case.
    let depth = 0;
    for (let prototype: object | null = value; prototype !== typedArrayPrototype;) {
      requireCondition(
        ++depth <= 32,
        "Byte prototype depth exceeds limit",
        "LIMIT_EXCEEDED",
      );
      requireCondition(prototype !== null, "Invalid byte view");
      for (const field of ["length", "buffer", "byteLength", "byteOffset"])
        requireCondition(
          !Object.getOwnPropertyDescriptor(prototype, field),
          "Shadowed byte layout",
        );
      prototype = Object.getPrototypeOf(prototype) as object | null;
    }
    return new Uint8Array(value);
  } catch (error) {
    if (error instanceof CodecError) throw error;
    throw new CodecError("MALFORMED", "Invalid byte view");
  }
}

export function fixedBytes(value: Uint8Array, size: number): Uint8Array {
  const bytes = checkedBytes(value, size);
  requireCondition(bytes.length === size, "Incorrect fixed byte width");
  return bytes;
}

export function isZero(value: Uint8Array): boolean {
  return checkedBytes(value, MAX_TRANSACTION_BYTES).every((byte) => byte === 0);
}

export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  a = checkedBytes(a, MAX_TRANSACTION_BYTES);
  b = checkedBytes(b, MAX_TRANSACTION_BYTES);
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i]! - b[i]!;
  }
  return a.length - b.length;
}

export function bytesToHex(value: Uint8Array): `0x${string}` {
  value = checkedBytes(value, MAX_TRANSACTION_BYTES);
  return `0x${Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export function hexToBytes(value: string, maximum = MAX_TRANSACTION_BYTES): Uint8Array {
  checkedNumber(maximum, MAX_TRANSACTION_BYTES);
  requireCondition(typeof value === "string", "Expected hexadecimal string");
  requireCondition(
    value.length <= maximum * 2 + 2,
    "Hex length exceeds limit",
    "LIMIT_EXCEEDED",
  );
  requireCondition(
    /^0x(?:[0-9a-fA-F]{2})*$/.test(value),
    "Expected 0x-prefixed complete hex bytes",
  );
  return Uint8Array.from(value.slice(2).match(/../g) ?? [], (byte) =>
    Number.parseInt(byte, 16),
  );
}

export function objectFields(value: object, allowed: readonly string[]): void {
  requireCondition(
    value !== null && typeof value === "object",
    "Expected structured value",
  );
  requireCondition(
    Object.keys(value).every((key) => allowed.includes(key)),
    "Unknown structured field",
    "NON_CANONICAL",
  );
}

export function boundedArray<T>(
  value: readonly T[],
  minimum: number,
  maximum: number,
): void {
  requireCondition(Array.isArray(value), "Expected array");
  requireCondition(
    value.length >= minimum && value.length <= maximum,
    "Collection count exceeds bounds",
    "LIMIT_EXCEEDED",
  );
}

/** Internal bounded writer; integer encoding is always big endian. */
export class Writer {
  private readonly parts: Uint8Array[] = [];
  private length = 0;
  constructor(private readonly maximum = MAX_TRANSACTION_BYTES) {}
  fixed(value: Uint8Array, size?: number): void {
    value = checkedBytes(value, this.maximum);
    size ??= value.length;
    value = fixedBytes(value, size);
    requireCondition(
      this.length + size <= this.maximum,
      "Encoded bytes exceed limit",
      "LIMIT_EXCEEDED",
    );
    this.parts.push(new Uint8Array(value));
    this.length += size;
  }
  uint(value: bigint, bits: number): void {
    checkedUint(value, bits);
    const result = new Uint8Array(bits / 8);
    for (let index = result.length - 1; index >= 0; index--) {
      result[index] = Number(value & 255n);
      value >>= 8n;
    }
    this.fixed(result);
  }
  number(value: number, bits: 8 | 16 | 32): void {
    this.uint(BigInt(checkedNumber(value, 2 ** bits - 1)), bits);
  }
  bool(value: boolean): void {
    requireCondition(typeof value === "boolean", "Expected boolean");
    this.number(value ? 1 : 0, 8);
  }
  bytes(value: Uint8Array, maximum: number): void {
    value = checkedBytes(value, maximum);
    this.number(value.length, 32);
    this.fixed(value);
  }
  finish(): Uint8Array {
    const output = new Uint8Array(this.length);
    let offset = 0;
    for (const part of this.parts) {
      output.set(part, offset);
      offset += part.length;
    }
    return output;
  }
}

export class Reader {
  position = 0;
  private readonly bytes: Uint8Array;
  constructor(bytes: Uint8Array) {
    this.bytes = checkedBytes(bytes, MAX_TRANSACTION_BYTES);
  }
  fixed(size: number): Uint8Array {
    requireCondition(
      size <= this.bytes.length - this.position,
      "Truncated canonical bytes",
    );
    const value = this.bytes.slice(this.position, this.position + size);
    this.position += size;
    return value;
  }
  uint(bits: number): bigint {
    let result = 0n;
    for (const byte of this.fixed(bits / 8)) result = (result << 8n) | BigInt(byte);
    return result;
  }
  number(bits: 8 | 16 | 32): number {
    return Number(this.uint(bits));
  }
  bool(): boolean {
    const value = this.number(8);
    requireCondition(value <= 1, "Noncanonical boolean", "NON_CANONICAL");
    return value === 1;
  }
  data(maximum: number): Uint8Array {
    const size = this.number(32);
    requireCondition(
      size <= maximum,
      "Declared length exceeds limit",
      "LIMIT_EXCEEDED",
    );
    return this.fixed(size);
  }
  done(): void {
    requireCondition(
      this.position === this.bytes.length,
      "Trailing canonical bytes",
      "NON_CANONICAL",
    );
  }
}

export interface Codec<T> {
  encode(value: T): Uint8Array;
  decode(bytes: Uint8Array): T;
}

export function codec<T>(
  maximum: number,
  write: (writer: Writer, value: T) => void,
  read: (reader: Reader) => T,
): Codec<T> {
  const encode = (value: T): Uint8Array => {
    const writer = new Writer(maximum);
    write(writer, value);
    return writer.finish();
  };
  return {
    encode,
    decode(bytes) {
      const input = new Uint8Array(checkedBytes(bytes, maximum));
      const reader = new Reader(input);
      const value = read(reader);
      reader.done();
      requireCondition(
        compareBytes(input, encode(value)) === 0,
        "Noncanonical encoding",
        "NON_CANONICAL",
      );
      return value;
    },
  };
}

export function encodeUint64(value: bigint): Uint8Array {
  const writer = new Writer(8);
  writer.uint(value, 64);
  return writer.finish();
}
export function encodeUint256(value: bigint): Uint8Array {
  const writer = new Writer(32);
  writer.uint(value, 256);
  return writer.finish();
}
export function decodeUint64(value: Uint8Array): bigint {
  return new Reader(fixedBytes(value, 8)).uint(64);
}
export function decodeUint256(value: Uint8Array): bigint {
  return new Reader(fixedBytes(value, 32)).uint(256);
}
