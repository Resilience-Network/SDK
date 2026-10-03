import { compareBytes } from "../core/bytes.js";
import { demand, WEBAUTHN_PARSE_LIMITS as limits } from "./errors.js";

export type Cbor =
  | number
  | bigint
  | string
  | boolean
  | null
  | Uint8Array
  | Cbor[]
  | Map<number | string, Cbor>;

/** Narrow CTAP2 canonical CBOR reader; never a permissive alternate decoder. */
export class CborReader {
  offset = 0;
  #items = 0;
  constructor(readonly input: Uint8Array) {}

  #byte() {
    demand(this.offset < this.input.length, "INVALID_CBOR");
    return this.input[this.offset++]!;
  }

  #argument(additional: number): bigint {
    if (additional < 24) return BigInt(additional);
    demand(additional >= 24 && additional <= 27, "INVALID_CBOR");
    const width = 1 << (additional - 24);
    let value = 0n;
    for (let i = 0; i < width; i++) value = (value << 8n) | BigInt(this.#byte());
    const minimum = [24n, 256n, 65536n, 4294967296n][additional - 24]!;
    demand(value >= minimum, "INVALID_CBOR");
    return value;
  }

  read(depth = 0): Cbor {
    demand(++this.#items <= limits.cborItems, "LIMIT_EXCEEDED");
    const head = this.#byte(),
      major = head >>> 5,
      additional = head & 31;
    if (major === 7) {
      demand([20, 21, 22].includes(additional), "INVALID_CBOR");
      return additional === 22 ? null : additional === 21;
    }
    demand(major <= 5, "INVALID_CBOR");
    const argument = this.#argument(additional);
    if (major < 2) {
      const value = major === 0 ? argument : -1n - argument;
      return value >= BigInt(Number.MIN_SAFE_INTEGER) &&
        value <= BigInt(Number.MAX_SAFE_INTEGER)
        ? Number(value)
        : value;
    }
    if (major === 2 || major === 3) {
      demand(argument <= BigInt(limits.attestationObjectBytes), "LIMIT_EXCEEDED");
      const length = Number(argument);
      demand(length <= this.input.length - this.offset, "INVALID_CBOR");
      const bytes = this.input.subarray(this.offset, (this.offset += length));
      if (major === 2) return bytes;
      try {
        return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
      } catch {
        demand(false, "INVALID_CBOR");
      }
    }
    demand(depth < limits.cborDepth, "LIMIT_EXCEEDED");
    demand(argument <= BigInt(limits.cborContainerEntries), "LIMIT_EXCEEDED");
    const length = Number(argument);
    if (major === 4) {
      const array: Cbor[] = [];
      for (let i = 0; i < length; i++) array.push(this.read(depth + 1));
      return array;
    }
    const map = new Map<number | string, Cbor>();
    let previous: Uint8Array | undefined;
    for (let i = 0; i < length; i++) {
      const start = this.offset,
        key = this.read(depth + 1),
        encoded = this.input.subarray(start, this.offset);
      demand(typeof key === "string" || typeof key === "number", "INVALID_CBOR");
      // For supported integer/text keys, CTAP2 order is encoded lexicographic order.
      demand(!previous || compareBytes(previous, encoded) < 0, "INVALID_CBOR");
      demand(!map.has(key), "INVALID_CBOR");
      previous = encoded;
      map.set(key, this.read(depth + 1));
    }
    return map;
  }
}

export function readCbor(input: Uint8Array) {
  const reader = new CborReader(input),
    value = reader.read();
  demand(reader.offset === input.length, "INVALID_CBOR");
  return value;
}
