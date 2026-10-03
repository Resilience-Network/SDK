import {
  demand,
  guarded,
  ownedBytes,
  WEBAUTHN_PARSE_LIMITS as limits,
} from "./errors.js";

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function decodeBase64url(value: string, maximum: number): Uint8Array {
  demand(
    typeof value === "string" && /^[A-Za-z0-9_-]+$/.test(value),
    "INVALID_CLIENT_DATA",
  );
  demand(value.length % 4 !== 1, "INVALID_CLIENT_DATA");
  const length = Math.floor((value.length * 6) / 8);
  demand(length > 0 && length <= maximum, "LIMIT_EXCEEDED");
  const bytes = new Uint8Array(length);
  let accumulator = 0,
    bits = 0,
    offset = 0;
  for (const char of value) {
    accumulator = (accumulator << 6) | alphabet.indexOf(char);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes[offset++] = accumulator >>> bits;
      accumulator &= (1 << bits) - 1;
    }
  }
  demand(accumulator === 0, "INVALID_CLIENT_DATA");
  return bytes;
}

type Json = string | number | boolean | null | Json[] | { [key: string]: Json };

class JsonReader {
  #offset = 0;
  #items = 0;
  constructor(readonly text: string) {}
  #space() {
    while (/[ \t\r\n]/.test(this.text[this.#offset] ?? "!")) this.#offset++;
  }
  #item() {
    demand(++this.#items <= limits.jsonItems, "LIMIT_EXCEEDED");
  }
  #string(): string {
    demand(this.text[this.#offset] === '"', "INVALID_CLIENT_DATA");
    const start = this.#offset++;
    let escaped = false;
    while (this.#offset < this.text.length) {
      const char = this.text[this.#offset++]!;
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') {
        let value: string;
        try {
          value = JSON.parse(this.text.slice(start, this.#offset)) as string;
        } catch {
          demand(false, "INVALID_CLIENT_DATA");
        }
        for (let i = 0; i < value.length; i++) {
          const unit = value.charCodeAt(i);
          if (unit >= 0xd800 && unit <= 0xdbff) {
            const next = value.charCodeAt(++i);
            demand(next >= 0xdc00 && next <= 0xdfff, "INVALID_CLIENT_DATA");
          } else demand(unit < 0xdc00 || unit > 0xdfff, "INVALID_CLIENT_DATA");
        }
        return value;
      }
    }
    demand(false, "INVALID_CLIENT_DATA");
  }
  #read(depth: number): Json {
    this.#space();
    this.#item();
    const char = this.text[this.#offset];
    if (char === '"') return this.#string();
    if (char === "{" || char === "[") {
      demand(depth < limits.jsonDepth, "LIMIT_EXCEEDED");
      const object = char === "{",
        close = object ? "}" : "]",
        values: Json[] = [],
        entries = Object.create(null) as { [key: string]: Json },
        keys = new Set<string>();
      let count = 0;
      this.#offset++;
      this.#space();
      if (this.text[this.#offset] !== close) {
        while (true) {
          demand(++count <= limits.jsonContainerEntries, "LIMIT_EXCEEDED");
          if (object) {
            this.#item();
            const key = this.#string();
            demand(!keys.has(key), "INVALID_CLIENT_DATA");
            keys.add(key);
            this.#space();
            demand(this.text[this.#offset++] === ":", "INVALID_CLIENT_DATA");
            entries[key] = this.#read(depth + 1);
          } else values.push(this.#read(depth + 1));
          this.#space();
          if (this.text[this.#offset] !== ",") break;
          this.#offset++;
          this.#space();
        }
      }
      demand(this.text[this.#offset++] === close, "INVALID_CLIENT_DATA");
      return object ? entries : values;
    }
    for (const [literal, value] of [
      ["true", true],
      ["false", false],
      ["null", null],
    ] as const) {
      if (this.text.startsWith(literal, this.#offset)) {
        this.#offset += literal.length;
        return value;
      }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(
      this.text.slice(this.#offset),
    );
    demand(number !== null, "INVALID_CLIENT_DATA");
    const value = Number(number[0]);
    demand(Number.isFinite(value), "INVALID_CLIENT_DATA");
    demand(
      !Number.isInteger(value) || Number.isSafeInteger(value),
      "INVALID_CLIENT_DATA",
    );
    this.#offset += number[0].length;
    return value;
  }
  read() {
    const value = this.#read(0);
    this.#space();
    demand(this.#offset === this.text.length, "INVALID_CLIENT_DATA");
    return value;
  }
}

export interface ParsedClientData {
  readonly original: Uint8Array;
  readonly type: "webauthn.create" | "webauthn.get";
  readonly challenge: Uint8Array;
  readonly origin: string;
  readonly crossOrigin: boolean;
  readonly topOrigin?: string;
}

/** Observed fields only. The RP must independently bind type/challenge/origin. */
export function parseClientDataJSON(input: Uint8Array): ParsedClientData {
  return guarded(() => {
    const original = ownedBytes(input, limits.clientDataBytes);
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
        original,
      );
    } catch {
      demand(false, "INVALID_CLIENT_DATA");
    }
    const object = new JsonReader(text).read();
    demand(
      object !== null && typeof object === "object" && !Array.isArray(object),
      "INVALID_CLIENT_DATA",
    );
    const { type, challenge, origin, crossOrigin, topOrigin } = object;
    demand(
      type === "webauthn.create" || type === "webauthn.get",
      "INVALID_CLIENT_DATA",
    );
    demand(typeof challenge === "string", "INVALID_CLIENT_DATA");
    demand(typeof origin === "string" && origin.length > 0, "INVALID_CLIENT_DATA");
    demand(
      crossOrigin === undefined || typeof crossOrigin === "boolean",
      "INVALID_CLIENT_DATA",
    );
    demand(
      topOrigin === undefined ||
        (typeof topOrigin === "string" && topOrigin.length > 0),
      "INVALID_CLIENT_DATA",
    );
    return {
      original,
      type,
      challenge: decodeBase64url(challenge, limits.challengeBytes),
      origin,
      crossOrigin: crossOrigin ?? false,
      ...(topOrigin === undefined ? {} : { topOrigin }),
    };
  });
}
