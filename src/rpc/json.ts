import { RpcClientError } from "./errors.js";
import type { JsonValue } from "./types.js";

const MAX_DEPTH = 64;
const MAX_NODES = 100_000;

/** Serialize owned JSON data without invoking getters or toJSON hooks. */
export function encodeRequest(value: unknown, maxBytes: number): string {
  const chunks: string[] = [];
  const ancestors = new Set<object>();
  const encoder = new TextEncoder();
  let bytes = 0;
  let nodes = 0;
  const invalid = () => new RpcClientError("INVALID_REQUEST");
  const limit = () => new RpcClientError("REQUEST_LIMIT");
  const append = (chunk: string) => {
    bytes += encoder.encode(chunk).byteLength;
    if (bytes > maxBytes) throw limit();
    chunks.push(chunk);
  };
  const string = (text: string) => {
    if (text.length > maxBytes) throw limit();
    append(JSON.stringify(text));
  };
  const visit = (item: unknown, depth: number): void => {
    if (depth > MAX_DEPTH || ++nodes > MAX_NODES) throw limit();
    if (item === null || typeof item === "boolean") {
      append(String(item));
    } else if (typeof item === "string") {
      string(item);
    } else if (typeof item === "number") {
      if (
        !Number.isFinite(item) ||
        (Number.isInteger(item) && !Number.isSafeInteger(item))
      )
        throw invalid();
      append(JSON.stringify(item));
    } else if (typeof item === "object") {
      if (ancestors.has(item)) throw invalid();
      ancestors.add(item);
      const array = Array.isArray(item);
      if (array && item.length > MAX_NODES) throw limit();
      if (
        !array &&
        Object.getPrototypeOf(item) !== Object.prototype &&
        Object.getPrototypeOf(item) !== null
      )
        throw invalid();
      const keys = Object.keys(item);
      if (keys.length > MAX_NODES) throw limit();
      if (array && keys.length !== item.length) throw invalid();
      // No ignored symbol fields, non-enumerable fields or serialization hooks.
      if (Reflect.ownKeys(item).length !== keys.length + (array ? 1 : 0))
        throw invalid();
      append(array ? "[" : "{");
      keys.forEach((key, index) => {
        if (array && key !== String(index)) throw invalid();
        if (!array && key === "toJSON") throw invalid();
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        if (!descriptor || !("value" in descriptor)) throw invalid();
        if (index > 0) append(",");
        if (!array) {
          string(key);
          append(":");
        }
        visit(descriptor.value, depth + 1);
      });
      append(array ? "]" : "}");
      ancestors.delete(item);
    } else {
      throw invalid();
    }
  };
  visit(value, 0);
  return chunks.join("");
}

/** Bounded JSON parser: duplicate keys and unsafe integer values fail closed. */
export function parseResponse(text: string, attempts: number): JsonValue {
  let at = 0;
  let nodes = 0;
  const numberToken = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
  const invalid = () => new RpcClientError("INVALID_JSON", attempts);
  const whitespace = () => {
    while (at < text.length && /[ \t\r\n]/.test(text[at]!)) at++;
  };
  const string = (): string => {
    const start = at++;
    while (at < text.length) {
      const char = text[at++];
      if (char === "\\") at++;
      else if (char === '"') {
        try {
          return JSON.parse(text.slice(start, at)) as string;
        } catch {
          throw invalid();
        }
      }
    }
    throw invalid();
  };
  const value = (depth: number): JsonValue => {
    if (depth > MAX_DEPTH || ++nodes > MAX_NODES)
      throw new RpcClientError("RESPONSE_LIMIT", attempts);
    whitespace();
    const char = text[at];
    if (char === '"') return string();
    if (char === "[" || char === "{") {
      const array = char === "[";
      const end = array ? "]" : "}";
      const result: JsonValue[] | Record<string, JsonValue> = array ? [] : {};
      const keys = new Set<string>();
      at++;
      whitespace();
      if (text[at] === end) {
        at++;
        return result;
      }
      for (;;) {
        let key = "";
        if (!array) {
          if (text[at] !== '"') throw invalid();
          key = string();
          if (keys.has(key)) throw invalid();
          keys.add(key);
          whitespace();
          if (text[at++] !== ":") throw invalid();
        }
        const next = value(depth + 1);
        if (Array.isArray(result)) result.push(next);
        else
          Object.defineProperty(result, key, {
            value: next,
            enumerable: true,
            writable: true,
            configurable: true,
          });
        whitespace();
        const separator = text[at++];
        if (separator === end) return result;
        if (separator !== ",") throw invalid();
        whitespace();
      }
    }
    for (const [literal, result] of [
      ["true", true],
      ["false", false],
      ["null", null],
    ] as const) {
      if (text.startsWith(literal, at)) {
        at += literal.length;
        return result;
      }
    }
    numberToken.lastIndex = at;
    const token = numberToken.exec(text)?.[0];
    if (!token) throw invalid();
    at += token.length;
    const number = Number(token);
    if (
      !Number.isFinite(number) ||
      (Number.isInteger(number) && !Number.isSafeInteger(number))
    )
      throw invalid();
    return number;
  };
  const result = value(0);
  whitespace();
  if (at !== text.length) throw invalid();
  return result;
}
