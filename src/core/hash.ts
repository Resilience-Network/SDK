import { keccak_256 } from "@noble/hashes/sha3.js";
import { checkedBytes, MAX_TRANSACTION_BYTES } from "./bytes.js";

/** Original Keccak padding; this is intentionally not NIST SHA3-256. */
export function keccak256(...parts: Uint8Array[]): Uint8Array {
  const state = keccak_256.create();
  for (const part of parts) state.update(checkedBytes(part, MAX_TRANSACTION_BYTES));
  return state.digest();
}

export function domainHash(domain: string, ...parts: Uint8Array[]): Uint8Array {
  return keccak256(new TextEncoder().encode(domain), ...parts);
}
