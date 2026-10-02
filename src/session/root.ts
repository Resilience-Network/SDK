import {
  boundedArray,
  codec,
  compareBytes,
  objectFields,
  requireCondition,
  Reader,
  Writer,
} from "../core/bytes.js";
import { rootKeyId } from "./keys.js";
import type {
  RootConfig,
  RootKey,
  RootWitnessEntry,
  RecipientProof,
  SessionWitness,
} from "./types.js";

export function versionOne(value: number): void {
  requireCondition(value === 1, "Unsupported version", "UNSUPPORTED_VERSION");
}

export function writeRootBody(writer: Writer, config: RootConfig): void {
  objectFields(config, ["version", "threshold", "keys"]);
  versionOne(config.version);
  boundedArray(config.keys, 1, 8);
  requireCondition(
    config.threshold > 0 && config.threshold <= config.keys.length,
    "Invalid root threshold",
  );
  writer.number(config.threshold, 16);
  writer.number(config.keys.length, 16);
  let previous: Uint8Array | undefined;
  for (const key of config.keys) {
    objectFields(key, ["keyScheme", "publicKey"]);
    const id = rootKeyId(key);
    requireCondition(
      !previous || compareBytes(previous, id) < 0,
      "Root keys not strictly sorted",
      "NON_CANONICAL",
    );
    writer.number(key.keyScheme, 8);
    writer.fixed(key.publicKey, 32);
    previous = id;
  }
}

export function readRootBody(reader: Reader): RootConfig {
  const threshold = reader.number(16),
    count = reader.number(16);
  requireCondition(
    count > 0 && count <= 8,
    "Root key count exceeds bounds",
    "LIMIT_EXCEEDED",
  );
  const keys: RootKey[] = [];
  for (let index = 0; index < count; index++)
    keys.push({ keyScheme: reader.number(8) as 1, publicKey: reader.fixed(32) });
  return { version: 1, threshold, keys };
}

export const rootConfigCodec = codec<RootConfig>(
  270,
  (w, v) => {
    objectFields(v, ["version", "threshold", "keys"]);
    versionOne(v.version);
    w.number(v.version, 16);
    writeRootBody(w, v);
  },
  (r) => {
    versionOne(r.number(16));
    return readRootBody(r);
  },
);

function writeRootWitness(w: Writer, entries: readonly RootWitnessEntry[]): void {
  boundedArray(entries, 1, 8);
  w.number(entries.length, 16);
  let previous: Uint8Array | undefined;
  for (const entry of entries) {
    objectFields(entry, ["rootKeyId", "signature"]);
    w.fixed(entry.rootKeyId, 32);
    w.fixed(entry.signature, 64);
    requireCondition(
      !previous || compareBytes(previous, entry.rootKeyId) < 0,
      "Root witness not strictly sorted",
      "NON_CANONICAL",
    );
    previous = entry.rootKeyId;
  }
}
const rootWitnessStructure = codec<readonly RootWitnessEntry[]>(
  770,
  writeRootWitness,
  (r) => {
    const count = r.number(16);
    requireCondition(count > 0 && count <= 8, "Root witness count", "LIMIT_EXCEEDED");
    return Array.from({ length: count }, () => ({
      rootKeyId: r.fixed(32),
      signature: r.fixed(64),
    }));
  },
);

export function encodeRootWitness(
  entries: readonly RootWitnessEntry[],
  threshold: number,
): Uint8Array {
  boundedArray(entries, 1, 8);
  requireCondition(
    threshold > 0 && threshold <= 8 && entries.length === threshold,
    "Root witness must equal threshold",
    "NON_CANONICAL",
  );
  return rootWitnessStructure.encode(entries);
}
export function decodeRootWitness(
  bytes: Uint8Array,
  threshold: number,
): readonly RootWitnessEntry[] {
  const entries = rootWitnessStructure.decode(bytes);
  requireCondition(
    entries.length === threshold && threshold > 0 && threshold <= 8,
    "Root witness must equal threshold",
    "NON_CANONICAL",
  );
  return entries;
}
export function validateRootWitnessStructure(bytes: Uint8Array): void {
  rootWitnessStructure.decode(bytes);
}

function writeProof(w: Writer, proof: RecipientProof): void {
  objectFields(proof, ["leafIndex", "leafCount", "siblings"]);
  requireCondition(
    proof.leafCount > 0 && proof.leafIndex < proof.leafCount,
    "Invalid recipient proof position",
    "NON_CANONICAL",
  );
  w.number(proof.leafIndex, 32);
  w.number(proof.leafCount, 32);
  boundedArray(proof.siblings, 0, 32);
  let depth = 0,
    remaining = BigInt(proof.leafCount - 1);
  while (remaining > 0n) {
    depth++;
    remaining >>= 1n;
  }
  requireCondition(
    proof.siblings.length === depth,
    "Recipient proof depth does not match count",
    "NON_CANONICAL",
  );
  w.number(depth, 8);
  for (const sibling of proof.siblings) w.fixed(sibling, 32);
}
function readProof(r: Reader): RecipientProof {
  const leafIndex = r.number(32),
    leafCount = r.number(32),
    count = r.number(8);
  requireCondition(
    count <= 32,
    "Recipient proof depth exceeds limit",
    "LIMIT_EXCEEDED",
  );
  return {
    leafIndex,
    leafCount,
    siblings: Array.from({ length: count }, () => r.fixed(32)),
  };
}
export const recipientProofCodec = codec<RecipientProof>(1033, writeProof, readProof);
export const sessionWitnessCodec = codec<SessionWitness>(
  1098,
  (w, v) => {
    objectFields(v, ["signature", "recipientProof"]);
    w.fixed(v.signature, 64);
    w.bool(v.recipientProof !== undefined);
    if (v.recipientProof !== undefined) writeProof(w, v.recipientProof);
  },
  (r) => {
    const signature = r.fixed(64);
    return r.bool() ? { signature, recipientProof: readProof(r) } : { signature };
  },
);
