import { readFileSync } from "node:fs";
import * as sdk from "../dist/index.js";

export { sdk };
export const vectors = JSON.parse(
  readFileSync(new URL("./vectors/chain-v1.json", import.meta.url), "utf8"),
);
export const bytes = sdk.hexToBytes;
export const hex = sdk.bytesToHex;
export const zero = (size) => new Uint8Array(size);
export const context = {
  chainId: BigInt(vectors.chain.chainId),
  genesisHash: bytes(vectors.chain.genesisHash),
};
export const rootConfig = {
  version: 1,
  threshold: vectors.root.threshold,
  keys: vectors.root.sortedKeys.map((key) => ({
    keyScheme: 1,
    publicKey: bytes(key.publicKey),
  })),
};
export const policy = sdk.policyCodec.decode(bytes(vectors.policy.canonical));
export const intent = sdk.txIntentCodec.decode(
  bytes(vectors.directTransfer.intentCanonical),
);
export const envelope = sdk.authEnvelopeCodec.decode(
  bytes(vectors.directTransfer.authEnvelopeCanonical),
);

export const fixtureCodecs = {
  intent: sdk.txIntentCodec,
  envelope: sdk.authEnvelopeCodec,
  transaction: sdk.transactionCodec,
  policy: sdk.policyCodec,
  root: sdk.rootConfigCodec,
  create: sdk.createGrantCodec,
  activate: sdk.activateAuthorizationCodec,
  revoke: sdk.revokeGrantCodec,
  replace: sdk.replaceGrantCodec,
  rotate: sdk.rotateRootCodec,
  reserve: sdk.setSecurityReserveCodec,
  cleanup: sdk.cleanupGrantCodec,
  proof: sdk.recipientProofCodec,
  sessionWitness: sdk.sessionWitnessCodec,
};

export function samples() {
  const samples = [];
  const add = (kind, value, name = kind) =>
    samples.push({ kind, name, hex: hex(fixtureCodecs[kind].encode(value)) });
  for (const name of [
    "directTransfer",
    "createGrant",
    "sessionTransfer",
    "p256CreateGrant",
    "p256SessionTransfer",
    "sponsoredTransfer",
  ]) {
    const v = vectors[name];
    const i = sdk.txIntentCodec.decode(bytes(v.intentCanonical)),
      e = sdk.authEnvelopeCodec.decode(bytes(v.authEnvelopeCanonical));
    add("intent", i, name);
    add("envelope", e, name);
    add("transaction", { intent: i, envelope: e }, name);
  }
  add("root", rootConfig);
  add("policy", policy);
  const grant = sdk.createGrantCodec.decode(
    bytes(vectors.createGrant.actionData),
  ).grant;
  add("create", { version: 1, grant });
  add(
    "create",
    sdk.createGrantCodec.decode(bytes(vectors.p256CreateGrant.actionData)),
    "P256 grant",
  );
  add("activate", {
    version: 1,
    config: rootConfig,
    securityReserve: BigInt(vectors.root.securityReserve),
  });
  add("revoke", { version: 1, grantId: bytes(vectors.createGrant.derivedGrantId) });
  add("replace", {
    version: 1,
    oldGrantId: bytes(vectors.createGrant.derivedGrantId),
    newGrant: grant,
  });
  for (const reserveMode of [0, 1])
    add("rotate", {
      version: 1,
      config: rootConfig,
      reserveMode,
      replacementReserve: reserveMode ? 100n : 0n,
    });
  add("reserve", { version: 1, securityReserve: 0n });
  add(
    "reserve",
    { version: 1, securityReserve: (1n << 256n) - 1n },
    "max u256 reserve",
  );
  add("cleanup", {
    version: 1,
    owner: bytes(vectors.keys.owner),
    grantId: bytes(vectors.createGrant.derivedGrantId),
  });
  const proof = {
    leafIndex: 2,
    leafCount: 3,
    siblings: [bytes(vectors.policy.policyHash), bytes(vectors.root.rootConfigHash)],
  };
  add("proof", proof);
  add("sessionWitness", { signature: zero(64), recipientProof: proof });
  add("sessionWitness", { signature: zero(64) });
  const maxProof = {
    leafIndex: 0xfffffffe,
    leafCount: 0xffffffff,
    siblings: Array.from({ length: 32 }, () => zero(32)),
  };
  add("proof", maxProof, "maximum depth");
  add(
    "sessionWitness",
    { signature: zero(64), recipientProof: maxProof },
    "maximum witness",
  );
  const maxRootEntries = Array.from({ length: 8 }, (_, index) => {
    const rootKeyId = zero(32);
    rootKeyId[31] = index + 1;
    return { rootKeyId, signature: zero(64) };
  });
  const rootEnvelope = sdk.authEnvelopeCodec.decode(
    bytes(vectors.createGrant.authEnvelopeCanonical),
  );
  add(
    "envelope",
    { ...rootEnvelope, witness: sdk.encodeRootWitness(maxRootEntries, 8) },
    "maximum root witness",
  );
  const sessionEnvelope = sdk.authEnvelopeCodec.decode(
    bytes(vectors.sessionTransfer.authEnvelopeCanonical),
  );
  add(
    "envelope",
    {
      ...sessionEnvelope,
      witness: sdk.sessionWitnessCodec.encode({
        signature: zero(64),
        recipientProof: maxProof,
      }),
      sponsorWitness: zero(96),
    },
    "maximum envelope",
  );
  const recipients = Array.from({ length: 128 }, (_, index) => {
    const address = zero(20);
    address[19] = index + 1;
    return address;
  });
  add(
    "policy",
    {
      ...policy,
      transfer: { ...policy.transfer, recipients: { kind: 0, recipients } },
    },
    "maximum inline recipients",
  );
  add(
    "policy",
    {
      ...policy,
      fee: { ...policy.fee, feeTokenBucket: { capacity: 1000n, refillPerBlock: 3n } },
      transfer: {
        ...policy.transfer,
        limits: {
          ...policy.transfer.limits,
          valueTokenBucket: { capacity: 999n, refillPerBlock: 0n },
        },
      },
    },
    "buckets",
  );
  add(
    "policy",
    {
      ...policy,
      transfer: {
        ...policy.transfer,
        recipients: {
          kind: 1,
          merkleRoot: bytes(vectors.policy.policyHash),
          leafCount: 3,
        },
      },
    },
    "Merkle recipients",
  );
  // Exercise every supported action as a complete intent as well as its payload.
  const kindActions = {
    activate: 0x80,
    create: 0x81,
    revoke: 0x82,
    replace: 0x83,
    rotate: 0x85,
    reserve: 0x86,
    cleanup: 8,
  };
  for (const item of [...samples])
    if (item.kind in kindActions)
      add(
        "intent",
        {
          ...intent,
          actionType: kindActions[item.kind],
          destination: zero(20),
          value: 0n,
          data: bytes(item.hex),
        },
        `${item.kind} intent`,
      );
  for (const actionType of [7, 0x84])
    add(
      "intent",
      { ...intent, actionType, destination: zero(20), value: 0n, data: zero(0) },
      `empty action ${actionType}`,
    );
  return samples;
}

/** Deterministic xorshift32 seed; retained here for reproducible mutation failures. */
export function seeded(seed = 0x01325602) {
  let state = seed;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}
