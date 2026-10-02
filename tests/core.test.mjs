import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  bytes,
  context,
  envelope,
  fixtureCodecs,
  hex,
  intent,
  policy,
  rootConfig,
  samples,
  sdk,
  seeded,
  vectors,
  zero,
} from "./helpers.mjs";

test("checked integer primitives preserve exact u64/u256 values and reject coercion/overflow", () => {
  for (const [width, encode, decode] of [
    [64, sdk.encodeUint64, sdk.decodeUint64],
    [256, sdk.encodeUint256, sdk.decodeUint256],
  ]) {
    for (const n of [0n, 1n, (1n << 53n) + 1n, (1n << BigInt(width)) - 1n])
      assert.equal(decode(encode(n)), n);
    for (const n of [-1n, 1n << BigInt(width), 1, NaN, "1"])
      assert.throws(() => encode(n));
    assert.throws(() => decode(zero(width / 8 - 1)));
  }
  for (const value of ["", "ab", "0Xab", "0xa", "0xgg", "0x00 "])
    assert.throws(() => bytes(value));
  assert.equal(hex(bytes("0xAbCd")), "0xabcd");
  assert.throws(() => bytes("0x00", 0));
});

test("source vectors remain byte-identical to pinned upstream provenance", () => {
  const pin = JSON.parse(
    readFileSync(new URL("../protocol-source.json", import.meta.url)),
  );
  const raw = readFileSync(new URL("./vectors/chain-v1.json", import.meta.url));
  assert.equal(createHash("sha256").update(raw).digest("hex"), pin.vectorSha256);
});

test("independent Keccak known answers reject accidental NIST SHA3 substitution", () => {
  for (const vector of vectors.knownKeccak256)
    assert.equal(hex(sdk.keccak256(bytes(vector.messageHex))), vector.digest);
  assert.notEqual(
    hex(sdk.keccak256(zero(0))),
    `0x${createHash("sha3-256").digest("hex")}`,
  );
});

test("independent canonical vectors and every signature digest/transaction ID", () => {
  assert.equal(hex(sdk.chainDomain(context)), vectors.chain.chainDomain);
  assert.equal(hex(sdk.policyCodec.encode(policy)), vectors.policy.canonical);
  assert.equal(hex(sdk.policyHash(policy)), vectors.policy.policyHash);
  assert.equal(hex(sdk.rootConfigHash(rootConfig)), vectors.root.rootConfigHash);
  for (let i = 0; i < rootConfig.keys.length; i++)
    assert.equal(
      hex(sdk.rootKeyId(rootConfig.keys[i])),
      vectors.root.sortedKeys[i].keyId,
    );
  for (const name of [
    "directTransfer",
    "createGrant",
    "sessionTransfer",
    "p256CreateGrant",
    "p256SessionTransfer",
    "sponsoredTransfer",
  ]) {
    const v = vectors[name],
      i = sdk.txIntentCodec.decode(bytes(v.intentCanonical)),
      e = sdk.authEnvelopeCodec.decode(bytes(v.authEnvelopeCanonical));
    assert.equal(hex(sdk.txIntentCodec.encode(i)), v.intentCanonical);
    assert.equal(hex(sdk.authEnvelopeCodec.encode(e)), v.authEnvelopeCanonical);
    assert.equal(hex(sdk.intentHash(context, i)), v.intentHash);
    assert.equal(hex(sdk.transactionId(context, i, e)), v.transactionId);
    if (v.directDigest)
      assert.equal(hex(sdk.directDigest(context, i, BigInt(v.nonce))), v.directDigest);
    if (v.rootDigest)
      assert.equal(
        hex(sdk.rootDigest(context, i, e.credentialId, e.authEpoch, e.nonce)),
        v.rootDigest,
      );
    if (v.sessionDigest)
      assert.equal(
        hex(
          sdk.sessionDigest(context, i, {
            grantId: e.credentialId,
            authEpoch: e.authEpoch,
            policyHash: e.policyHash,
            nonce: e.nonce,
          }),
        ),
        v.sessionDigest,
      );
    if (v.sponsorDigest)
      assert.equal(
        hex(sdk.sponsorDigest(context, i, bytes(v.sponsor), BigInt(v.sponsorNonce))),
        v.sponsorDigest,
      );
  }
  for (const [name, keys] of [
    ["createGrant", vectors.keys],
    ["p256CreateGrant", vectors.p256Keys],
  ]) {
    const value = sdk.createGrantCodec.decode(bytes(vectors[name].actionData));
    assert.equal(hex(sdk.createGrantCodec.encode(value)), vectors[name].actionData);
    assert.equal(
      hex(
        sdk.grantId(
          context,
          bytes(keys.owner),
          1n,
          0n,
          value.grant.keyScheme,
          value.grant.publicKey,
        ),
      ),
      vectors[name].derivedGrantId,
    );
  }
  assert.equal(
    hex(sdk.sessionKeyFingerprint(2, bytes(vectors.p256Keys.sessionPublicKey))),
    vectors.p256Keys.sessionKeyFingerprint,
  );
});

test("root threshold/order, fixed widths, key scheme and point validation", () => {
  for (const value of [null, undefined, {}, { threshold: 1 }]) {
    assert.throws(
      () => sdk.rootConfigCodec.encode(value),
      (error) => error instanceof sdk.CodecError,
    );
  }
  assert.throws(
    () => sdk.encodeRootWitness(null, 1),
    (error) => error instanceof sdk.CodecError,
  );
  const entries = sdk.decodeRootWitness(bytes(vectors.createGrant.rootWitness), 2);
  assert.equal(hex(sdk.encodeRootWitness(entries, 2)), vectors.createGrant.rootWitness);
  assert.throws(() => sdk.decodeRootWitness(bytes(vectors.createGrant.rootWitness), 1));
  assert.throws(() => sdk.encodeRootWitness([...entries].reverse(), 2));
  assert.throws(() =>
    sdk.rootConfigCodec.encode({ ...rootConfig, keys: [...rootConfig.keys].reverse() }),
  );
  assert.throws(() =>
    sdk.rootConfigCodec.encode({
      ...rootConfig,
      keys: [rootConfig.keys[0], rootConfig.keys[0]],
    }),
  );
  for (const scheme of [1, 2])
    assert.throws(() =>
      sdk.validateSessionPublicKey(scheme, zero(scheme === 1 ? 32 : 64)),
    );
  const identity = zero(32);
  identity[0] = 1;
  assert.throws(() => sdk.validateSessionPublicKey(1, identity));
  sdk.validateSessionPublicKey(1, bytes(vectors.keys.sessionPublicKey));
  sdk.validateSessionPublicKey(2, bytes(vectors.p256Keys.sessionPublicKey));
  assert.throws(() => sdk.sessionKeyFingerprint(1, zero(64))); // wire keys are not padded storage keys
  assert.throws(() => sdk.authEnvelopeCodec.encode({ ...envelope, keyScheme: 2 }));
});

test("reject context mismatch, sponsor inconsistency and unsupported features without dropping fields", () => {
  assert.throws(() => sdk.intentHash({ ...context, chainId: 99n }, intent));
  assert.notEqual(
    hex(sdk.intentHash({ ...context, genesisHash: zero(32) }, intent)),
    vectors.directTransfer.intentHash,
  );
  assert.throws(() =>
    sdk.transactionCodec.encode({
      intent,
      envelope: { ...envelope, sponsorNonce: 1n },
    }),
  );
  assert.throws(() => sdk.txIntentCodec.encode({ ...intent, sponsor: intent.sender }));
  assert.throws(() => sdk.txIntentCodec.encode({ ...intent, actionType: 1 }));
  assert.throws(() => sdk.policyCodec.encode({ ...policy, contractCall: {} }));
  assert.throws(() => sdk.policyCodec.encode({ ...policy, actionMask: 3n }));
  assert.throws(() => sdk.txIntentCodec.encode({ ...intent, flags: 1 }));
  assert.throws(() => sdk.txIntentCodec.encode({ ...intent, gasLimit: 1 }));
  assert.throws(() =>
    sdk.txIntentCodec.encode({
      ...intent,
      maxPriorityFeePerGas: intent.maxFeePerGas + 1n,
    }),
  );
});

test("all supported codecs reject truncation/trailing data and return owned byte copies", () => {
  for (const item of samples()) {
    const codec = fixtureCodecs[item.kind],
      encoded = bytes(item.hex);
    assert.throws(() => codec.decode(encoded.slice(0, -1)), item.name);
    const trailing = new Uint8Array(encoded.length + 1);
    trailing.set(encoded);
    assert.throws(() => codec.decode(trailing), item.name);
    const decoded = codec.decode(encoded),
      canonical = codec.encode(decoded);
    encoded.fill(255);
    assert.equal(hex(codec.encode(decoded)), hex(canonical));
    // Buffer.slice() aliases memory; accepted Uint8Array subclasses must still copy.
    const buffer = Buffer.from(canonical),
      fromBuffer = codec.decode(buffer);
    buffer.fill(255);
    assert.equal(hex(codec.encode(fromBuffer)), hex(canonical));
  }
});

test("bounded declared lengths/counts, booleans, recipient ordering, proof and version cases", () => {
  const invalid = bytes(vectors.directTransfer.intentCanonical);
  invalid.fill(255, 177, 181);
  assert.throws(() => sdk.txIntentCodec.decode(invalid));
  assert.throws(() => sdk.rootConfigCodec.decode(Uint8Array.of(0, 1, 0, 1, 255, 255)));
  assert.throws(() =>
    sdk.sessionWitnessCodec.decode(Uint8Array.from([...zero(64), 2])),
  );
  assert.throws(() =>
    sdk.recipientProofCodec.encode({
      leafIndex: 3,
      leafCount: 3,
      siblings: [zero(32), zero(32)],
    }),
  );
  assert.throws(() =>
    sdk.recipientProofCodec.encode({
      leafIndex: 0,
      leafCount: 3,
      siblings: [zero(32)],
    }),
  );
  const recipients = policy.transfer.recipients.recipients;
  assert.throws(() =>
    sdk.policyCodec.encode({
      ...policy,
      transfer: {
        ...policy.transfer,
        recipients: { kind: 0, recipients: [recipients[0], recipients[0]] },
      },
    }),
  );
  assert.throws(() =>
    sdk.policyCodec.encode({
      ...policy,
      fee: { ...policy.fee, feeTokenBucket: { capacity: 0n, refillPerBlock: 1n } },
    }),
  );
  assert.throws(() =>
    sdk.activateAuthorizationCodec.encode({
      version: 2,
      config: rootConfig,
      securityReserve: 0n,
    }),
  );
  assert.throws(() =>
    sdk.rotateRootCodec.encode({
      version: 1,
      config: rootConfig,
      reserveMode: 0,
      replacementReserve: 1n,
    }),
  );
  assert.throws(() => sdk.revokeGrantCodec.encode({ version: 1, grantId: zero(32) }));
});

test("seeded mutations either reject or reproduce exact accepted canonical bytes", () => {
  const random = seeded();
  let accepted = 0,
    rejected = 0;
  for (const item of samples()) {
    const codec = fixtureCodecs[item.kind],
      source = bytes(item.hex);
    for (let j = 0; j < 32; j++) {
      const candidate = source.slice();
      const position = random() % candidate.length;
      candidate[position] ^= 1 << (random() % 8);
      try {
        assert.equal(hex(codec.encode(codec.decode(candidate))), hex(candidate));
        accepted++;
      } catch (error) {
        assert(error instanceof sdk.CodecError);
        rejected++;
      }
    }
  }
  assert(accepted > 0 && rejected > 0);
});

test("maximum proof/count bounds and oversized inputs fail before declared allocation", () => {
  const proof = {
    leafIndex: 0xfffffffe,
    leafCount: 0xffffffff,
    siblings: Array.from({ length: 32 }, () => zero(32)),
  };
  assert.equal(sdk.recipientProofCodec.encode(proof).length, 1033);
  assert.equal(
    sdk.sessionWitnessCodec.encode({ signature: zero(64), recipientProof: proof })
      .length,
    1098,
  );
  for (const siblings of [
    Array.from({ length: 31 }, () => zero(32)),
    Array.from({ length: 33 }, () => zero(32)),
  ]) {
    assert.throws(() => sdk.recipientProofCodec.encode({ ...proof, siblings }));
  }
  const recipients = Array.from({ length: 128 }, (_, index) => {
    const address = zero(20);
    address[19] = index + 1;
    return address;
  });
  const maximumPolicy = {
    ...policy,
    transfer: { ...policy.transfer, recipients: { kind: 0, recipients } },
  };
  assert.equal(
    sdk.policyCodec.decode(sdk.policyCodec.encode(maximumPolicy)).transfer.recipients
      .recipients.length,
    128,
  );
  assert.throws(() =>
    sdk.policyCodec.encode({
      ...maximumPolicy,
      transfer: {
        ...maximumPolicy.transfer,
        recipients: { kind: 0, recipients: [...recipients, recipients[0]] },
      },
    }),
  );
  for (const [codec, maximum] of [
    [sdk.transactionCodec, 67011],
    [sdk.policyCodec, 16384],
    [sdk.authEnvelopeCodec, 1294],
    [sdk.rootConfigCodec, 270],
  ]) {
    assert.throws(
      () => codec.decode(zero(maximum + 1)),
      (error) => error instanceof sdk.CodecError && error.code === "LIMIT_EXCEEDED",
    );
  }
});

test("storage/recipient/validator hash helpers enforce their domain input contracts", () => {
  for (const value of [0n, -1n, 1n << 64n])
    assert.throws(() =>
      sdk.authorizationActiveKey(value, bytes(vectors.policy.policyHash)),
    );
  assert.throws(() => sdk.authorizationGrantKey(zero(32)));
  assert.throws(() => sdk.authorizationActiveKey(1n, zero(32)));
  assert.throws(() => sdk.recipientLeafHash(context, 0, zero(20)));
  assert.throws(() => sdk.recipientNodeHash(context, 1, zero(32), zero(32)));
  assert.throws(() => sdk.recipientEmptyLeafHash(context, 0, 2 ** 32));
  for (const size of [0, 65529])
    assert.throws(() => sdk.validatorConsensusKeyHash(zero(size)));
  assert.equal(sdk.validatorConsensusKeyHash(zero(65528)).length, 32);
});
