import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  sdk,
  context,
  bytes,
  hex,
  zero,
  vectors,
  policy,
  intent,
  envelope,
  samples,
  rootConfig,
  seeded,
} from "./helpers.mjs";
const golden = JSON.parse(
  readFileSync(new URL("./display/golden/fields.json", import.meta.url)),
);
const values = (review) =>
  Object.fromEntries(review.fields.map((f) => [f.path, f.value]));
const byPath = (review, path) => review.fields.find((f) => f.path === path);
const unsupported = (error) =>
  error instanceof sdk.CodecError && error.code === "UNSUPPORTED_FEATURE";

test("policy golden maps every supported field using independently specified exact values", () => {
  const review = sdk.reviewPolicy(bytes(vectors.policy.canonical));
  assert.equal(
    golden.provenance.chainRevision,
    JSON.parse(readFileSync(new URL("../protocol-source.json", import.meta.url)))
      .revision,
  );
  assert.deepEqual(values(review), golden.policy);
  assert.equal(review.binding.hash, vectors.policy.policyHash);
  assert.equal(review.binding.canonical, vectors.policy.canonical);
  assert.equal(review.binding.hashDomain, "RESILIENCE_POLICY_V1");
  assert.equal(review.binding.network, undefined);
  assert.equal(review.verification, "canonical-structure-only");
});

test("independent native intent, transaction and signing-domain goldens for all schemes/modes/sponsors", () => {
  for (const name of [
    "directTransfer",
    "createGrant",
    "sessionTransfer",
    "p256CreateGrant",
    "p256SessionTransfer",
    "sponsoredTransfer",
  ]) {
    const v = vectors[name];
    const review = sdk.reviewIntent(context, bytes(v.intentCanonical));
    assert.equal(review.binding.hash, v.intentHash);
    assert.equal(review.binding.canonical, v.intentCanonical);
    assert.deepEqual(review.binding.network, vectors.chain);
    const tx = sdk.reviewTransaction(
      context,
      bytes(v.intentCanonical + v.authEnvelopeCanonical.slice(2)),
    );
    assert.equal(tx.binding.hash, v.transactionId);
    assert.equal(tx.binding.hashDomain, "RESILIENCE_TX_ID_V2");
    assert.equal(
      byPath(tx, "envelope.signingDigest").value,
      v.directDigest ?? v.rootDigest ?? v.sessionDigest,
    );
    if (v.sponsorDigest)
      assert.equal(byPath(tx, "envelope.sponsorSigningDigest").value, v.sponsorDigest);
    const fields = values(tx);
    for (const field of [
      "version",
      "chainId",
      "sender",
      "actionType",
      "flags",
      "destination",
      "value",
      "gasLimit",
      "maxFeePerGas",
      "maxPriorityFeePerGas",
      "sponsor",
      "data",
    ])
      assert(Object.hasOwn(fields, `intent.${field}`), `${name}: omitted ${field}`);
    for (const field of [
      "version",
      "mode",
      "keyScheme",
      "credentialId",
      "authEpoch",
      "policyHash",
      "nonce",
      "sponsorNonce",
      "witness",
      "sponsorWitness",
    ])
      assert(Object.hasOwn(fields, `envelope.${field}`), `${name}: omitted ${field}`);
    assert.equal(fields["intent.chainId"], "1337");
    assert.equal(tx.verification, "canonical-structure-only");
  }
});

test("grant golden exposes both key schemes, inclusive/exclusive heights, deposit, every policy field and root witness", () => {
  for (const name of ["createGrant", "p256CreateGrant"]) {
    const review = sdk.reviewIntent(context, bytes(vectors[name].intentCanonical)),
      fields = values(review);
    for (const [path, value] of Object.entries(golden.grant[name]))
      assert.equal(fields[`intent.data.grant.${path}`], value);
    for (const [path, value] of Object.entries(golden.policy))
      assert.equal(fields[`intent.data.grant.${path}`], value);
    assert.match(
      byPath(review, "intent.data.grant.validAfterHeight").meaning,
      /Inclusive/,
    );
    assert.match(
      byPath(review, "intent.data.grant.validUntilHeight").meaning,
      /Exclusive/,
    );
    assert.match(
      byPath(review, "intent.data.grant.keyScheme").meaning,
      /WebAuthn.*different/,
    );
  }
  const tx = sdk.reviewTransaction(
    context,
    bytes(
      vectors.createGrant.intentCanonical +
        vectors.createGrant.authEnvelopeCanonical.slice(2),
    ),
  );
  assert.equal(values(tx)["envelope.rootSignatureCount"], "2");
  vectors.root.sortedKeys.forEach((key, i) =>
    assert.equal(values(tx)[`envelope.rootWitness[${i}].rootKeyId`], key.keyId),
  );
});

test("all control payload fields and epoch/nonce effects have explicit display mappings", () => {
  for (const item of samples().filter((item) => item.kind === "intent")) {
    const i = sdk.txIntentCodec.decode(bytes(item.hex)),
      fields = values(sdk.reviewIntent(context, bytes(item.hex)));
    switch (i.actionType) {
      case sdk.Action.ActivateAuthorization:
        assert.equal(
          fields["intent.data.securityReserve"],
          vectors.root.securityReserve,
        );
        assert.equal(fields["intent.data.config.threshold"], "2");
        assert.equal(fields["intent.data.config.hash"], vectors.root.rootConfigHash);
        vectors.root.sortedKeys.forEach((key, index) => {
          assert.equal(
            fields[`intent.data.config.keys[${index}].rootKeyId`],
            key.keyId,
          );
          assert.equal(
            fields[`intent.data.config.keys[${index}].publicKey`],
            key.publicKey,
          );
          assert.equal(
            fields[`intent.data.config.keys[${index}].keyScheme`],
            "Ed25519",
          );
        });
        break;
      case sdk.Action.RevokeGrant:
        assert.equal(fields["intent.data.grantId"], vectors.createGrant.derivedGrantId);
        break;
      case sdk.Action.ReplaceGrant:
        assert.equal(
          fields["intent.data.oldGrantId"],
          vectors.createGrant.derivedGrantId,
        );
        assert.equal(
          fields["intent.data.newGrant.publicKey"],
          vectors.keys.sessionPublicKey,
        );
        for (const [path, value] of Object.entries(golden.policy))
          assert.equal(fields[`intent.data.newGrant.${path}`], value);
        break;
      case sdk.Action.RotateRoot: {
        const data = sdk.rotateRootCodec.decode(i.data);
        assert.equal(
          fields["intent.data.reserveMode"],
          data.reserveMode ? "replace" : "preserve",
        );
        assert.equal(
          fields["intent.data.replacementReserve"],
          data.reserveMode ? "100" : "0",
        );
        assert.equal(fields["intent.data.config.hash"], vectors.root.rootConfigHash);
        break;
      }
      case sdk.Action.SetSecurityReserve:
        assert.equal(
          fields["intent.data.securityReserve"],
          sdk.setSecurityReserveCodec.decode(i.data).securityReserve.toString(),
        );
        break;
      case sdk.Action.CleanupGrant:
        assert.equal(fields["intent.data.owner"], vectors.keys.owner);
        assert.equal(fields["intent.data.grantId"], vectors.createGrant.derivedGrantId);
        break;
      case sdk.Action.RevokeAllGrants:
        assert.equal(
          fields["intent.data.effect"],
          "advance-epoch-invalidate-all-grants",
        );
        break;
      case sdk.Action.SessionCancel:
        assert.equal(
          fields["intent.data.effect"],
          "consume-session-nonce-without-transfer",
        );
        break;
    }
  }
});

test("zero caps, absent buckets, zero refill and boolean denials never imply unrestricted authority", () => {
  const p = structuredClone(policy);
  p.transfer.limits.maxPerTransaction = 0n;
  p.transfer.limits.lifetimeLimit = 0n;
  p.transfer.limits.valueTokenBucket = { capacity: 1n, refillPerBlock: 0n };
  p.fee.feeTokenBucket = { capacity: (1n << 256n) - 1n, refillPerBlock: 1n };
  p.transfer.allowZeroValue = true;
  p.transfer.allowSelfTransfer = true;
  const review = sdk.reviewPolicy(sdk.policyCodec.encode(p));
  for (const name of ["maxPerTransaction", "lifetimeLimit"]) {
    assert.equal(byPath(review, `policy.transfer.limits.${name}`).value, "0");
    assert.match(
      byPath(review, `policy.transfer.limits.${name}`).meaning,
      /cannot move value.*never unlimited/,
    );
  }
  assert.equal(
    byPath(review, "policy.transfer.limits.valueTokenBucket.enabled").value,
    true,
  );
  assert.match(
    byPath(review, "policy.transfer.limits.valueTokenBucket.refillPerBlock").meaning,
    /never replenish/,
  );
  assert.equal(
    byPath(review, "policy.fee.feeTokenBucket.capacity").value,
    ((1n << 256n) - 1n).toString(),
  );
  assert.equal(byPath(review, "policy.transfer.allowZeroValue").value, true);
  assert.equal(byPath(review, "policy.transfer.allowSelfTransfer").value, true);
  assert.match(
    byPath(
      sdk.reviewPolicy(bytes(vectors.policy.canonical)),
      "policy.fee.feeTokenBucket.enabled",
    ).meaning,
    /other finite limits/,
  );
});

test("Merkle root, count and maximum-depth proof are shown completely with unverified membership", () => {
  const p = {
    ...policy,
    transfer: {
      ...policy.transfer,
      recipients: {
        kind: 1,
        merkleRoot: bytes(vectors.policy.policyHash),
        leafCount: 3,
      },
    },
  };
  const fields = values(sdk.reviewPolicy(sdk.policyCodec.encode(p)));
  assert.equal(fields["policy.transfer.recipients.kind"], "merkle-allowlist");
  assert.equal(
    fields["policy.transfer.recipients.merkleRoot"],
    vectors.policy.policyHash,
  );
  assert.equal(fields["policy.transfer.recipients.leafCount"], "3");
  const tx = {
    intent,
    envelope: sdk.authEnvelopeCodec.decode(
      bytes(vectors.sessionTransfer.authEnvelopeCanonical),
    ),
  };
  tx.envelope.witness = sdk.sessionWitnessCodec.encode({
    signature: zero(64),
    recipientProof: {
      leafIndex: 0xfffffffe,
      leafCount: 0xffffffff,
      siblings: Array.from({ length: 32 }, () => zero(32)),
    },
  });
  const review = sdk.reviewTransaction(context, sdk.transactionCodec.encode(tx));
  assert.equal(values(review)["envelope.recipientProof.leafIndex"], "4294967294");
  assert.equal(
    review.fields.filter((f) => f.path.startsWith("envelope.recipientProof.siblings["))
      .length,
    32,
  );
  assert.match(
    byPath(review, "envelope.recipientProof.present").meaning,
    /does not prove/,
  );
  assert.equal(values(review)["envelope.sessionPublicKey"], "not-in-envelope");
});

test("maximum inline recipient set is never elided and disabled sections remain explicit", () => {
  const sample = samples().find((s) => s.name === "maximum inline recipients");
  const review = sdk.reviewPolicy(bytes(sample.hex));
  assert.equal(values(review)["policy.transfer.recipients.count"], "128");
  assert.equal(
    review.fields.filter((f) => /^policy.transfer.recipients\[/.test(f.path)).length,
    128,
  );
  for (const name of [
    "contractCall",
    "contractCreate",
    "stake",
    "unstake",
    "delegate",
    "claimRewards",
  ])
    assert.equal(values(review)[`policy.${name}.enabled`], false);
});

test("exact base-unit formatting preserves u256, sub-unit tails and rejects unsafe coercion", () => {
  assert.equal(sdk.formatBaseUnits(0n, 18), "0.000000000000000000");
  assert.equal(sdk.formatBaseUnits(1000000000000000001n, 18), "1.000000000000000001");
  assert.equal(sdk.formatBaseUnits(9007199254740993n), "9007199254740993");
  assert.equal(sdk.formatBaseUnits((1n << 256n) - 1n), ((1n << 256n) - 1n).toString());
  assert.equal(sdk.formatBaseUnits(1n, 255).length, 257);
  for (const value of [1, "1", NaN, -1n, 1n << 256n])
    assert.throws(() => sdk.formatBaseUnits(value));
  for (const decimals of [-1, 256, Infinity, 1.5, "18"])
    assert.throws(() => sdk.formatBaseUnits(1n, decimals));
  const max = {
    ...intent,
    value: (1n << 256n) - 1n,
    gasLimit: (1n << 64n) - 1n,
    maxFeePerGas: (1n << 256n) - 1n,
  };
  const review = sdk.reviewIntent(context, sdk.txIntentCodec.encode(max));
  assert.equal(values(review)["intent.value"], ((1n << 256n) - 1n).toString());
  assert.equal(
    values(review)["intent.maximumFee"],
    (((1n << 64n) - 1n) * ((1n << 256n) - 1n)).toString(),
  );
});

test("review snapshots have no mutable arrays/byte references and survive input/context mutation", () => {
  const c = structuredClone(context),
    input = bytes(vectors.policy.canonical);
  const review = sdk.reviewPolicy(input),
    before = JSON.stringify(review);
  input.fill(0);
  c.genesisHash.fill(0);
  assert.equal(JSON.stringify(review), before);
  for (const value of [review, review.binding, review.fields, ...review.fields])
    assert(Object.isFrozen(value));
  assert.throws(() => {
    review.fields[0].value = "spoof";
  }, TypeError);
  assert.throws(() => {
    review.fields.pop();
  }, TypeError);
  const i = bytes(vectors.directTransfer.intentCanonical),
    ctx = structuredClone(context);
  const tx = sdk.reviewIntent(ctx, i),
    original = JSON.stringify(tx);
  i.fill(0);
  ctx.genesisHash.fill(0);
  ctx.chainId = 1n;
  assert.equal(JSON.stringify(tx), original);
  assert(Object.isFrozen(tx.binding.network));
});

test("wrong network and unsupported contract/staking/name/recovery policy or action fail closed", () => {
  assert.throws(
    () =>
      sdk.reviewIntent(
        { ...context, chainId: 1n },
        bytes(vectors.directTransfer.intentCanonical),
      ),
    (e) => e.code === "CONTEXT_MISMATCH",
  );
  for (const code of [1, 2, 3, 4, 5, 6, 0x87, 0xff]) {
    const input = bytes(vectors.directTransfer.intentCanonical);
    input[30] = code;
    assert.throws(() => sdk.reviewIntent(context, input), unsupported);
  }
  for (let section = 0; section < 6; section++) {
    const input = bytes(vectors.policy.canonical);
    input[input.length - 6 + section] = 1;
    assert.throws(() => sdk.reviewPolicy(input), unsupported);
  }
  for (const label of [
    "approved",
    "\u202efee",
    "<script>alert(1)</script>",
    "аpple",
    "validUntil:never",
  ]) {
    assert.throws(
      () =>
        sdk.reviewIntent(
          { ...context, label },
          bytes(vectors.directTransfer.intentCanonical),
        ),
      (e) => e.code === "NON_CANONICAL",
    );
    assert.throws(() => sdk.txIntentCodec.encode({ ...intent, label }));
  }
});

test("truncation, trailing bytes, noncanonical values and bounded deterministic mutations never yield partial reviews", () => {
  for (const [input, review] of [
    [bytes(vectors.policy.canonical), (b) => sdk.reviewPolicy(b)],
    [
      bytes(vectors.directTransfer.intentCanonical),
      (b) => sdk.reviewIntent(context, b),
    ],
    [
      bytes(
        vectors.directTransfer.intentCanonical +
          vectors.directTransfer.authEnvelopeCanonical.slice(2),
      ),
      (b) => sdk.reviewTransaction(context, b),
    ],
  ]) {
    for (let length = 0; length < input.length; length++)
      assert.throws(() => review(input.slice(0, length)));
    assert.throws(() => review(new Uint8Array([...input, 0])));
    const random = seeded();
    for (let i = 0; i < 200; i++) {
      const changed = new Uint8Array(input);
      changed[random() % changed.length] ^= 1 << (random() % 8);
      try {
        const result = review(changed);
        assert.equal(result.binding.canonical, hex(changed));
        assert.equal(
          new Set(result.fields.map((f) => f.path)).size,
          result.fields.length,
        );
        assert.equal(result.verification, "canonical-structure-only");
      } catch (error) {
        assert(error instanceof sdk.CodecError, `${error}`);
      }
    }
  }
  for (const input of [null, undefined, {}, "0x00", new Uint8Array(67012)])
    assert.throws(() => sdk.reviewPolicy(input));
});
