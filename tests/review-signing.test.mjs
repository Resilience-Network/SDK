import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { sdk, bytes, hex, zero, vectors, context } from "./helpers.mjs";
import {
  directOptions,
  rootInput,
  sessionOptions,
  p256Signer,
  edSigner,
  deferred,
  code,
} from "./signer-helpers.mjs";
const fields = (r) => Object.fromEntries(r.fields.map((f) => [f.path, f.value]));
const modes = [
  [directOptions, sdk.signDirectTransaction],
  [rootInput, sdk.signRootTransaction],
  [sessionOptions, sdk.signSessionTransaction],
  [() => sessionOptions(p256Signer()), sdk.signSessionTransaction],
];
function counting(options) {
  let count = 0;
  for (const signer of options.signers ?? [options.signer]) {
    const original = signer.sign;
    signer.sign = async (...args) => {
      count++;
      return original.apply(signer, args);
    };
  }
  return () => count;
}
function frozen(value) {
  if (value === null || typeof value !== "object") return;
  assert(Object.isFrozen(value));
  for (const entry of Object.values(value)) frozen(entry);
}
function placeholder(tx) {
  tx = sdk.transactionCodec.decode(sdk.transactionCodec.encode(tx));
  if (tx.envelope.mode === 0) tx.envelope.witness.fill(0, 32);
  else if (tx.envelope.mode === 1)
    tx.envelope.witness = sdk.encodeRootWitness(
      sdk
        .decodeRootWitness(
          tx.envelope.witness,
          (tx.envelope.witness[0] << 8) | tx.envelope.witness[1],
        )
        .map((entry) => ({ ...entry, signature: zero(64) })),
      (tx.envelope.witness[0] << 8) | tx.envelope.witness[1],
    );
  else {
    const witness = sdk.sessionWitnessCodec.decode(tx.envelope.witness);
    witness.signature.fill(0);
    tx.envelope.witness = sdk.sessionWitnessCodec.encode(witness);
  }
  return sdk.transactionCodec.encode(tx);
}

test("review callback binds every scheme/mode to the exact subsequently signed template, digest and public authority", async () => {
  for (const [make, sign] of modes) {
    const options = make(),
      calls = counting(options);
    let request;
    options.approve = (r) => {
      assert.equal(calls(), 0);
      request = r;
      assert(Object.isFrozen(r));
      frozen(r.review);
      assert.equal(r.review.signaturePlaceholder, "64-zero-bytes");
      assert.equal(r.review.reviewHashDomain, "RESILIENCE_SDK_SIGNING_REVIEW_V1");
      assert.equal(
        r.review.signingDigest,
        fields(r.review.transactionTemplate)["envelope.signingDigest"],
      );
      assert.equal(
        r.review.intent.binding.canonical,
        hex(sdk.txIntentCodec.encode(options.intent)),
      );
      assert.equal(
        r.review.intent.binding.hash,
        hex(sdk.intentHash(options.context, options.intent)),
      );
      assert.notEqual(r.signal, options.signal);
      assert.equal(r.signal.aborted, false);
      return true;
    };
    const tx = await sign(options);
    assert.equal(
      hex(placeholder(tx)),
      request.review.transactionTemplate.binding.canonical,
    );
    assert.equal(calls(), options.signers?.length ?? 1);
    assert.equal(request.signal.aborted, true);
    assert.notEqual(
      hex(sdk.transactionId(options.context, tx.intent, tx.envelope)),
      request.review.transactionTemplate.binding.hash,
    );
    if (tx.envelope.mode === 1) {
      assert.equal(request.review.authority.threshold, options.config.threshold);
      assert.equal(
        request.review.authority.configCanonical,
        hex(sdk.rootConfigCodec.encode(options.config)),
      );
      assert.equal(request.review.authority.keys.length, options.config.keys.length);
      assert.deepEqual(
        request.review.authority.selectedKeyIds,
        sdk
          .decodeRootWitness(tx.envelope.witness, options.config.threshold)
          .map((e) => hex(e.rootKeyId)),
      );
    } else {
      assert.equal(request.review.authority.publicKey, hex(options.signer.publicKey));
      assert.equal(
        request.review.authority.keyFingerprint,
        hex(
          sdk.sessionKeyFingerprint(options.signer.keyScheme, options.signer.publicKey),
        ),
      );
    }
  }
});

test("only literal true approves; reviewer errors and forged diagnostics are redacted before any signer", async () => {
  for (const [make, sign] of modes) {
    for (const value of [false, undefined, null, "true", 1, {}, { approved: true }]) {
      const options = make(),
        calls = counting(options);
      options.approve = () => value;
      await assert.rejects(sign(options), code("REVIEW_REJECTED"));
      assert.equal(calls(), 0);
    }
    const options = make(),
      calls = counting(options);
    options.approve = () => {
      throw {
        get code() {
          throw Error("secret");
        },
        message: "secret",
        name: "SignerError",
      };
    };
    await assert.rejects(
      sign(options),
      (error) =>
        error instanceof sdk.SignerError &&
        error.code === "REVIEW_FAILED" &&
        !String(error).includes("secret"),
    );
    assert.equal(calls(), 0);
    await assert.rejects(
      sign({ ...make(), approve: true }),
      (error) => error instanceof sdk.CodecError,
    );
  }
});

const intentMutations = [
  (o) => {
    o.intent.version = 3;
  },
  (o) => {
    o.intent.chainId++;
  },
  (o) => {
    o.intent.sender[0] ^= 1;
  },
  (o) => {
    o.intent.actionType = sdk.Action.SessionCancel;
    o.intent.destination.fill(0);
    o.intent.value = 0n;
  },
  (o) => {
    o.intent.flags = 1;
  },
  (o) => {
    o.intent.destination[0] ^= 1;
  },
  (o) => {
    o.intent.value++;
  },
  (o) => {
    o.intent.gasLimit++;
  },
  (o) => {
    o.intent.maxFeePerGas++;
  },
  (o) => {
    o.intent.maxPriorityFeePerGas = 0n;
  },
  (o) => {
    o.intent.sponsor[0] = 1;
  },
  (o) => {
    o.intent.data = Uint8Array.of(0);
  },
  (o) => {
    o.context.chainId++;
  },
  (o) => {
    o.context.genesisHash[0] ^= 1;
  },
  (o) => {
    o.approve = () => true;
  },
];
test("every common intent/network/approval mutation during async review fails before signing", async () => {
  for (const [make, sign] of modes)
    for (const mutate of intentMutations) {
      const options = make(),
        calls = counting(options),
        gate = deferred(),
        entered = deferred();
      options.approve = () => {
        entered.resolve();
        return gate.promise;
      };
      const pending = sign(options);
      await entered.promise;
      mutate(options);
      gate.resolve(true);
      await assert.rejects(pending, code("MUTATED_INPUT"));
      assert.equal(calls(), 0);
    }
});

test("every root authority, credential, signer and proof field is guarded through async review", async () => {
  const cases = [
    [
      rootInput,
      sdk.signRootTransaction,
      [
        (o) => {
          o.nonce++;
        },
        (o) => {
          o.authEpoch++;
        },
        (o) => {
          o.config.version = 2;
        },
        (o) => {
          o.config.threshold = 1;
        },
        (o) => {
          o.config.keys[0].keyScheme = 2;
        },
        (o) => {
          o.config.keys[0].publicKey[0] ^= 1;
        },
        (o) => {
          o.config.keys.pop();
        },
        (o) => {
          o.signers.reverse();
        },
        (o) => {
          o.signers[0].publicKey[0] ^= 1;
        },
        (o) => {
          o.signers[0].sign = async () => {};
        },
        (o) => {
          o.signers[0].keyScheme = 2;
        },
      ],
    ],
    [
      directOptions,
      sdk.signDirectTransaction,
      [
        (o) => {
          o.nonce++;
        },
        (o) => {
          o.signer.publicKey[0] ^= 1;
        },
        (o) => {
          o.signer.keyScheme = 2;
        },
        (o) => {
          o.signer.sign = async () => {};
        },
      ],
    ],
    [
      () => ({
        ...sessionOptions(),
        recipientProof: { leafIndex: 0, leafCount: 2, siblings: [zero(32)] },
      }),
      sdk.signSessionTransaction,
      [
        (o) => {
          o.credential.grantId[0] ^= 1;
        },
        (o) => {
          o.credential.authEpoch++;
        },
        (o) => {
          o.credential.policyHash[0] ^= 1;
        },
        (o) => {
          o.credential.nonce++;
        },
        (o) => {
          o.credential.keyScheme = 2;
        },
        (o) => {
          o.credential.publicKey[0] ^= 1;
        },
        (o) => {
          o.signer.publicKey[0] ^= 1;
        },
        (o) => {
          o.signer.keyScheme = 2;
        },
        (o) => {
          o.signer.sign = async () => {};
        },
        (o) => {
          o.recipientProof.leafIndex = 1;
        },
        (o) => {
          o.recipientProof.leafCount = 3;
        },
        (o) => {
          o.recipientProof.siblings[0][0] = 1;
        },
        (o) => {
          o.recipientProof.siblings.pop();
        },
        (o) => {
          o.recipientProof = undefined;
        },
      ],
    ],
  ];
  for (const [make, sign, mutations] of cases)
    for (const mutate of mutations) {
      const options = make(),
        calls = counting(options),
        gate = deferred(),
        entered = deferred();
      options.approve = () => {
        entered.resolve();
        return gate.promise;
      };
      const pending = sign(options);
      await entered.promise;
      mutate(options);
      gate.resolve(true);
      await assert.rejects(pending, code("MUTATED_INPUT"));
      assert.equal(calls(), 0);
    }
});

test("SDK review hash binds session key and full root selection/config beyond the chain signing digest", async () => {
  async function capture(options, sign) {
    let review;
    options.approve = (r) => {
      review = r.review;
      return false;
    };
    await assert.rejects(sign(options), code("REVIEW_REJECTED"));
    return review;
  }
  const first = await capture(sessionOptions(edSigner(1)), sdk.signSessionTransaction);
  const second = await capture(sessionOptions(edSigner(2)), sdk.signSessionTransaction);
  // Same intent sender deliberately: credential/key validation is separate from live grant authority.
  const same = sessionOptions(edSigner(2));
  same.intent.sender = bytes(fields(first.intent)["intent.sender"]);
  const third = await capture(same, sdk.signSessionTransaction);
  assert.equal(first.signingDigest, third.signingDigest);
  assert.notEqual(first.reviewHash, third.reviewHash);
  assert.notEqual(first.authority.publicKey, third.authority.publicKey);
  assert.notEqual(first.reviewHash, second.reviewHash);
  const root = rootInput(),
    rootReview = await capture(root, sdk.signRootTransaction);
  const other = rootInput();
  other.signers = [edSigner(2), edSigner(3)];
  const rootOther = await capture(other, sdk.signRootTransaction);
  assert.equal(rootReview.signingDigest, rootOther.signingDigest);
  assert.notEqual(rootReview.reviewHash, rootOther.reviewHash);
  const again = await capture(rootInput(), sdk.signRootTransaction);
  assert.equal(rootReview.reviewHash, again.reviewHash);
  assert.notEqual(rootReview.reviewHash, first.reviewHash);
});

test("every canonical grant/policy input changes the review binding with complete mapping and precision", async () => {
  const base = sdk.createGrantCodec.decode(bytes(vectors.createGrant.actionData));
  const mutations = [
    (g) => {
      g.keyScheme = 2;
      g.publicKey = bytes(vectors.p256Keys.sessionPublicKey);
    },
    (g) => {
      g.publicKey = edSigner(2).publicKey;
    },
    (g) => {
      g.validAfterHeight++;
    },
    (g) => {
      g.validUntilHeight++;
    },
    (g) => {
      g.storageDeposit++;
    },
    (g) => {
      g.policy.maxAttempts++;
    },
    (g) => {
      g.policy.fee.maxGasLimit++;
    },
    (g) => {
      g.policy.fee.maxGasPrice++;
    },
    (g) => {
      g.policy.fee.maxFeePerTransaction++;
    },
    (g) => {
      g.policy.fee.lifetimeFeeLimit++;
    },
    (g) => {
      g.policy.fee.feeTokenBucket = { capacity: 1n, refillPerBlock: 0n };
    },
    (g) => {
      g.policy.fee.feeTokenBucket = { capacity: 2n, refillPerBlock: 1n };
    },
    (g) => {
      g.policy.transfer.recipients.recipients.pop();
    },
    (g) => {
      g.policy.transfer.recipients = {
        kind: 1,
        merkleRoot: bytes(vectors.policy.policyHash),
        leafCount: 2,
      };
    },
    (g) => {
      g.policy.transfer.limits.maxPerTransaction = 0n;
    },
    (g) => {
      g.policy.transfer.limits.lifetimeLimit = (1n << 256n) - 1n;
    },
    (g) => {
      g.policy.transfer.limits.valueTokenBucket = { capacity: 5n, refillPerBlock: 0n };
    },
    (g) => {
      g.policy.transfer.limits.valueTokenBucket = { capacity: 6n, refillPerBlock: 1n };
    },
    (g) => {
      g.policy.transfer.allowZeroValue = true;
    },
    (g) => {
      g.policy.transfer.allowSelfTransfer = true;
    },
  ];
  async function review(grant) {
    const options = rootInput();
    options.intent = sdk.txIntentCodec.decode(
      bytes(vectors.createGrant.intentCanonical),
    );
    options.intent.data = sdk.createGrantCodec.encode({ version: 1, grant });
    let review;
    options.approve = (r) => {
      review = r.review;
      return false;
    };
    await assert.rejects(sdk.signRootTransaction(options), code("REVIEW_REJECTED"));
    return review;
  }
  const original = await review(base.grant);
  for (const mutate of mutations) {
    const g = structuredClone(base.grant);
    mutate(g);
    const changed = await review(g);
    assert.notEqual(changed.intent.binding.hash, original.intent.binding.hash);
    assert.notEqual(changed.reviewHash, original.reviewHash);
    assert.notDeepEqual(fields(changed.intent), fields(original.intent));
  }
  assert.equal(fields(original.intent)["intent.data.grant.validAfterHeight"], "101");
  assert.equal(fields(original.intent)["intent.data.grant.validUntilHeight"], "10101");
});

test("abort and timeout interrupt a noncooperating reviewer, consume late failures and isolate parallel operations", async () => {
  for (const [make, sign] of modes) {
    const options = make(),
      calls = counting(options),
      gate = deferred(),
      entered = deferred(),
      controller = new AbortController();
    options.signal = controller.signal;
    options.approve = (r) => {
      entered.resolve(r);
      return gate.promise;
    };
    const pending = sign(options),
      request = await entered.promise;
    controller.abort("secret");
    await assert.rejects(pending, code("ABORTED"));
    gate.reject(Error("late secret"));
    assert.equal(request.signal.aborted, true);
    assert.equal(calls(), 0);
    const timed = make(),
      timedCalls = counting(timed),
      timedGate = deferred();
    timed.timeoutMs = 5;
    timed.approve = () => timedGate.promise;
    await assert.rejects(sign(timed), code("TIMEOUT"));
    timedGate.resolve(true);
    await new Promise((r) => setImmediate(r));
    assert.equal(timedCalls(), 0);
    const live = make();
    live.approve = () => true;
    assert(await sign(live));
  }
});

test("pre-abort invokes neither reviewer nor signer; expired review does not prompt a ROOT key", async () => {
  const controller = new AbortController();
  controller.abort();
  const options = rootInput(),
    calls = counting(options);
  options.signal = controller.signal;
  let approvals = 0;
  options.approve = () => {
    approvals++;
    return true;
  };
  await assert.rejects(sdk.signRootTransaction(options), code("ABORTED"));
  assert.equal(approvals, 0);
  assert.equal(calls(), 0);
  const delayed = rootInput(),
    delayedCalls = counting(delayed);
  delayed.timeoutMs = 5;
  delayed.approve = () => {
    const start = performance.now();
    while (performance.now() - start < 10) {}
    return true;
  };
  await assert.rejects(sdk.signRootTransaction(delayed), code("TIMEOUT"));
  assert.equal(delayedCalls(), 0);
});

test("approved callback cannot mutate frozen display or inject app/Unicode/time authority", async () => {
  const options = directOptions(),
    calls = counting(options);
  options.approve = ({ review }) => {
    review.transactionTemplate.fields[0].value = "APPROVED";
    return true;
  };
  await assert.rejects(sdk.signDirectTransaction(options), code("REVIEW_FAILED"));
  assert.equal(calls(), 0);
  for (const label of [
    "\u202enonce",
    "аpple",
    "<script>approved</script>",
    "expires-never",
  ]) {
    const unsafe = directOptions();
    unsafe.intent[label] = "untrusted";
    const calls = counting(unsafe);
    unsafe.approve = () => {
      assert.fail("No partial review");
    };
    await assert.rejects(
      sdk.signDirectTransaction(unsafe),
      (e) => e instanceof sdk.CodecError,
    );
    assert.equal(calls(), 0);
  }
});

test("SDK-only review binding matches independent pinned Python Keccak and manually assembled metadata goldens", async () => {
  const fixture = JSON.parse(
    readFileSync(new URL("./display/golden/signing-binding.json", import.meta.url)),
  );
  assert.equal(
    fixture.validatedAtRevision,
    JSON.parse(readFileSync(new URL("../protocol-source.json", import.meta.url)))
      .revision,
  );
  for (const expected of fixture.cases) {
    const vector = vectors[expected.name],
      intent = sdk.txIntentCodec.decode(bytes(vector.intentCanonical)),
      envelope = sdk.authEnvelopeCodec.decode(bytes(vector.authEnvelopeCanonical));
    const signer = (publicKey, keyScheme = 1) => ({
      keyScheme,
      publicKey: bytes(publicKey),
      async sign() {
        assert.fail("Rejected review must never sign");
      },
    });
    const common = {
      context: structuredClone(context),
      intent,
      approve: ({ review }) => {
        assert.equal(review.reviewHash, expected.reviewHash);
        assert.equal(review.transactionTemplate.binding.canonical, expected.template);
        return false;
      },
    };
    let options, sign;
    if (envelope.mode === 0) {
      options = {
        ...common,
        nonce: envelope.nonce,
        signer: signer(vectors.keys.directPublicKey),
      };
      sign = sdk.signDirectTransaction;
    } else if (envelope.mode === 1) {
      options = {
        ...common,
        nonce: envelope.nonce,
        authEpoch: envelope.authEpoch,
        config: {
          version: 1,
          threshold: 2,
          keys: vectors.root.sortedKeys.map((k) => ({
            keyScheme: 1,
            publicKey: bytes(k.publicKey),
          })),
        },
        signers: vectors.root.sortedKeys.map((k) => signer(k.publicKey)),
      };
      sign = sdk.signRootTransaction;
    } else {
      const key =
        envelope.keyScheme === 1
          ? vectors.keys.sessionPublicKey
          : vectors.p256Keys.sessionPublicKey;
      options = {
        ...common,
        credential: {
          grantId: envelope.credentialId,
          authEpoch: envelope.authEpoch,
          policyHash: envelope.policyHash,
          nonce: envelope.nonce,
          keyScheme: envelope.keyScheme,
          publicKey: bytes(key),
        },
        signer: signer(key, envelope.keyScheme),
      };
      sign = sdk.signSessionTransaction;
    }
    await assert.rejects(sign(options), code("REVIEW_REJECTED"));
  }
});
