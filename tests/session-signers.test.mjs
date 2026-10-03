import assert from "node:assert/strict";
import { test } from "node:test";
import { webcrypto } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sdk, zero } from "./helpers.mjs";
import {
  code,
  cofactorFixture,
  deferred,
  directOptions,
  edSigner,
  p256Signer,
  rootInput,
  sessionOptions,
} from "./signer-helpers.mjs";

test("DIRECT signs the exact domain using independent Node/OpenSSL Ed25519", async () => {
  const options = directOptions();
  let observed;
  const sign = options.signer.sign;
  options.signer.sign = async (request) => {
    observed = structuredClone({ digest: request.digest, mode: request.mode });
    return sign(request);
  };
  const tx = await sdk.signDirectTransaction(options);
  const digest = sdk.directDigest(options.context, options.intent, options.nonce);
  assert.deepEqual(observed, { mode: 0, digest });
  assert(
    ed25519.verify(
      tx.envelope.witness.slice(32),
      digest,
      tx.envelope.witness.slice(0, 32),
      { zip215: false },
    ),
  );
  assert.deepEqual(sdk.transactionCodec.decode(sdk.transactionCodec.encode(tx)), tx);
  options.intent.sender.fill(0);
  options.signer.publicKey.fill(0);
  assert(tx.intent.sender.some(Boolean));
  assert(tx.envelope.witness.some(Boolean));
});

test("Chain's exact Ed25519 equation rejects cofactor-only signatures without banning mixed-order keys", async () => {
  const options = sessionOptions();
  const digest = sdk.sessionDigest(options.context, options.intent, options.credential);
  for (const [mixedKey, balanced] of [
    [false, false],
    [true, false],
    [true, true],
  ]) {
    const response = cofactorFixture(digest, mixedKey, balanced);
    assert(
      ed25519.verify(response.signature, digest, response.publicKey, { zip215: false }),
    );
    sdk.validateSessionPublicKey(1, response.publicKey);
    options.signer.publicKey = response.publicKey;
    options.credential.publicKey = response.publicKey;
    options.signer.sign = async () => response;
    if (balanced) await sdk.signSessionTransaction(options);
    else
      await assert.rejects(
        sdk.signSessionTransaction(options),
        code("INVALID_SIGNATURE"),
      );
  }
});

test("ROOT signs exactly threshold, orders selected IDs and covers thresholds 1..8", async () => {
  for (let threshold = 1; threshold <= 8; threshold++) {
    const options = rootInput(threshold, 8);
    const calls = [];
    for (const signer of options.signers) {
      const sign = signer.sign;
      signer.sign = async (request) => {
        calls.push(sdk.rootKeyId({ keyScheme: 1, publicKey: request.publicKey }));
        return sign(request);
      };
    }
    const tx = await sdk.signRootTransaction(options);
    const entries = sdk.decodeRootWitness(tx.envelope.witness, threshold);
    assert.equal(calls.length, threshold);
    assert.deepEqual(
      entries.map((entry) => entry.rootKeyId),
      calls,
    );
    for (let i = 1; i < calls.length; i++)
      assert(Buffer.compare(calls[i - 1], calls[i]) < 0);
    assert.deepEqual(tx.envelope.credentialId, sdk.rootConfigHash(options.config));
  }
});

test("SESSION accepts both schemes and P-256 high-S without double hashing", async () => {
  for (const signer of [edSigner(), p256Signer()]) {
    const options = sessionOptions(signer);
    options.recipientProof = {
      leafIndex: 1,
      leafCount: 2,
      siblings: [new Uint8Array(32).fill(9)],
    };
    const tx = await sdk.signSessionTransaction(options);
    assert.equal(tx.envelope.keyScheme, signer.keyScheme);
    assert.deepEqual(
      sdk.sessionWitnessCodec.decode(tx.envelope.witness).recipientProof,
      options.recipientProof,
    );
  }
  const options = sessionOptions(p256Signer());
  const sign = options.signer.sign;
  options.signer.sign = async (request) => {
    const response = await sign(request);
    const parsed = p256.Signature.fromBytes(response.signature);
    const low =
      parsed.s > p256.Point.Fn.ORDER / 2n ? p256.Point.Fn.ORDER - parsed.s : parsed.s;
    response.signature = new p256.Signature(
      parsed.r,
      p256.Point.Fn.ORDER - low,
    ).toBytes();
    return response;
  };
  await sdk.signSessionTransaction(options);
});

test("native signing rejects actual WebCrypto ECDSA double hashing and WebAuthn message confusion", async () => {
  const privateKey = zero(32);
  privateKey[31] = 7;
  const options = sessionOptions(p256Signer());
  const key = await webcrypto.subtle.importKey(
    "jwk",
    {
      kty: "EC",
      crv: "P-256",
      x: Buffer.from(options.signer.publicKey.slice(0, 32)).toString("base64url"),
      y: Buffer.from(options.signer.publicKey.slice(32)).toString("base64url"),
      d: Buffer.from(privateKey).toString("base64url"),
    },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  options.signer.sign = async ({ digest }) => ({
    keyScheme: 2,
    publicKey: options.signer.publicKey,
    signature: new Uint8Array(
      await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, digest),
    ),
  });
  await assert.rejects(sdk.signSessionTransaction(options), code("INVALID_SIGNATURE"));
  options.signer.sign = async () => ({
    keyScheme: 2,
    publicKey: options.signer.publicKey,
    signature: p256.sign(new Uint8Array(69).fill(42), privateKey),
  });
  await assert.rejects(sdk.signSessionTransaction(options), code("INVALID_SIGNATURE"));
});

test("invalid signatures, schemes, response keys and DER fail explicitly", async () => {
  for (const signer of [edSigner(), p256Signer()]) {
    for (const mutate of [
      (r) => {
        r.signature = zero(64);
      },
      (r) => {
        r.signature = r.signature.slice(1);
      },
      (r) => {
        r.signature = new Uint8Array(65);
      },
      (r) => {
        r.signature[0] ^= 1;
      },
    ]) {
      const options = sessionOptions(signer),
        sign = signer.sign;
      options.signer = {
        ...signer,
        sign: async (request) => {
          const response = await sign(request);
          mutate(response);
          return response;
        },
      };
      await assert.rejects(
        sdk.signSessionTransaction(options),
        code("INVALID_SIGNATURE"),
      );
    }
  }
  const options = sessionOptions();
  const sign = options.signer.sign;
  for (const mutate of [
    (r) => {
      r.keyScheme = 2;
    },
    (r) => {
      r.publicKey = edSigner(2).publicKey;
    },
  ]) {
    options.signer.sign = async (request) => {
      const response = await sign(request);
      mutate(response);
      return response;
    };
    await assert.rejects(sdk.signSessionTransaction(options), code("SIGNER_MISMATCH"));
  }
  const p = sessionOptions(p256Signer()),
    raw = p.signer.sign;
  p.signer.sign = async (request) => {
    const r = await raw(request);
    r.signature = p256.Signature.fromBytes(r.signature).toBytes("der");
    return r;
  };
  await assert.rejects(sdk.signSessionTransaction(p), code("INVALID_SIGNATURE"));
});

test("P-256 DIRECT/ROOT, mismatched sender, sponsor and credential fail before callbacks", async () => {
  const p = p256Signer();
  let calls = 0;
  p.sign = async () => {
    calls++;
    throw Error("must not sign");
  };
  await assert.rejects(sdk.signDirectTransaction(directOptions(p)), {
    code: "UNSUPPORTED_FEATURE",
  });
  const root = rootInput();
  root.signers[0] = p;
  await assert.rejects(sdk.signRootTransaction(root), { code: "UNSUPPORTED_FEATURE" });
  assert.equal(calls, 0);
  const direct = directOptions();
  direct.intent.sender[0] ^= 1;
  await assert.rejects(sdk.signDirectTransaction(direct), { code: "CONTEXT_MISMATCH" });
  direct.intent.sponsor[0] = 1;
  await assert.rejects(sdk.signDirectTransaction(direct), {
    code: "UNSUPPORTED_FEATURE",
  });
  const session = sessionOptions();
  session.credential.publicKey = edSigner(2).publicKey;
  await assert.rejects(sdk.signSessionTransaction(session), {
    code: "CONTEXT_MISMATCH",
  });
});

test("ROOT duplicate, excess, missing, unknown and invalid config keys fail before signing", async () => {
  for (const mutate of [
    (o) => {
      o.signers.push(edSigner(3));
    },
    (o) => {
      o.signers.pop();
    },
    (o) => {
      o.signers[1] = o.signers[0];
    },
    (o) => {
      o.signers[0] = edSigner(9);
    },
    (o) => {
      o.config.keys[0].publicKey.fill(0);
    },
    (o) => {
      o.config.keys.reverse();
    },
  ]) {
    const options = rootInput();
    let calls = 0;
    for (const signer of options.signers)
      signer.sign = async () => {
        calls++;
        throw Error("must not sign");
      };
    mutate(options);
    await assert.rejects(sdk.signRootTransaction(options));
    assert.equal(calls, 0);
  }
});

test("wrong context/domain and noncanonical Ed25519 R/S are rejected", async () => {
  for (const mutateDigest of [
    (d) => {
      d[0] ^= 1;
      return d;
    },
    () => zero(32),
  ]) {
    const options = sessionOptions(),
      sign = options.signer.sign;
    options.signer.sign = async (request) =>
      sign({
        ...request,
        digest: mutateDigest(request.digest.slice()) ?? request.digest,
      });
    await assert.rejects(
      sdk.signSessionTransaction(options),
      code("INVALID_SIGNATURE"),
    );
  }
  for (const mutate of [
    (r) => {
      r.signature.fill(0, 0, 32);
      r.signature[0] = 1;
    },
    (r) => {
      r.signature.fill(255, 32);
    },
  ]) {
    const options = sessionOptions(),
      sign = options.signer.sign;
    options.signer.sign = async (request) => {
      const response = await sign(request);
      mutate(response);
      return response;
    };
    await assert.rejects(
      sdk.signSessionTransaction(options),
      code("INVALID_SIGNATURE"),
    );
  }
});

test("async signing detects caller mutation in intent, context, key, credential, config and proof", async () => {
  const cases = [
    [
      directOptions,
      sdk.signDirectTransaction,
      (o) => {
        o.intent.value++;
      },
    ],
    [
      directOptions,
      sdk.signDirectTransaction,
      (o) => {
        o.context.genesisHash[0] ^= 1;
      },
    ],
    [
      directOptions,
      sdk.signDirectTransaction,
      (o) => {
        o.nonce++;
      },
    ],
    [
      directOptions,
      sdk.signDirectTransaction,
      (o) => {
        o.signer.publicKey[0] ^= 1;
      },
    ],
    [
      directOptions,
      sdk.signDirectTransaction,
      (o) => {
        o.signer.sign = async () => {};
      },
    ],
    [
      sessionOptions,
      sdk.signSessionTransaction,
      (o) => {
        o.credential.authEpoch++;
      },
    ],
    [
      sessionOptions,
      sdk.signSessionTransaction,
      (o) => {
        o.credential.grantId.fill(0);
      },
    ],
    [
      rootInput,
      sdk.signRootTransaction,
      (o) => {
        o.config.threshold = 1;
      },
    ],
    [
      rootInput,
      sdk.signRootTransaction,
      (o) => {
        o.signers.reverse();
      },
    ],
  ];
  for (const [make, execute, mutate] of cases) {
    const options = make(),
      started = deferred(),
      resume = deferred();
    const signers = options.signers ?? [options.signer];
    for (const signer of signers) {
      const sign = signer.sign;
      signer.sign = async (request) => {
        const response = await sign(request);
        started.resolve();
        await resume.promise;
        return response;
      };
    }
    const result = execute(options);
    await started.promise;
    mutate(options);
    resume.resolve();
    await assert.rejects(result, code("MUTATED_INPUT"));
  }
  const options = sessionOptions(),
    started = deferred(),
    resume = deferred();
  options.recipientProof = { leafIndex: 0, leafCount: 2, siblings: [zero(32)] };
  const sign = options.signer.sign;
  options.signer.sign = async (request) => {
    const r = await sign(request);
    started.resolve();
    await resume.promise;
    return r;
  };
  const result = sdk.signSessionTransaction(options);
  await started.promise;
  options.recipientProof.siblings[0][0] = 1;
  resume.resolve();
  await assert.rejects(result, code("MUTATED_INPUT"));
});

test("adapter request mutations are rejected and signature buffers are detached", async () => {
  for (const field of ["digest", "publicKey"]) {
    const options = directOptions(),
      sign = options.signer.sign;
    options.signer.sign = async (request) => {
      const r = await sign(request);
      request[field].fill(0);
      return r;
    };
    await assert.rejects(sdk.signDirectTransaction(options), code("MUTATED_INPUT"));
  }
  const options = directOptions(),
    sign = options.signer.sign;
  let response;
  options.signer.sign = async (request) => {
    response = await sign(request);
    return response;
  };
  const tx = await sdk.signDirectTransaction(options);
  const before = tx.envelope.witness.slice();
  response.signature.fill(0);
  assert.deepEqual(tx.envelope.witness, before);
});

test("pre-abort invokes no signer; active abort stops ROOT collection and ignores late failures", async () => {
  const abort = new AbortController();
  abort.abort(Error("private secret"));
  const pre = directOptions();
  pre.signal = abort.signal;
  let calls = 0;
  pre.signer.sign = async () => {
    calls++;
  };
  await assert.rejects(sdk.signDirectTransaction(pre), code("ABORTED"));
  assert.equal(calls, 0);
  const options = rootInput(),
    controller = new AbortController(),
    started = deferred(),
    late = deferred();
  options.signal = controller.signal;
  let signal;
  for (const signer of options.signers)
    signer.sign = async (request) => {
      calls++;
      signal = request.signal;
      started.resolve();
      return late.promise;
    };
  const pending = sdk.signRootTransaction(options);
  await started.promise;
  controller.abort(Error("private secret"));
  await assert.rejects(pending, code("ABORTED"));
  assert(signal.aborted);
  assert.equal(calls, 1);
  late.reject(Error("late private secret"));
  await new Promise((resolve) => setImmediate(resolve));
});

test("overall deadline bounds a noncooperating signer and rejects invalid timeout options", async () => {
  const options = directOptions();
  let signal;
  options.timeoutMs = 20;
  options.signer.sign = async (request) => {
    signal = request.signal;
    return new Promise(() => {});
  };
  await assert.rejects(sdk.signDirectTransaction(options), code("TIMEOUT"));
  assert(signal.aborted);
  for (const timeoutMs of [0, -1, 0.5, 300001, NaN, Infinity])
    await assert.rejects(sdk.signDirectTransaction({ ...directOptions(), timeoutMs }));
});

test("adapter exceptions are sanitized and concurrent signing is independently cancelled", async () => {
  const failure = directOptions();
  failure.signer.sign = async () => {
    throw Error("private-key=secret");
  };
  await assert.rejects(
    sdk.signDirectTransaction(failure),
    (error) =>
      code("SIGNER_FAILED")(error) &&
      !error.message.includes("secret") &&
      error.cause === undefined,
  );
  const cancelled = directOptions(),
    started = deferred(),
    controller = new AbortController();
  cancelled.signal = controller.signal;
  cancelled.signer.sign = async () => {
    started.resolve();
    return new Promise(() => {});
  };
  const a = sdk.signDirectTransaction(cancelled),
    b = sdk.signDirectTransaction(directOptions(edSigner(2)));
  await started.promise;
  controller.abort();
  await assert.rejects(a, code("ABORTED"));
  assert.equal((await b).envelope.mode, 0);
});

test("elapsed deadline stops further ROOT signers even before the timer callback runs", async () => {
  const original = globalThis.performance;
  let now = 0;
  globalThis.performance = { now: () => now };
  try {
    const options = rootInput();
    options.timeoutMs = 100;
    let calls = 0;
    for (const signer of options.signers) {
      const sign = signer.sign;
      signer.sign = async (request) => {
        calls++;
        const r = await sign(request);
        now = 101;
        return r;
      };
    }
    await assert.rejects(sdk.signRootTransaction(options), code("TIMEOUT"));
    assert.equal(calls, 1);
  } finally {
    globalThis.performance = original;
  }
});

test("signing removes caller listeners on success and provider failure", async () => {
  for (const fails of [false, true]) {
    const options = directOptions(),
      controller = new AbortController();
    const add = controller.signal.addEventListener.bind(controller.signal),
      remove = controller.signal.removeEventListener.bind(controller.signal);
    const listeners = new Set();
    controller.signal.addEventListener = (name, listener, ...rest) => {
      listeners.add(listener);
      return add(name, listener, ...rest);
    };
    controller.signal.removeEventListener = (name, listener, ...rest) => {
      listeners.delete(listener);
      return remove(name, listener, ...rest);
    };
    options.signal = controller.signal;
    if (fails)
      options.signer.sign = async () => {
        throw Error("provider failure");
      };
    if (fails)
      await assert.rejects(sdk.signDirectTransaction(options), code("SIGNER_FAILED"));
    else await sdk.signDirectTransaction(options);
    assert.equal(listeners.size, 0);
  }
});

test("provider response getters cannot impersonate SDK errors or leak diagnostics", async () => {
  const options = directOptions();
  const error = new sdk.SignerError("SIGNER_MISMATCH");
  error.message = "private-key=secret";
  options.signer.sign = async () => ({
    get keyScheme() {
      throw error;
    },
    publicKey: options.signer.publicKey,
    signature: zero(64),
  });
  await assert.rejects(
    sdk.signDirectTransaction(options),
    (e) =>
      code("INVALID_SIGNATURE")(e) &&
      !e.message.includes("secret") &&
      e.cause === undefined,
  );
  options.signer.sign = async (request) => {
    request.digest = undefined;
    return { keyScheme: 1, publicKey: options.signer.publicKey, signature: zero(64) };
  };
  await assert.rejects(sdk.signDirectTransaction(options), code("MUTATED_INPUT"));
});
