import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, webcrypto } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import { bytes, hex, sdk, seeded, zero } from "../tests/helpers.mjs";
import {
  directOptions,
  cofactorFixture,
  edSigner,
  p256Signer,
  rootInput,
  sessionOptions,
} from "../tests/signer-helpers.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const chain = process.env.RSC_CHAIN_DIR;
assert(chain, "Set RSC_CHAIN_DIR to a clean checkout at the immutable protocol pin.");
const pin = JSON.parse(
  await readFile(new URL("../protocol-source.json", import.meta.url), "utf8"),
);
const run = (command, args, options = {}) =>
  execFileSync(command, args, { cwd: resolve(chain), encoding: "utf8", ...options });
assert.equal(run("git", ["rev-parse", "HEAD"]).trim(), pin.revision);
assert.equal(run("git", ["status", "--porcelain", "--untracked-files=no"]).trim(), "");
assert.equal(
  run("go", ["env", "CGO_ENABLED"]).trim(),
  "1",
  "Native signing gate requires CGO_ENABLED=1",
);
run("make", ["build-crypto"], { stdio: "inherit" });
const temporary = await mkdtemp(join(tmpdir(), "resilience-sdk-signatures-"));
try {
  const binary = join(temporary, "go-signatures");
  run(
    "go",
    ["build", "-o", binary, join(root, "tests/go-signature-reference/main.go")],
    { stdio: "inherit" },
  );
  const oracle = (requests) =>
    JSON.parse(
      run(binary, [], { input: JSON.stringify(requests), maxBuffer: 16 * 1024 * 1024 }),
    );
  const nativeSigner = (scheme, seed = 1) => {
    const publicKey = scheme === 1 ? edSigner(seed).publicKey : p256Signer().publicKey;
    return {
      keyScheme: scheme,
      publicKey,
      async sign({ digest }) {
        const [result] = oracle([
          { operation: "sign", scheme, seed, digest: hex(digest) },
        ]);
        assert.equal(result.accepted, true);
        return {
          keyScheme: scheme,
          publicKey: bytes(result.publicKey),
          signature: bytes(result.signature),
        };
      },
    };
  };
  const cases = [];
  const add = (name, tx, options) => {
    const c = options.credential;
    const request = {
      operation: "verify",
      transaction: hex(sdk.transactionCodec.encode(tx)),
      genesis: hex(options.context.genesisHash),
      chainId: options.context.chainId.toString(),
      nonce: (c?.nonce ?? options.nonce).toString(),
    };
    if (options.config) {
      request.root = hex(sdk.rootConfigCodec.encode(options.config));
      request.epoch = options.authEpoch.toString();
    }
    if (c)
      Object.assign(request, {
        epoch: c.authEpoch.toString(),
        grantId: hex(c.grantId),
        policyHash: hex(c.policyHash),
        publicKey: hex(c.publicKey),
        scheme: c.keyScheme,
      });
    cases.push({ name, request, tx, accepted: true });
  };
  for (const signer of [edSigner(), nativeSigner(1)]) {
    const options = directOptions(signer);
    add(
      "DIRECT independent Ed25519",
      await sdk.signDirectTransaction(options),
      options,
    );
  }
  for (let threshold = 1; threshold <= 8; threshold++) {
    const options = rootInput(threshold, 8);
    options.signers = Array.from({ length: threshold }, (_, i) =>
      nativeSigner(1, i + 1),
    ).reverse();
    add(`ROOT threshold ${threshold}`, await sdk.signRootTransaction(options), options);
  }
  for (const signer of [edSigner(), p256Signer(), nativeSigner(1), nativeSigner(2)]) {
    const options = sessionOptions(signer);
    add(
      `SESSION ${signer.keyScheme}`,
      await sdk.signSessionTransaction(options),
      options,
    );
  }
  const high = sessionOptions(nativeSigner(2));
  const nativeSign = high.signer.sign;
  high.signer.sign = async (request) => {
    const response = await nativeSign(request),
      sig = p256.Signature.fromBytes(response.signature);
    const s = sig.s > p256.Point.Fn.ORDER / 2n ? sig.s : p256.Point.Fn.ORDER - sig.s;
    return { ...response, signature: new p256.Signature(sig.r, s).toBytes() };
  };
  add("SESSION independent Go high-S", await sdk.signSessionTransaction(high), high);
  const accepted = [...cases];
  const negative = (base, name, patch) =>
    cases.push({
      name: `${base.name}/${name}`,
      request: { ...base.request, ...patch },
      accepted: false,
    });
  const random = seeded(0x18a11ce);
  for (const base of accepted) {
    negative(base, "wrong genesis", { genesis: "0x" + "77".repeat(32) });
    negative(base, "wrong chain", { chainId: "1" });
    negative(base, "wrong nonce", {
      nonce: (BigInt(base.request.nonce) + 1n).toString(),
    });
    const intent = { ...base.tx.intent, value: base.tx.intent.value + 1n };
    negative(base, "wrong intent", {
      transaction: hex(sdk.transactionCodec.encode({ ...base.tx, intent })),
    });
    const envelopeOffset = sdk.txIntentCodec.encode(base.tx.intent).length;
    if (base.tx.envelope.mode !== 2) {
      const raw = bytes(base.request.transaction);
      raw[envelopeOffset + 3] = 2;
      negative(base, "P256 DIRECT/ROOT", { transaction: hex(raw) });
    }
    if (base.request.epoch)
      negative(base, "wrong epoch", {
        epoch: (BigInt(base.request.epoch) + 1n).toString(),
      });
    if (base.request.grantId) {
      negative(base, "wrong grant", { grantId: "0x" + "88".repeat(32) });
      negative(base, "wrong policy", { policyHash: "0x" + "88".repeat(32) });
      negative(base, "wrong credential key", {
        publicKey: hex(
          base.request.scheme === 1
            ? edSigner(9).publicKey
            : p256.getPublicKey(new Uint8Array(32).fill(9), false).slice(1),
        ),
      });
    }
    const witness = base.tx.envelope.witness;
    // DIRECT sig offset=32; ROOT first entry sig offset=2+32; SESSION=0.
    const start =
      base.tx.envelope.mode === 0 ? 32 : base.tx.envelope.mode === 1 ? 34 : 0;
    for (let i = 0; i < 32; i++) {
      const bad = witness.slice();
      bad[start + (random() % 64)] ^= 1 << (random() % 8);
      negative(base, `signature bit mutation ${i}`, {
        transaction: hex(
          sdk.transactionCodec.encode({
            ...base.tx,
            envelope: { ...base.tx.envelope, witness: bad },
          }),
        ),
      });
    }
  }
  const direct = accepted[0];
  for (const kind of ["small-order R", "noncanonical S"]) {
    const witness = direct.tx.envelope.witness.slice();
    if (kind === "small-order R") {
      witness.fill(0, 32, 64);
      witness[32] = 1;
    } else witness.fill(255, 64);
    negative(direct, kind, {
      transaction: hex(
        sdk.transactionCodec.encode({
          ...direct.tx,
          envelope: { ...direct.tx.envelope, witness },
        }),
      ),
    });
  }
  const rootTwo = accepted.find((c) => c.name === "ROOT threshold 2");
  const entries = sdk.decodeRootWitness(rootTwo.tx.envelope.witness, 2);
  const unknown = {
    ...entries[0],
    rootKeyId: sdk.rootKeyId({ keyScheme: 1, publicKey: edSigner(99).publicKey }),
  };
  const unknownEntries = [unknown, entries[1]].sort((a, b) =>
    Buffer.compare(a.rootKeyId, b.rootKeyId),
  );
  negative(rootTwo, "unknown root key", {
    transaction: hex(
      sdk.transactionCodec.encode({
        ...rootTwo.tx,
        envelope: {
          ...rootTwo.tx.envelope,
          witness: sdk.encodeRootWitness(unknownEntries, 2),
        },
      }),
    ),
  });
  const extraEntries = [...entries, unknown].sort((a, b) =>
    Buffer.compare(a.rootKeyId, b.rootKeyId),
  );
  negative(rootTwo, "over threshold", {
    transaction: hex(
      sdk.transactionCodec.encode({
        ...rootTwo.tx,
        envelope: {
          ...rootTwo.tx.envelope,
          witness: sdk.encodeRootWitness(extraEntries, 3),
        },
      }),
    ),
  });
  const directWitness = direct.tx.envelope.witness.slice();
  directWitness.set(edSigner(99).publicKey);
  negative(direct, "wrong direct key/sender binding", {
    transaction: hex(
      sdk.transactionCodec.encode({
        ...direct.tx,
        envelope: { ...direct.tx.envelope, witness: directWitness },
      }),
    ),
  });
  negative(rootTwo, "under threshold", {
    transaction: hex(
      sdk.transactionCodec.encode({
        ...rootTwo.tx,
        envelope: {
          ...rootTwo.tx.envelope,
          witness: sdk.encodeRootWitness(entries.slice(0, 1), 1),
        },
      }),
    ),
  });
  const reordered = rootTwo.tx.envelope.witness.slice();
  reordered.set(rootTwo.tx.envelope.witness.slice(98, 194), 2);
  reordered.set(rootTwo.tx.envelope.witness.slice(2, 98), 98);
  const raw = bytes(rootTwo.request.transaction),
    at = raw.length - rootTwo.tx.envelope.witness.length - 4;
  raw.set(reordered, at);
  negative(rootTwo, "reordered witness", { transaction: hex(raw) });
  const duplicate = raw.slice();
  duplicate.set(duplicate.slice(at + 2, at + 98), at + 98);
  negative(rootTwo, "duplicate witness", { transaction: hex(duplicate) });

  const p = sessionOptions(p256Signer()),
    digest = sdk.sessionDigest(p.context, p.intent, p.credential);
  const privateKey = zero(32);
  privateKey[31] = 7;
  const key = await webcrypto.subtle.importKey(
    "jwk",
    {
      kty: "EC",
      crv: "P-256",
      x: Buffer.from(p.signer.publicKey.slice(0, 32)).toString("base64url"),
      y: Buffer.from(p.signer.publicKey.slice(32)).toString("base64url"),
      d: Buffer.from(privateKey).toString("base64url"),
    },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const badSignatures = [
    [
      "WebCrypto SHA256(SessionDigest)",
      new Uint8Array(
        await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, digest),
      ),
    ],
    [
      "WebAuthn different assertion message",
      p256.sign(new Uint8Array(69).fill(42), privateKey),
    ],
    [
      "independent Go double hash",
      bytes(
        oracle([
          {
            operation: "sign",
            scheme: 2,
            digest: hex(new Uint8Array(createHash("sha256").update(digest).digest())),
          },
        ])[0].signature,
      ),
    ],
  ];
  const sessionBase = accepted.find((c) => c.request.scheme === 2);
  for (const [name, signature] of badSignatures) {
    p.signer.sign = async () => ({
      keyScheme: 2,
      publicKey: p.signer.publicKey,
      signature,
    });
    await assert.rejects(sdk.signSessionTransaction(p), { code: "INVALID_SIGNATURE" });
    negative(sessionBase, name, {
      transaction: hex(
        sdk.transactionCodec.encode({
          ...sessionBase.tx,
          envelope: {
            ...sessionBase.tx.envelope,
            witness: sdk.sessionWitnessCodec.encode({ signature }),
          },
        }),
      ),
    });
  }
  const edOptions = sessionOptions();
  const edDigest = sdk.sessionDigest(
    edOptions.context,
    edOptions.intent,
    edOptions.credential,
  );
  const edBase = accepted.find((c) => c.request.scheme === 1);
  for (const [mixedKey, balanced] of [
    [false, false],
    [true, false],
    [true, true],
  ]) {
    const response = cofactorFixture(edDigest, mixedKey, balanced);
    edOptions.signer.publicKey = response.publicKey;
    edOptions.credential.publicKey = response.publicKey;
    edOptions.signer.sign = async () => response;
    if (balanced)
      add(
        "SESSION exact-equation mixed-order key",
        await sdk.signSessionTransaction(edOptions),
        edOptions,
      );
    else {
      await assert.rejects(sdk.signSessionTransaction(edOptions), {
        code: "INVALID_SIGNATURE",
      });
      negative(edBase, `cofactored-only signature mixedKey=${mixedKey}`, {
        publicKey: hex(response.publicKey),
        transaction: hex(
          sdk.transactionCodec.encode({
            ...edBase.tx,
            envelope: {
              ...edBase.tx.envelope,
              witness: sdk.sessionWitnessCodec.encode({
                signature: response.signature,
              }),
            },
          }),
        ),
      });
    }
  }
  const results = oracle(cases.map((c) => c.request));
  assert.equal(results.length, cases.length);
  results.forEach((result, i) =>
    assert.equal(
      result.accepted,
      cases[i].accepted,
      `${cases[i].name}: ${result.error ?? "unexpected acceptance"}`,
    ),
  );
  console.log(
    `Pinned Go signature verification PASS: ${cases.length} cases (${cases.filter((c) => c.accepted).length} accepted, ${cases.filter((c) => !c.accepted).length} rejected); independent Node/OpenSSL Ed25519 and Go Ed25519/P-256; retained mutation seed 0x18a11ce.`,
  );
  console.log(
    `Chain ${pin.revision}; ${run("go", ["version"]).trim()}; CGO=1; ${run("rustc", ["--version"]).trim()}; Node ${process.version}.`,
  );
} finally {
  await rm(temporary, { recursive: true, force: true });
}
