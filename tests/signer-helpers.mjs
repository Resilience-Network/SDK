import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { sdk, context, intent, zero } from "./helpers.mjs";

// Fixed public test keys only. Never use these predictable seeds in a wallet.
export function edSigner(seedByte = 1) {
  const seed = Buffer.alloc(32, seedByte);
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    format: "der",
    type: "pkcs8",
  });
  const publicKey = new Uint8Array(
    createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32),
  );
  return {
    keyScheme: 1,
    publicKey,
    async sign({ digest }) {
      return {
        keyScheme: 1,
        publicKey: new Uint8Array(publicKey),
        signature: sign(null, digest, privateKey),
      };
    },
  };
}
export function p256Signer() {
  const privateKey = zero(32);
  privateKey[31] = 7;
  const publicKey = p256.getPublicKey(privateKey, false).slice(1);
  return {
    keyScheme: 2,
    publicKey,
    async sign({ digest }) {
      return {
        keyScheme: 2,
        publicKey: new Uint8Array(publicKey),
        signature: p256.sign(digest, privateKey, { prehash: false, lowS: false }),
      };
    },
  };
}
export function directOptions(signer = edSigner()) {
  return {
    context: structuredClone(context),
    intent: {
      ...structuredClone(intent),
      sender: sdk.keccak256(signer.publicKey).slice(12),
      sponsor: zero(20),
    },
    nonce: 3n,
    signer,
  };
}
export function rootOptions(threshold = 2, count = 3) {
  const signers = Array.from({ length: count }, (_, i) => edSigner(i + 1));
  const keys = signers
    .map(({ publicKey }) => ({ keyScheme: 1, publicKey: new Uint8Array(publicKey) }))
    .sort((a, b) => Buffer.compare(sdk.rootKeyId(a), sdk.rootKeyId(b)));
  return {
    ...directOptions(),
    config: { version: 1, threshold, keys },
    authEpoch: 4n,
    signers: signers.slice(0, threshold).reverse(),
    signer: undefined,
  };
}
export function rootInput(threshold = 2, count = 3) {
  const { signer: _unused, ...options } = rootOptions(threshold, count);
  return options;
}
export function sessionOptions(signer = edSigner()) {
  const { nonce: _nonce, ...options } = directOptions(signer);
  return {
    ...options,
    credential: {
      grantId: new Uint8Array(32).fill(3),
      authEpoch: 4n,
      policyHash: new Uint8Array(32).fill(5),
      nonce: 6n,
      keyScheme: signer.keyScheme,
      publicKey: new Uint8Array(signer.publicKey),
    },
  };
}
export function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
export const code = (expected) => (error) =>
  error instanceof sdk.SignerError && error.code === expected;

/** Independently constructed equation fixture; not a signing implementation. */
export function cofactorFixture(digest, mixedKey = false, balanced = false) {
  const le = (bytes) => [...bytes].reverse().reduce((n, b) => n * 256n + BigInt(b), 0n);
  const extended = sha512(new Uint8Array(32).fill(1));
  extended[0] &= 248;
  extended[31] &= 127;
  extended[31] |= 64;
  const n = ed25519.Point.Fn.ORDER,
    scalar = le(extended.slice(0, 32)) % n;
  const encodedT = new Uint8Array(32).fill(255);
  encodedT[0] = 236;
  encodedT[31] = 127;
  const t = ed25519.Point.fromBytes(encodedT, false);
  const a = ed25519.Point.BASE.multiply(scalar);
  const publicKey = (mixedKey ? a.add(t) : a).toBytes();
  for (let nonce = 7n; nonce < 100n; nonce++) {
    const r = ed25519.Point.BASE.multiply(nonce);
    const encodedR = (mixedKey ? r : r.add(t)).toBytes();
    const challenge = new Uint8Array(96);
    challenge.set(encodedR);
    challenge.set(publicKey, 32);
    challenge.set(digest, 64);
    const k = le(sha512(challenge)) % n;
    if (mixedKey && (k % 2n === 0n) !== balanced) continue;
    let s = (nonce + k * scalar) % n;
    const signature = new Uint8Array(64);
    signature.set(encodedR);
    for (let i = 32; i < 64; i++) {
      signature[i] = Number(s & 255n);
      s >>= 8n;
    }
    return { keyScheme: 1, publicKey, signature };
  }
  throw Error("No torsion fixture found in bounded nonce search");
}
