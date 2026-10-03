import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { sha512 } from "@noble/hashes/sha2.js";
import {
  boundedArray,
  checkedNumber,
  compareBytes,
  encodeUint64,
  fixedBytes,
  isZero,
  objectFields,
  requireCondition,
} from "../core/bytes.js";
import { keccak256 } from "../core/hash.js";
import { directDigest, rootConfigHash, rootDigest, sessionDigest } from "./hash.js";
import { rootKeyId, validateSessionPublicKey } from "./keys.js";
import {
  encodeRootWitness,
  recipientProofCodec,
  rootConfigCodec,
  sessionWitnessCodec,
} from "./root.js";
import { transactionCodec, txIntentCodec } from "./transaction.js";
import type {
  AuthEnvelope,
  ChainContext,
  RecipientProof,
  RootConfig,
  Scheme,
  SessionCredential,
  Transaction,
  TxIntent,
} from "./types.js";

export type SignerErrorCode =
  | "INVALID_SIGNATURE"
  | "SIGNER_MISMATCH"
  | "SIGNER_FAILED"
  | "MUTATED_INPUT"
  | "ABORTED"
  | "TIMEOUT";

/** Deliberately excludes adapter exceptions, keys and signature diagnostics. */
export class SignerError extends Error {
  constructor(public readonly code: SignerErrorCode) {
    super(`Authorization signing failed: ${code}`);
    this.name = "SignerError";
  }
}

export interface SignerRequest {
  readonly mode: 0 | 1 | 2;
  readonly keyScheme: Scheme;
  readonly publicKey: Uint8Array;
  /** Ed25519 signs these message bytes; P-256 signs this already-hashed digest. */
  readonly digest: Uint8Array;
  readonly signal: AbortSignal;
}
export interface SignerResponse {
  keyScheme: Scheme;
  publicKey: Uint8Array;
  /** Exactly 64 bytes: Ed25519 R||S or P-256 big-endian r||s. */
  signature: Uint8Array;
}
/** External ownership: no private-key input, generation or persistence. */
export interface RawSigner<S extends Scheme = Scheme> {
  readonly keyScheme: S;
  readonly publicKey: Uint8Array;
  sign(request: SignerRequest): Promise<SignerResponse>;
}
export interface SigningOptions {
  context: ChainContext;
  intent: TxIntent;
  signal?: AbortSignal;
  /** Overall operation deadline, including all ROOT signatures: 1..300000 ms. */
  timeoutMs?: number;
}
export interface DirectSigningOptions extends SigningOptions {
  nonce: bigint;
  signer: RawSigner<1>;
}
export interface RootSigningOptions extends SigningOptions {
  config: RootConfig;
  authEpoch: bigint;
  nonce: bigint;
  /** Explicit selection of exactly config.threshold distinct ROOT keys. */
  signers: readonly RawSigner<1>[];
}
export interface SessionSigningCredential extends SessionCredential {
  keyScheme: Scheme;
  publicKey: Uint8Array;
}
export interface SessionSigningOptions extends SigningOptions {
  credential: SessionSigningCredential;
  signer: RawSigner;
  recipientProof?: RecipientProof;
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return compareBytes(a, b) === 0;
}
function describe(signer: RawSigner): Uint8Array[] {
  objectFields(signer, ["keyScheme", "publicKey", "sign"]);
  validateSessionPublicKey(signer.keyScheme, signer.publicKey);
  requireCondition(typeof signer.sign === "function", "Missing signer callback");
  return [Uint8Array.of(signer.keyScheme), new Uint8Array(signer.publicKey)];
}
function common(options: SigningOptions): Uint8Array[] {
  objectFields(options.context, ["chainId", "genesisHash"]);
  requireCondition(
    isZero(options.intent.sponsor),
    "Sponsored signing is not implemented",
    "UNSUPPORTED_FEATURE",
  );
  return [
    encodeUint64(options.context.chainId),
    new Uint8Array(fixedBytes(options.context.genesisHash, 32)),
    txIntentCodec.encode(options.intent),
  ];
}
function snapshotContext(context: ChainContext): ChainContext {
  return { chainId: context.chainId, genesisHash: new Uint8Array(context.genesisHash) };
}
function watch(
  read: () => Uint8Array[],
  callbacks: () => readonly RawSigner["sign"][],
): () => void {
  const bytes = read().map((part) => new Uint8Array(part));
  const functions = [...callbacks()];
  return () => {
    try {
      const current = read(),
        currentFunctions = callbacks();
      if (
        current.length !== bytes.length ||
        !current.every((part, i) => same(part, bytes[i]!)) ||
        currentFunctions.length !== functions.length ||
        !currentFunctions.every((fn, i) => fn === functions[i])
      )
        throw new SignerError("MUTATED_INPUT");
    } catch {
      throw new SignerError("MUTATED_INPUT");
    }
  };
}

function verifySignature(
  scheme: Scheme,
  publicKey: Uint8Array,
  signature: Uint8Array,
  digest: Uint8Array,
): void {
  let valid = false;
  try {
    fixedBytes(signature, 64);
    if (scheme === 1) {
      // Chain also rejects noncanonical/small-order R before Ed25519 verification.
      validateSessionPublicKey(1, signature.subarray(0, 32));
      valid = ed25519.verify(signature, digest, publicKey, { zip215: false });
      if (valid) {
        // Noble uses a cofactored equation even in strict decoding mode. Go's
        // Ed25519 verifier requires SB = R + kA. Do not add a torsion-free-key
        // restriction: canonical mixed-order keys are allowed by the pin.
        const littleEndian = (bytes: Uint8Array): bigint => {
          let value = 0n;
          for (let i = bytes.length - 1; i >= 0; i--)
            value = (value << 8n) | BigInt(bytes[i]!);
          return value;
        };
        const challenge = new Uint8Array(96);
        challenge.set(signature.subarray(0, 32));
        challenge.set(publicKey, 32);
        challenge.set(digest, 64);
        const k = littleEndian(sha512(challenge)) % ed25519.Point.Fn.ORDER;
        const s = littleEndian(signature.subarray(32));
        const r = ed25519.Point.fromBytes(signature.subarray(0, 32), false);
        const a = ed25519.Point.fromBytes(publicKey, false);
        valid = ed25519.Point.BASE.multiplyUnsafe(s).equals(r.add(a.multiplyUnsafe(k)));
      }
    } else {
      const point = new Uint8Array(65);
      point[0] = 4;
      point.set(publicKey, 1);
      valid = p256.verify(signature, digest, point, {
        prehash: false,
        lowS: false,
        format: "compact",
      });
    }
  } catch {
    valid = false;
  }
  if (!valid) throw new SignerError("INVALID_SIGNATURE");
}

async function collect(
  signer: RawSigner,
  mode: 0 | 1 | 2,
  digest: Uint8Array,
  signal: AbortSignal,
  unchanged: () => void,
): Promise<Uint8Array> {
  unchanged();
  if (signal.aborted) throw new SignerError("ABORTED");
  const scheme = signer.keyScheme,
    key = new Uint8Array(signer.publicKey);
  const request: SignerRequest = {
    mode,
    keyScheme: scheme,
    publicKey: new Uint8Array(key),
    digest: new Uint8Array(digest),
    signal,
  };
  let response: SignerResponse;
  try {
    response = await signer.sign(request);
  } catch {
    unchanged();
    throw new SignerError("SIGNER_FAILED");
  }
  unchanged();
  if (signal.aborted) throw new SignerError("ABORTED");
  let requestUnchanged = false;
  try {
    requestUnchanged =
      request.mode === mode &&
      request.keyScheme === scheme &&
      request.signal === signal &&
      same(fixedBytes(request.publicKey, key.length), key) &&
      same(fixedBytes(request.digest, 32), digest);
  } catch {
    /* A replaced/malformed request is also a mutation. */
  }
  if (!requestUnchanged) throw new SignerError("MUTATED_INPUT");
  let responseScheme: Scheme, responseKey: Uint8Array, signature: Uint8Array;
  try {
    objectFields(response, ["keyScheme", "publicKey", "signature"]);
    responseScheme = response.keyScheme;
    responseKey = new Uint8Array(fixedBytes(response.publicKey, key.length));
    signature = new Uint8Array(fixedBytes(response.signature, 64));
  } catch {
    throw new SignerError("INVALID_SIGNATURE");
  }
  if (responseScheme !== scheme || !same(responseKey, key))
    throw new SignerError("SIGNER_MISMATCH");
  verifySignature(scheme, key, signature, digest);
  return signature;
}

async function bounded(
  options: SigningOptions,
  unchanged: () => void,
  work: (signal: AbortSignal, guard: () => void) => Promise<Transaction>,
): Promise<Transaction> {
  const timeout = options.timeoutMs ?? 30_000;
  checkedNumber(timeout, 300_000);
  requireCondition(timeout > 0, "Signing deadline must be positive");
  const external = options.signal;
  if (external?.aborted) throw new SignerError("ABORTED");
  const controller = new AbortController();
  const started = performance.now();
  let failure: SignerError | undefined;
  let rejectCancellation!: (error: SignerError) => void;
  const cancellation = new Promise<never>((_resolve, reject) => {
    rejectCancellation = reject;
  });
  const cancel = (code: "ABORTED" | "TIMEOUT") => {
    if (failure) return;
    failure = new SignerError(code);
    rejectCancellation(failure);
    controller.abort();
  };
  const onAbort = () => cancel("ABORTED");
  external?.addEventListener("abort", onAbort, { once: true });
  const timer = setTimeout(() => cancel("TIMEOUT"), timeout);
  const guard = () => {
    if (failure) throw failure;
    if (performance.now() - started >= timeout) {
      cancel("TIMEOUT");
      throw failure;
    }
    unchanged();
  };
  try {
    const result = await Promise.race([
      Promise.resolve().then(() => {
        guard();
        return work(controller.signal, guard);
      }),
      cancellation,
    ]);
    guard();
    return transactionCodec.decode(transactionCodec.encode(result));
  } finally {
    clearTimeout(timer);
    external?.removeEventListener("abort", onAbort);
    controller.abort();
  }
}

function envelope(
  mode: 0 | 1 | 2,
  scheme: Scheme,
  id: Uint8Array,
  epoch: bigint,
  policy: Uint8Array,
  nonce: bigint,
  witness: Uint8Array,
): AuthEnvelope {
  return {
    version: 1,
    mode,
    keyScheme: scheme,
    credentialId: new Uint8Array(id),
    authEpoch: epoch,
    policyHash: new Uint8Array(policy),
    nonce,
    sponsorNonce: 0n,
    witness,
    sponsorWitness: new Uint8Array(),
  };
}

export async function signDirectTransaction(
  options: DirectSigningOptions,
): Promise<Transaction> {
  objectFields(options, [
    "context",
    "intent",
    "nonce",
    "signer",
    "signal",
    "timeoutMs",
  ]);
  requireCondition(
    options.signer.keyScheme === 1,
    "DIRECT requires Ed25519",
    "UNSUPPORTED_FEATURE",
  );
  const unchanged = watch(
    () => [
      ...common(options),
      encodeUint64(options.nonce),
      ...describe(options.signer),
    ],
    () => [options.signer.sign],
  );
  const context = snapshotContext(options.context),
    intent = txIntentCodec.decode(txIntentCodec.encode(options.intent));
  const key = new Uint8Array(options.signer.publicKey),
    nonce = options.nonce;
  requireCondition(
    same(keccak256(key).subarray(12), intent.sender),
    "DIRECT signer does not match sender",
    "CONTEXT_MISMATCH",
  );
  const digest = directDigest(context, intent, nonce);
  return bounded(options, unchanged, async (signal, guard) => {
    const signature = await collect(options.signer, 0, digest, signal, guard);
    const witness = new Uint8Array(96);
    witness.set(key);
    witness.set(signature, 32);
    return {
      intent,
      envelope: envelope(
        0,
        1,
        new Uint8Array(32),
        0n,
        new Uint8Array(32),
        nonce,
        witness,
      ),
    };
  });
}

export async function signRootTransaction(
  options: RootSigningOptions,
): Promise<Transaction> {
  objectFields(options, [
    "context",
    "intent",
    "config",
    "authEpoch",
    "nonce",
    "signers",
    "signal",
    "timeoutMs",
  ]);
  boundedArray(options.signers, 1, 8);
  const unchanged = watch(
    () => [
      ...common(options),
      rootConfigCodec.encode(options.config),
      encodeUint64(options.authEpoch),
      encodeUint64(options.nonce),
      ...options.signers.flatMap(describe),
    ],
    () => options.signers.map((signer) => signer.sign),
  );
  const config = rootConfigCodec.decode(rootConfigCodec.encode(options.config));
  for (const key of config.keys) validateSessionPublicKey(1, key.publicKey);
  requireCondition(
    options.signers.length === config.threshold,
    "Select exactly the ROOT threshold",
    "NON_CANONICAL",
  );
  const selected = options.signers
    .map((signer) => {
      requireCondition(
        signer.keyScheme === 1,
        "ROOT requires Ed25519",
        "UNSUPPORTED_FEATURE",
      );
      const id = rootKeyId({ keyScheme: 1, publicKey: signer.publicKey });
      requireCondition(
        config.keys.some((key) => same(rootKeyId(key), id)),
        "Signer is not in ROOT config",
        "CONTEXT_MISMATCH",
      );
      return { signer, id };
    })
    .sort((a, b) => compareBytes(a.id, b.id));
  for (let i = 1; i < selected.length; i++)
    requireCondition(
      !same(selected[i - 1]!.id, selected[i]!.id),
      "Duplicate ROOT signer",
      "NON_CANONICAL",
    );
  const context = snapshotContext(options.context),
    intent = txIntentCodec.decode(txIntentCodec.encode(options.intent));
  const hash = rootConfigHash(config),
    epoch = options.authEpoch,
    nonce = options.nonce;
  const digest = rootDigest(context, intent, hash, epoch, nonce);
  return bounded(options, unchanged, async (signal, guard) => {
    const entries = [];
    for (const { signer, id } of selected)
      entries.push({
        rootKeyId: id,
        signature: await collect(signer, 1, digest, signal, guard),
      });
    return {
      intent,
      envelope: envelope(
        1,
        1,
        hash,
        epoch,
        new Uint8Array(32),
        nonce,
        encodeRootWitness(entries, config.threshold),
      ),
    };
  });
}

export async function signSessionTransaction(
  options: SessionSigningOptions,
): Promise<Transaction> {
  objectFields(options, [
    "context",
    "intent",
    "credential",
    "signer",
    "recipientProof",
    "signal",
    "timeoutMs",
  ]);
  const credentialParts = () => {
    const c = options.credential;
    objectFields(c, [
      "grantId",
      "authEpoch",
      "policyHash",
      "nonce",
      "keyScheme",
      "publicKey",
    ]);
    validateSessionPublicKey(c.keyScheme, c.publicKey);
    return [
      new Uint8Array(fixedBytes(c.grantId, 32)),
      encodeUint64(c.authEpoch),
      new Uint8Array(fixedBytes(c.policyHash, 32)),
      encodeUint64(c.nonce),
      Uint8Array.of(c.keyScheme),
      new Uint8Array(c.publicKey),
    ];
  };
  const unchanged = watch(
    () => [
      ...common(options),
      ...credentialParts(),
      ...describe(options.signer),
      options.recipientProof === undefined
        ? new Uint8Array()
        : recipientProofCodec.encode(options.recipientProof),
    ],
    () => [options.signer.sign],
  );
  const c = options.credential;
  requireCondition(
    c.keyScheme === options.signer.keyScheme &&
      same(c.publicKey, options.signer.publicKey),
    "Signer does not match SESSION credential",
    "CONTEXT_MISMATCH",
  );
  requireCondition(
    !isZero(c.grantId) && !isZero(c.policyHash),
    "Missing SESSION identity",
  );
  const credential = {
    grantId: new Uint8Array(c.grantId),
    authEpoch: c.authEpoch,
    policyHash: new Uint8Array(c.policyHash),
    nonce: c.nonce,
  };
  const scheme = c.keyScheme;
  const proof =
    options.recipientProof === undefined
      ? undefined
      : recipientProofCodec.decode(recipientProofCodec.encode(options.recipientProof));
  const context = snapshotContext(options.context),
    intent = txIntentCodec.decode(txIntentCodec.encode(options.intent));
  const digest = sessionDigest(context, intent, credential);
  return bounded(options, unchanged, async (signal, guard) => {
    const signature = await collect(options.signer, 2, digest, signal, guard);
    const witness = sessionWitnessCodec.encode(
      proof === undefined ? { signature } : { signature, recipientProof: proof },
    );
    return {
      intent,
      envelope: envelope(
        2,
        scheme,
        credential.grantId,
        credential.authEpoch,
        credential.policyHash,
        credential.nonce,
        witness,
      ),
    };
  });
}
