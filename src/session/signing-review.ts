import { bytesToHex, Writer } from "../core/bytes.js";
import { domainHash } from "../core/hash.js";
import { reviewIntent, reviewTransaction } from "../display/review.js";
import type { CanonicalReview } from "../display/review.js";
import { chainDomain } from "./hash.js";
import { rootKeyId, sessionKeyFingerprint } from "./keys.js";
import { rootConfigCodec } from "./root.js";
import { transactionCodec, txIntentCodec } from "./transaction.js";
import type { ChainContext, RootConfig, Scheme, Transaction } from "./types.js";

export type SigningAuthority =
  | {
      readonly mode: "DIRECT" | "SESSION";
      readonly keyScheme: Scheme;
      readonly publicKey: `0x${string}`;
      readonly keyFingerprint: `0x${string}`;
    }
  | {
      readonly mode: "ROOT";
      readonly threshold: number;
      readonly configCanonical: `0x${string}`;
      readonly keys: readonly {
        readonly keyScheme: 1;
        readonly publicKey: `0x${string}`;
        readonly rootKeyId: `0x${string}`;
      }[];
      readonly selectedKeyIds: readonly `0x${string}`[];
    };
export interface SigningReview {
  /** SDK-only binding including every public signing input, not an on-chain digest. */
  readonly reviewHash: `0x${string}`;
  readonly reviewHashDomain: "RESILIENCE_SDK_SIGNING_REVIEW_V1";
  readonly intent: CanonicalReview;
  /** Zero signature placeholders: template hash is NOT the final transaction ID. */
  readonly transactionTemplate: CanonicalReview;
  readonly signaturePlaceholder: "64-zero-bytes";
  readonly signingDigest: `0x${string}`;
  readonly authority: SigningAuthority;
}
export interface ReviewApprovalRequest {
  readonly review: SigningReview;
  readonly signal: AbortSignal;
}
/** Application-owned review UI. Only literal true approves this exact snapshot. */
export type ReviewApproval = (
  request: ReviewApprovalRequest,
) => boolean | Promise<boolean>;

/** Called only with the signer's owned, validated snapshots. */
export function buildSigningReview(
  context: ChainContext,
  template: Transaction,
  digest: Uint8Array,
  publicKey?: Uint8Array,
  config?: RootConfig,
  selectedKeyIds?: readonly Uint8Array[],
): SigningReview {
  const { mode, keyScheme } = template.envelope;
  const metadata = new Writer(600);
  metadata.number(1, 16);
  metadata.number(mode, 8);
  metadata.number(keyScheme, 8);
  let authority: SigningAuthority;
  if (mode === 1) {
    const bytes = rootConfigCodec.encode(config!);
    metadata.bytes(bytes, 270);
    metadata.number(selectedKeyIds!.length, 8);
    for (const id of selectedKeyIds!) metadata.fixed(id, 32);
    authority = Object.freeze({
      mode: "ROOT",
      threshold: config!.threshold,
      configCanonical: bytesToHex(bytes),
      keys: Object.freeze(
        config!.keys.map((key) =>
          Object.freeze({
            keyScheme: key.keyScheme,
            publicKey: bytesToHex(key.publicKey),
            rootKeyId: bytesToHex(rootKeyId(key)),
          }),
        ),
      ),
      selectedKeyIds: Object.freeze(selectedKeyIds!.map((id) => bytesToHex(id))),
    });
  } else {
    metadata.fixed(publicKey!, keyScheme === 1 ? 32 : 64);
    authority = Object.freeze({
      mode: mode === 0 ? "DIRECT" : "SESSION",
      keyScheme,
      publicKey: bytesToHex(publicKey!),
      keyFingerprint: bytesToHex(sessionKeyFingerprint(keyScheme, publicKey!)),
    });
  }
  const bytes = transactionCodec.encode(template);
  return Object.freeze({
    reviewHash: bytesToHex(
      domainHash(
        "RESILIENCE_SDK_SIGNING_REVIEW_V1",
        chainDomain(context),
        bytes,
        metadata.finish(),
      ),
    ),
    reviewHashDomain: "RESILIENCE_SDK_SIGNING_REVIEW_V1",
    intent: reviewIntent(context, txIntentCodec.encode(template.intent)),
    transactionTemplate: reviewTransaction(context, bytes),
    signaturePlaceholder: "64-zero-bytes",
    signingDigest: bytesToHex(digest),
    authority,
  });
}
