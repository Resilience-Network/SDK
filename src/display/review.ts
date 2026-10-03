import {
  bytesToHex,
  checkedNumber,
  checkedUint,
  fixedBytes,
  objectFields,
} from "../core/bytes.js";
import {
  activateAuthorizationCodec,
  cleanupGrantCodec,
  createGrantCodec,
  replaceGrantCodec,
  revokeGrantCodec,
  rotateRootCodec,
  setSecurityReserveCodec,
} from "../session/actions.js";
import {
  chainDomain,
  directDigest,
  intentHash,
  policyHash,
  rootConfigHash,
  rootDigest,
  sessionDigest,
  sponsorDigest,
  transactionId,
} from "../session/hash.js";
import { rootKeyId, sessionKeyFingerprint } from "../session/keys.js";
import { policyCodec } from "../session/policy.js";
import { decodeRootWitness, sessionWitnessCodec } from "../session/root.js";
import { transactionCodec, txIntentCodec } from "../session/transaction.js";
import { Action } from "../session/types.js";
import type {
  AuthEnvelope,
  ChainContext,
  GrantSpec,
  Policy,
  RootConfig,
  TokenBucket,
  TxIntent,
} from "../session/types.js";

/** Stable paths and exact values for a renderer. All returned data is frozen. */
export interface ReviewField {
  readonly path: string;
  readonly label: string;
  readonly value: string | boolean;
  readonly unit:
    | "integer"
    | "base-units"
    | "base-units-per-gas"
    | "gas"
    | "height"
    | "bytes"
    | "boolean"
    | "enum";
  readonly meaning: string;
  readonly source: "canonical" | "derived";
}
export interface ReviewBinding {
  readonly canonical: `0x${string}`;
  readonly hash: `0x${string}`;
  readonly hashDomain:
    "RESILIENCE_POLICY_V1" | "RESILIENCE_TX_INTENT_V2" | "RESILIENCE_TX_ID_V2";
  readonly network?: {
    readonly chainId: string;
    readonly genesisHash: `0x${string}`;
    readonly chainDomain: `0x${string}`;
  };
}
export interface CanonicalReview {
  readonly kind: "policy" | "intent" | "transaction";
  readonly binding: ReviewBinding;
  readonly fields: readonly ReviewField[];
  readonly verification: "canonical-structure-only";
}

/** Exact unsigned base-unit rendering. No locale, rounding, scientific notation or ticker. */
export function formatBaseUnits(value: bigint, decimals = 0): string {
  checkedUint(value, 256);
  checkedNumber(decimals, 255);
  const digits = value.toString();
  if (decimals === 0) return digits;
  const padded = digits.padStart(decimals + 1, "0");
  return `${padded.slice(0, -decimals)}.${padded.slice(-decimals)}`;
}

type Fields = ReviewField[];
function field(
  fields: Fields,
  path: string,
  label: string,
  value: string | boolean | bigint | number,
  unit: ReviewField["unit"],
  meaning = "Exact canonical field; no live authority or inclusion claim.",
  source: ReviewField["source"] = "canonical",
): void {
  fields.push(
    Object.freeze({
      path,
      label,
      value: typeof value === "boolean" ? value : String(value),
      unit,
      meaning,
      source,
    }),
  );
}
function hex(
  fields: Fields,
  path: string,
  label: string,
  bytes: Uint8Array,
  meaning?: string,
  source?: ReviewField["source"],
): void {
  field(fields, path, label, bytesToHex(bytes), "bytes", meaning, source);
}
function bucket(
  fields: Fields,
  path: string,
  label: string,
  value?: TokenBucket,
): void {
  field(
    fields,
    `${path}.enabled`,
    `${label} enabled`,
    value !== undefined,
    "boolean",
    value
      ? "Additional rate limit; finite lifetime and per-transaction limits still apply."
      : "No additional token-bucket rate limit; other finite limits still apply.",
  );
  if (value) {
    field(
      fields,
      `${path}.capacity`,
      `${label} capacity`,
      value.capacity,
      "base-units",
      "Nonzero finite capacity.",
    );
    field(
      fields,
      `${path}.refillPerBlock`,
      `${label} refill per block`,
      value.refillPerBlock,
      "base-units",
      value.refillPerBlock === 0n
        ? "Zero refill: tokens never replenish."
        : "Refill per block, capped by capacity.",
    );
  }
}
function policyFields(fields: Fields, p: Policy, prefix = "policy"): void {
  field(fields, `${prefix}.version`, "Policy version", p.version, "integer");
  field(
    fields,
    `${prefix}.actionMask`,
    "Allowed action mask",
    p.actionMask,
    "integer",
    "Only native transfer is enabled.",
  );
  field(
    fields,
    `${prefix}.maxAttempts`,
    "Maximum included attempts",
    p.maxAttempts,
    "integer",
    "Nonzero finite cap; included authorized failures consume attempts.",
  );
  field(
    fields,
    `${prefix}.fee.maxGasLimit`,
    "Maximum gas limit",
    p.fee.maxGasLimit,
    "gas",
    "Nonzero finite fee bound.",
  );
  field(
    fields,
    `${prefix}.fee.maxGasPrice`,
    "Maximum gas price",
    p.fee.maxGasPrice,
    "base-units-per-gas",
    "Bounds maxFeePerGas; nonzero finite cap.",
  );
  field(
    fields,
    `${prefix}.fee.maxFeePerTransaction`,
    "Maximum fee per transaction",
    p.fee.maxFeePerTransaction,
    "base-units",
    "Nonzero finite maximum possible fee bound.",
  );
  field(
    fields,
    `${prefix}.fee.lifetimeFeeLimit`,
    "Lifetime fee limit",
    p.fee.lifetimeFeeLimit,
    "base-units",
    "Nonzero finite cap; actual included fees consume it.",
  );
  bucket(fields, `${prefix}.fee.feeTokenBucket`, "Fee bucket", p.fee.feeTokenBucket);
  const recipients = p.transfer.recipients;
  field(
    fields,
    `${prefix}.transfer.recipients.kind`,
    "Recipient restriction",
    recipients.kind === 0 ? "inline-allowlist" : "merkle-allowlist",
    "enum",
    "Restricted recipients; no unrestricted recipient form is supported.",
  );
  if (recipients.kind === 0) {
    field(
      fields,
      `${prefix}.transfer.recipients.count`,
      "Recipient count",
      recipients.recipients.length,
      "integer",
      "All canonical recipients are shown; no truncation.",
      "derived",
    );
    recipients.recipients.forEach((address, i) =>
      hex(
        fields,
        `${prefix}.transfer.recipients[${i}]`,
        `Allowed recipient ${i + 1}`,
        address,
      ),
    );
  } else {
    hex(
      fields,
      `${prefix}.transfer.recipients.merkleRoot`,
      "Recipient Merkle root",
      recipients.merkleRoot,
      "A membership proof is required; this root is not a recipient identity.",
    );
    field(
      fields,
      `${prefix}.transfer.recipients.leafCount`,
      "Recipient leaf count",
      recipients.leafCount,
      "integer",
    );
  }
  const limits = p.transfer.limits;
  for (const [name, label] of [
    ["maxPerTransaction", "Transfer maximum per transaction"],
    ["lifetimeLimit", "Transfer lifetime limit"],
  ] as const) {
    field(
      fields,
      `${prefix}.transfer.limits.${name}`,
      label,
      limits[name],
      "base-units",
      limits[name] === 0n
        ? "Zero cap: cannot move value; never unlimited."
        : "Finite value cap; never an unlimited sentinel.",
    );
  }
  bucket(
    fields,
    `${prefix}.transfer.limits.valueTokenBucket`,
    "Transfer value bucket",
    limits.valueTokenBucket,
  );
  field(
    fields,
    `${prefix}.transfer.allowZeroValue`,
    "Zero-value transfers allowed",
    p.transfer.allowZeroValue,
    "boolean",
    p.transfer.allowZeroValue
      ? "Zero-value transfers are permitted subject to all other checks."
      : "Zero-value transfers are denied.",
  );
  field(
    fields,
    `${prefix}.transfer.allowSelfTransfer`,
    "Self transfers allowed",
    p.transfer.allowSelfTransfer,
    "boolean",
    p.transfer.allowSelfTransfer
      ? "Transfers to the sender are permitted subject to all other checks."
      : "Transfers to the sender are denied.",
  );
  for (const name of [
    "contractCall",
    "contractCreate",
    "stake",
    "unstake",
    "delegate",
    "claimRewards",
  ])
    field(
      fields,
      `${prefix}.${name}.enabled`,
      `${name} enabled`,
      false,
      "boolean",
      "Disabled canonical policy section; unsupported by this SDK.",
    );
}
function rootFields(fields: Fields, config: RootConfig, path: string): void {
  field(
    fields,
    `${path}.version`,
    "Root configuration version",
    config.version,
    "integer",
  );
  hex(
    fields,
    `${path}.hash`,
    "Root configuration hash",
    rootConfigHash(config),
    undefined,
    "derived",
  );
  field(
    fields,
    `${path}.threshold`,
    "Required root signatures",
    config.threshold,
    "integer",
    "Exactly this many signatures from the sorted root key set are required.",
  );
  field(
    fields,
    `${path}.keyCount`,
    "Root key count",
    config.keys.length,
    "integer",
    "All configured keys are shown.",
    "derived",
  );
  config.keys.forEach((key, i) => {
    field(
      fields,
      `${path}.keys[${i}].keyScheme`,
      `Root key ${i + 1} scheme`,
      "Ed25519",
      "enum",
    );
    hex(
      fields,
      `${path}.keys[${i}].publicKey`,
      `Root public key ${i + 1}`,
      key.publicKey,
    );
    hex(
      fields,
      `${path}.keys[${i}].rootKeyId`,
      `Root key ${i + 1} ID`,
      rootKeyId(key),
      undefined,
      "derived",
    );
  });
}
function grantFields(fields: Fields, grant: GrantSpec, path: string): void {
  field(
    fields,
    `${path}.keyScheme`,
    "Session key scheme",
    grant.keyScheme === 1 ? "Ed25519" : "P-256-raw",
    "enum",
    "Native session key; WebAuthn assertion is a different signature domain.",
  );
  hex(fields, `${path}.publicKey`, "Session public key", grant.publicKey);
  hex(
    fields,
    `${path}.keyFingerprint`,
    "Session key fingerprint",
    sessionKeyFingerprint(grant.keyScheme, grant.publicKey),
    undefined,
    "derived",
  );
  field(
    fields,
    `${path}.validAfterHeight`,
    "First valid height",
    grant.validAfterHeight,
    "height",
    "Inclusive lower bound; no wall-clock expiry guarantee.",
  );
  field(
    fields,
    `${path}.validUntilHeight`,
    "First invalid height",
    grant.validUntilHeight,
    "height",
    "Exclusive upper bound; at this height the grant is expired.",
  );
  field(
    fields,
    `${path}.storageDeposit`,
    "Grant storage deposit",
    grant.storageDeposit,
    "base-units",
    "Nonzero locked deposit, distinct from transaction fees and reserve.",
  );
  hex(
    fields,
    `${path}.policyHash`,
    "Grant policy hash",
    policyHash(grant.policy),
    undefined,
    "derived",
  );
  policyFields(fields, grant.policy, `${path}.policy`);
}
function intentFields(fields: Fields, intent: TxIntent): void {
  field(
    fields,
    "intent.version",
    "Transaction intent version",
    intent.version,
    "integer",
  );
  field(fields, "intent.chainId", "Chain ID", intent.chainId, "integer");
  hex(fields, "intent.sender", "Sender account", intent.sender);
  field(
    fields,
    "intent.actionType",
    "Action",
    Object.entries(Action).find(([, code]) => code === intent.actionType)![0],
    "enum",
  );
  field(
    fields,
    "intent.actionCode",
    "Action code",
    intent.actionType,
    "integer",
    undefined,
    "derived",
  );
  field(
    fields,
    "intent.flags",
    "Intent flags",
    intent.flags,
    "integer",
    "Zero flags; extensions are not supported.",
  );
  hex(
    fields,
    "intent.destination",
    "Destination",
    intent.destination,
    intent.actionType === Action.Transfer
      ? "Exact transfer recipient address; application labels are untrusted."
      : "Zero sentinel for control actions; not a value recipient.",
  );
  field(
    fields,
    "intent.value",
    "Transferred value",
    intent.value,
    "base-units",
    intent.value === 0n
      ? "Exactly zero value; never hidden or unlimited."
      : "Exact native value in base units.",
  );
  field(fields, "intent.gasLimit", "Gas limit", intent.gasLimit, "gas");
  field(
    fields,
    "intent.maxFeePerGas",
    "Maximum fee per gas",
    intent.maxFeePerGas,
    "base-units-per-gas",
  );
  field(
    fields,
    "intent.maxPriorityFeePerGas",
    "Maximum priority fee per gas",
    intent.maxPriorityFeePerGas,
    "base-units-per-gas",
  );
  field(
    fields,
    "intent.maximumFee",
    "Maximum possible transaction fee",
    intent.gasLimit * intent.maxFeePerGas,
    "base-units",
    "Gas limit times fee cap; actual fee is determined at inclusion. This arithmetic does not establish admission.",
    "derived",
  );
  hex(
    fields,
    "intent.sponsor",
    "Fee sponsor",
    intent.sponsor,
    intent.sponsor.every((b) => b === 0)
      ? "Zero sentinel: no fee sponsor."
      : "Exact sponsor account; sponsorship is not supported by the raw signer helpers.",
  );
  hex(
    fields,
    "intent.data",
    "Canonical action data",
    intent.data,
    "Exact supported action payload; no opaque contract selector or proxy claim.",
  );
  const path = "intent.data";
  switch (intent.actionType) {
    case Action.Transfer:
      break;
    case Action.ActivateAuthorization: {
      const data = activateAuthorizationCodec.decode(intent.data);
      field(fields, `${path}.version`, "Action data version", data.version, "integer");
      rootFields(fields, data.config, `${path}.config`);
      field(
        fields,
        `${path}.securityReserve`,
        "Security reserve",
        data.securityReserve,
        "base-units",
        "Reserved security balance; zero is an exact zero reserve.",
      );
      break;
    }
    case Action.CreateGrant: {
      const data = createGrantCodec.decode(intent.data);
      field(fields, `${path}.version`, "Action data version", data.version, "integer");
      grantFields(fields, data.grant, `${path}.grant`);
      break;
    }
    case Action.ReplaceGrant: {
      const data = replaceGrantCodec.decode(intent.data);
      field(fields, `${path}.version`, "Action data version", data.version, "integer");
      hex(fields, `${path}.oldGrantId`, "Replaced grant ID", data.oldGrantId);
      grantFields(fields, data.newGrant, `${path}.newGrant`);
      break;
    }
    case Action.RevokeGrant: {
      const data = revokeGrantCodec.decode(intent.data);
      field(fields, `${path}.version`, "Action data version", data.version, "integer");
      hex(fields, `${path}.grantId`, "Revoked grant ID", data.grantId);
      break;
    }
    case Action.RotateRoot: {
      const data = rotateRootCodec.decode(intent.data);
      field(fields, `${path}.version`, "Action data version", data.version, "integer");
      rootFields(fields, data.config, `${path}.config`);
      field(
        fields,
        `${path}.reserveMode`,
        "Reserve mode",
        data.reserveMode === 0 ? "preserve" : "replace",
        "enum",
        "Rotation advances the authority epoch and invalidates current grants.",
      );
      field(
        fields,
        `${path}.replacementReserve`,
        "Replacement reserve",
        data.replacementReserve,
        "base-units",
        data.reserveMode === 0
          ? "Zero sentinel: preserve existing reserve, not reset to zero."
          : "Exact replacement reserve, including zero.",
      );
      break;
    }
    case Action.SetSecurityReserve: {
      const data = setSecurityReserveCodec.decode(intent.data);
      field(fields, `${path}.version`, "Action data version", data.version, "integer");
      field(
        fields,
        `${path}.securityReserve`,
        "Replacement security reserve",
        data.securityReserve,
        "base-units",
        "Exact replacement reserve, including zero.",
      );
      break;
    }
    case Action.CleanupGrant: {
      const data = cleanupGrantCodec.decode(intent.data);
      field(fields, `${path}.version`, "Action data version", data.version, "integer");
      hex(
        fields,
        `${path}.owner`,
        "Cleaned grant owner",
        data.owner,
        "Grant owner may differ from transaction sender.",
      );
      hex(fields, `${path}.grantId`, "Cleaned grant ID", data.grantId);
      break;
    }
    case Action.RevokeAllGrants:
      field(
        fields,
        `${path}.effect`,
        "Revoke-all effect",
        "advance-epoch-invalidate-all-grants",
        "enum",
        "Current grants become unusable; existing records may remain readable.",
        "derived",
      );
      break;
    case Action.SessionCancel:
      field(
        fields,
        `${path}.effect`,
        "Cancel effect",
        "consume-session-nonce-without-transfer",
        "enum",
        "Authority and fee checks still apply.",
        "derived",
      );
      break;
  }
}
function envelopeFields(
  fields: Fields,
  context: ChainContext,
  intent: TxIntent,
  e: AuthEnvelope,
): void {
  const p = "envelope";
  field(fields, `${p}.version`, "Authorization version", e.version, "integer");
  field(
    fields,
    `${p}.mode`,
    "Authorization mode",
    ["DIRECT", "ROOT", "SESSION"][e.mode]!,
    "enum",
  );
  field(
    fields,
    `${p}.keyScheme`,
    "Authorization key scheme",
    e.keyScheme === 1 ? "Ed25519" : "P-256-raw",
    "enum",
  );
  hex(
    fields,
    `${p}.credentialId`,
    "Authorization credential ID",
    e.credentialId,
    e.mode === 0
      ? "Zero DIRECT sentinel."
      : e.mode === 1
        ? "Root configuration hash; live configuration is not proven."
        : "Session grant ID; record existence is not live authority.",
  );
  field(fields, `${p}.authEpoch`, "Authority epoch", e.authEpoch, "integer");
  hex(
    fields,
    `${p}.policyHash`,
    "Authorization policy hash",
    e.policyHash,
    e.mode === 2
      ? "Requires exact matching live grant policy."
      : "Zero non-session sentinel.",
  );
  field(
    fields,
    `${p}.nonce`,
    "Authorization nonce",
    e.nonce,
    "integer",
    "Replay boundary; decoding does not establish the current nonce.",
  );
  field(fields, `${p}.sponsorNonce`, "Sponsor nonce", e.sponsorNonce, "integer");
  hex(
    fields,
    `${p}.witness`,
    "Authorization witness",
    e.witness,
    "Canonical framing only; signatures and membership have not been verified.",
  );
  hex(
    fields,
    `${p}.sponsorWitness`,
    "Sponsor witness",
    e.sponsorWitness,
    "Canonical framing only; sponsor signature has not been verified.",
  );
  const digest =
    e.mode === 0
      ? directDigest(context, intent, e.nonce)
      : e.mode === 1
        ? rootDigest(context, intent, e.credentialId, e.authEpoch, e.nonce)
        : sessionDigest(context, intent, {
            grantId: e.credentialId,
            authEpoch: e.authEpoch,
            policyHash: e.policyHash,
            nonce: e.nonce,
          });
  hex(
    fields,
    `${p}.signingDigest`,
    "Native authorization digest",
    digest,
    "Exact signing domain; not a WebAuthn assertion digest.",
    "derived",
  );
  if (e.mode === 0) {
    hex(fields, `${p}.directPublicKey`, "DIRECT public key", e.witness.slice(0, 32));
    hex(
      fields,
      `${p}.directKeyFingerprint`,
      "DIRECT key fingerprint",
      sessionKeyFingerprint(1, e.witness.slice(0, 32)),
      undefined,
      "derived",
    );
    hex(fields, `${p}.signature`, "DIRECT signature", e.witness.slice(32));
  } else if (e.mode === 1) {
    const entries = decodeRootWitness(e.witness, (e.witness[0]! << 8) | e.witness[1]!);
    field(
      fields,
      `${p}.rootSignatureCount`,
      "Provided root signatures",
      entries.length,
      "integer",
      "Not a verified live threshold.",
      "derived",
    );
    entries.forEach((entry, i) => {
      hex(
        fields,
        `${p}.rootWitness[${i}].rootKeyId`,
        `Signing root key ID ${i + 1}`,
        entry.rootKeyId,
      );
      hex(
        fields,
        `${p}.rootWitness[${i}].signature`,
        `Root signature ${i + 1}`,
        entry.signature,
      );
    });
  } else {
    const witness = sessionWitnessCodec.decode(e.witness);
    hex(fields, `${p}.signature`, "Session signature", witness.signature);
    field(
      fields,
      `${p}.recipientProof.present`,
      "Recipient proof present",
      witness.recipientProof !== undefined,
      "boolean",
      "Presence/framing does not prove policy membership.",
    );
    field(
      fields,
      `${p}.sessionPublicKey`,
      "Session public key source",
      "not-in-envelope",
      "enum",
      "Must resolve the matching live grant; never infer a key fingerprint from the grant ID.",
      "derived",
    );
    if (witness.recipientProof) {
      const proof = witness.recipientProof;
      field(
        fields,
        `${p}.recipientProof.leafIndex`,
        "Recipient leaf index",
        proof.leafIndex,
        "integer",
      );
      field(
        fields,
        `${p}.recipientProof.leafCount`,
        "Recipient proof leaf count",
        proof.leafCount,
        "integer",
      );
      proof.siblings.forEach((sibling, i) =>
        hex(
          fields,
          `${p}.recipientProof.siblings[${i}]`,
          `Recipient proof sibling ${i + 1}`,
          sibling,
        ),
      );
    }
  }
  if (e.sponsorWitness.length) {
    hex(
      fields,
      `${p}.sponsorPublicKey`,
      "Sponsor public key",
      e.sponsorWitness.slice(0, 32),
    );
    hex(
      fields,
      `${p}.sponsorSignature`,
      "Sponsor signature",
      e.sponsorWitness.slice(32),
    );
    hex(
      fields,
      `${p}.sponsorSigningDigest`,
      "Sponsor signing digest",
      sponsorDigest(context, intent, intent.sponsor, e.sponsorNonce),
      undefined,
      "derived",
    );
  }
}
function snapshot(context: ChainContext): ChainContext {
  objectFields(context, ["chainId", "genesisHash"]);
  return {
    chainId: checkedUint(context.chainId, 64),
    genesisHash: new Uint8Array(fixedBytes(context.genesisHash, 32)),
  };
}
function network(context: ChainContext): NonNullable<ReviewBinding["network"]> {
  return Object.freeze({
    chainId: context.chainId.toString(),
    genesisHash: bytesToHex(context.genesisHash),
    chainDomain: bytesToHex(chainDomain(context)),
  });
}
function document(
  kind: CanonicalReview["kind"],
  binding: ReviewBinding,
  fields: Fields,
): CanonicalReview {
  return Object.freeze({
    kind,
    binding: Object.freeze(binding),
    fields: Object.freeze(fields),
    verification: "canonical-structure-only",
  });
}
export function reviewPolicy(canonical: Uint8Array): CanonicalReview {
  const policy = policyCodec.decode(canonical),
    fields: Fields = [];
  policyFields(fields, policy);
  return document(
    "policy",
    {
      canonical: bytesToHex(policyCodec.encode(policy)),
      hash: bytesToHex(policyHash(policy)),
      hashDomain: "RESILIENCE_POLICY_V1",
    },
    fields,
  );
}
export function reviewIntent(
  context: ChainContext,
  canonical: Uint8Array,
): CanonicalReview {
  const expected = snapshot(context),
    intent = txIntentCodec.decode(canonical),
    fields: Fields = [];
  intentFields(fields, intent);
  return document(
    "intent",
    {
      canonical: bytesToHex(txIntentCodec.encode(intent)),
      hash: bytesToHex(intentHash(expected, intent)),
      hashDomain: "RESILIENCE_TX_INTENT_V2",
      network: network(expected),
    },
    fields,
  );
}
export function reviewTransaction(
  context: ChainContext,
  canonical: Uint8Array,
): CanonicalReview {
  const expected = snapshot(context),
    tx = transactionCodec.decode(canonical),
    fields: Fields = [];
  intentFields(fields, tx.intent);
  envelopeFields(fields, expected, tx.intent, tx.envelope);
  return document(
    "transaction",
    {
      canonical: bytesToHex(transactionCodec.encode(tx)),
      hash: bytesToHex(transactionId(expected, tx.intent, tx.envelope)),
      hashDomain: "RESILIENCE_TX_ID_V2",
      network: network(expected),
    },
    fields,
  );
}
