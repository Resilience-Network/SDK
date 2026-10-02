import {
  checkedBytes,
  codec,
  fixedBytes,
  isZero,
  MAX_TRANSACTION_BYTES,
  objectFields,
  requireCondition,
  Reader,
  Writer,
} from "../core/bytes.js";
import {
  activateAuthorizationCodec,
  cleanupGrantCodec,
  createGrantCodec,
  replaceGrantCodec,
  revokeGrantCodec,
  rotateRootCodec,
  setSecurityReserveCodec,
} from "./actions.js";
import {
  sessionWitnessCodec,
  validateRootWitnessStructure,
  versionOne,
} from "./root.js";
import { Action } from "./types.js";
import type { AuthEnvelope, Transaction, TxIntent } from "./types.js";

function validateIntent(intent: TxIntent): void {
  objectFields(intent, [
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
  ]);
  requireCondition(
    intent.version === 2,
    "Unsupported intent version",
    "UNSUPPORTED_VERSION",
  );
  requireCondition(
    Object.values(Action).includes(intent.actionType),
    "Action is not implemented",
    "UNSUPPORTED_FEATURE",
  );
  fixedBytes(intent.sender, 20);
  fixedBytes(intent.destination, 20);
  fixedBytes(intent.sponsor, 20);
  checkedBytes(intent.data, 65_536);
  requireCondition(intent.flags === 0, "Nonzero intent flags", "NON_CANONICAL");
  requireCondition(
    !isZero(intent.sender) && intent.gasLimit > 0n,
    "Zero sender or gas limit",
  );
  requireCondition(
    intent.maxPriorityFeePerGas <= intent.maxFeePerGas,
    "Priority fee exceeds max fee",
    "NON_CANONICAL",
  );
  requireCondition(
    isZero(intent.sponsor) ||
      !intent.sponsor.every((byte, i) => byte === intent.sender[i]),
    "Self sponsorship",
    "NON_CANONICAL",
  );
  if (intent.actionType === Action.Transfer) {
    requireCondition(
      !isZero(intent.destination) && intent.data.length === 0,
      "Noncanonical transfer fields",
      "NON_CANONICAL",
    );
    return;
  }
  requireCondition(
    isZero(intent.destination) && intent.value === 0n,
    "Noncanonical control fields",
    "NON_CANONICAL",
  );
  switch (intent.actionType) {
    case Action.SessionCancel:
    case Action.RevokeAllGrants:
      requireCondition(
        intent.data.length === 0,
        "Action requires empty data",
        "NON_CANONICAL",
      );
      break;
    case Action.ActivateAuthorization:
      activateAuthorizationCodec.decode(intent.data);
      break;
    case Action.CreateGrant:
      createGrantCodec.decode(intent.data);
      break;
    case Action.RevokeGrant:
      revokeGrantCodec.decode(intent.data);
      break;
    case Action.ReplaceGrant:
      replaceGrantCodec.decode(intent.data);
      break;
    case Action.RotateRoot:
      rotateRootCodec.decode(intent.data);
      break;
    case Action.SetSecurityReserve:
      setSecurityReserveCodec.decode(intent.data);
      break;
    case Action.CleanupGrant:
      cleanupGrantCodec.decode(intent.data);
      break;
  }
}

function writeIntent(w: Writer, v: TxIntent): void {
  validateIntent(v);
  w.number(v.version, 16);
  w.uint(v.chainId, 64);
  w.fixed(v.sender, 20);
  w.number(v.actionType, 8);
  w.number(v.flags, 16);
  w.fixed(v.destination, 20);
  w.uint(v.value, 256);
  w.uint(v.gasLimit, 64);
  w.uint(v.maxFeePerGas, 256);
  w.uint(v.maxPriorityFeePerGas, 256);
  w.fixed(v.sponsor, 20);
  w.bytes(v.data, 65_536);
}
function readIntent(r: Reader): TxIntent {
  return {
    version: r.number(16) as 2,
    chainId: r.uint(64),
    sender: r.fixed(20),
    actionType: r.number(8) as TxIntent["actionType"],
    flags: r.number(16) as 0,
    destination: r.fixed(20),
    value: r.uint(256),
    gasLimit: r.uint(64),
    maxFeePerGas: r.uint(256),
    maxPriorityFeePerGas: r.uint(256),
    sponsor: r.fixed(20),
    data: r.data(65_536),
  };
}

function writeEnvelope(w: Writer, v: AuthEnvelope): void {
  objectFields(v, [
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
  ]);
  versionOne(v.version);
  fixedBytes(v.credentialId, 32);
  fixedBytes(v.policyHash, 32);
  checkedBytes(v.witness, 1_098);
  checkedBytes(v.sponsorWitness, 96);
  requireCondition(
    v.sponsorWitness.length === 0 || v.sponsorWitness.length === 96,
    "Sponsor witness width",
  );
  switch (v.mode) {
    case 0:
      requireCondition(
        v.keyScheme === 1,
        "DIRECT requires Ed25519",
        "UNSUPPORTED_FEATURE",
      );
      requireCondition(
        isZero(v.credentialId) && v.authEpoch === 0n && isZero(v.policyHash),
        "Noncanonical DIRECT sentinel fields",
        "NON_CANONICAL",
      );
      fixedBytes(v.witness, 96);
      break;
    case 1:
      requireCondition(
        v.keyScheme === 1,
        "ROOT requires Ed25519",
        "UNSUPPORTED_FEATURE",
      );
      requireCondition(
        !isZero(v.credentialId) && isZero(v.policyHash),
        "Noncanonical ROOT sentinel fields",
        "NON_CANONICAL",
      );
      validateRootWitnessStructure(v.witness);
      break;
    case 2:
      requireCondition(
        v.keyScheme === 1 || v.keyScheme === 2,
        "Unsupported session scheme",
        "UNSUPPORTED_FEATURE",
      );
      requireCondition(
        !isZero(v.credentialId) && !isZero(v.policyHash),
        "Missing SESSION identity",
        "NON_CANONICAL",
      );
      sessionWitnessCodec.decode(v.witness);
      break;
    default:
      requireCondition(false, "Unsupported authorization mode", "UNSUPPORTED_FEATURE");
  }
  w.number(v.version, 16);
  w.number(v.mode, 8);
  w.number(v.keyScheme, 8);
  w.fixed(v.credentialId, 32);
  w.uint(v.authEpoch, 64);
  w.fixed(v.policyHash, 32);
  w.uint(v.nonce, 64);
  w.uint(v.sponsorNonce, 64);
  w.bytes(v.witness, 1_098);
  w.bytes(v.sponsorWitness, 96);
}
function readEnvelope(r: Reader): AuthEnvelope {
  return {
    version: r.number(16) as 1,
    mode: r.number(8) as AuthEnvelope["mode"],
    keyScheme: r.number(8) as AuthEnvelope["keyScheme"],
    credentialId: r.fixed(32),
    authEpoch: r.uint(64),
    policyHash: r.fixed(32),
    nonce: r.uint(64),
    sponsorNonce: r.uint(64),
    witness: r.data(1_098),
    sponsorWitness: r.data(96),
  };
}
export const txIntentCodec = codec<TxIntent>(181 + 65_536, writeIntent, readIntent);
export const authEnvelopeCodec = codec<AuthEnvelope>(
  100 + 1_098 + 96,
  writeEnvelope,
  readEnvelope,
);

function validateBinding({ intent, envelope }: Transaction): void {
  const sponsored = !isZero(intent.sponsor);
  requireCondition(
    sponsored
      ? envelope.sponsorWitness.length === 96
      : envelope.sponsorWitness.length === 0 && envelope.sponsorNonce === 0n,
    "Intent/envelope sponsor mismatch",
    "NON_CANONICAL",
  );
}
/** Transaction V2 is intent || envelope, without a wrapper or length prefixes. */
export const transactionCodec = codec<Transaction>(
  MAX_TRANSACTION_BYTES,
  (w, v) => {
    objectFields(v, ["intent", "envelope"]);
    w.fixed(txIntentCodec.encode(v.intent));
    w.fixed(authEnvelopeCodec.encode(v.envelope));
    validateBinding(v);
  },
  (r) => ({ intent: readIntent(r), envelope: readEnvelope(r) }),
);
