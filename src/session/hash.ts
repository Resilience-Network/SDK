import {
  encodeUint64,
  checkedBytes,
  fixedBytes,
  isZero,
  requireCondition,
  Writer,
} from "../core/bytes.js";
import { domainHash } from "../core/hash.js";
import { sessionKeyFingerprint } from "./keys.js";
import { policyCodec } from "./policy.js";
import { rootConfigCodec } from "./root.js";
import { authEnvelopeCodec, txIntentCodec } from "./transaction.js";
import type {
  AuthEnvelope,
  ChainContext,
  Policy,
  RootConfig,
  Scheme,
  SessionCredential,
  TxIntent,
} from "./types.js";

export function chainDomain(context: ChainContext): Uint8Array {
  return domainHash(
    "RESILIENCE_CHAIN_DOMAIN_V1",
    fixedBytes(context.genesisHash, 32),
    encodeUint64(context.chainId),
  );
}
export function rootConfigHash(value: RootConfig): Uint8Array {
  return domainHash("RESILIENCE_ROOT_CONFIG_V1", rootConfigCodec.encode(value));
}
export function policyHash(value: Policy): Uint8Array {
  return domainHash("RESILIENCE_POLICY_V1", policyCodec.encode(value));
}
export function intentHash(context: ChainContext, intent: TxIntent): Uint8Array {
  requireCondition(
    intent.chainId === context.chainId,
    "Intent chain ID mismatch",
    "CONTEXT_MISMATCH",
  );
  return domainHash(
    "RESILIENCE_TX_INTENT_V2",
    chainDomain(context),
    txIntentCodec.encode(intent),
  );
}
export function transactionId(
  context: ChainContext,
  intent: TxIntent,
  envelope: AuthEnvelope,
): Uint8Array {
  return domainHash(
    "RESILIENCE_TX_ID_V2",
    intentHash(context, intent),
    authEnvelopeCodec.encode(envelope),
  );
}
export function directDigest(
  context: ChainContext,
  intent: TxIntent,
  nonce: bigint,
): Uint8Array {
  return domainHash(
    "RESILIENCE_DIRECT_AUTH_V1",
    chainDomain(context),
    fixedBytes(intent.sender, 20),
    encodeUint64(nonce),
    intentHash(context, intent),
  );
}
export function rootDigest(
  context: ChainContext,
  intent: TxIntent,
  configHash: Uint8Array,
  authEpoch: bigint,
  nonce: bigint,
): Uint8Array {
  return domainHash(
    "RESILIENCE_ROOT_AUTH_V1",
    chainDomain(context),
    fixedBytes(intent.sender, 20),
    fixedBytes(configHash, 32),
    encodeUint64(authEpoch),
    encodeUint64(nonce),
    intentHash(context, intent),
  );
}
export function sessionDigest(
  context: ChainContext,
  intent: TxIntent,
  credential: SessionCredential,
): Uint8Array {
  return domainHash(
    "RESILIENCE_SESSION_AUTH_V1",
    chainDomain(context),
    fixedBytes(intent.sender, 20),
    fixedBytes(credential.grantId, 32),
    encodeUint64(credential.authEpoch),
    fixedBytes(credential.policyHash, 32),
    encodeUint64(credential.nonce),
    intentHash(context, intent),
  );
}
export function sponsorDigest(
  context: ChainContext,
  intent: TxIntent,
  sponsor: Uint8Array,
  nonce: bigint,
): Uint8Array {
  fixedBytes(sponsor, 20);
  requireCondition(
    !isZero(sponsor) && sponsor.every((v, i) => v === intent.sponsor[i]),
    "Sponsor binding mismatch",
    "CONTEXT_MISMATCH",
  );
  return domainHash(
    "RESILIENCE_SPONSOR_AUTH_V1",
    chainDomain(context),
    sponsor,
    encodeUint64(nonce),
    intentHash(context, intent),
  );
}
export function grantId(
  context: ChainContext,
  owner: Uint8Array,
  authEpoch: bigint,
  generationSequence: bigint,
  scheme: Scheme,
  publicKey: Uint8Array,
): Uint8Array {
  return domainHash(
    "RESILIENCE_GRANT_ID_V1",
    chainDomain(context),
    fixedBytes(owner, 20),
    encodeUint64(authEpoch),
    encodeUint64(generationSequence),
    sessionKeyFingerprint(scheme, publicKey),
  );
}
export function authorizationMetaKey(): Uint8Array {
  return domainHash("RESILIENCE_AUTH_META_KEY_V1");
}
export function authorizationRecoveryKey(): Uint8Array {
  return domainHash("RESILIENCE_AUTH_RECOVERY_KEY_V1");
}
export function authorizationGrantKey(id: Uint8Array): Uint8Array {
  fixedBytes(id, 32);
  requireCondition(!isZero(id), "Zero grant ID");
  return domainHash("RESILIENCE_AUTH_GRANT_KEY_V1", id);
}
export function authorizationActiveKey(
  epoch: bigint,
  fingerprint: Uint8Array,
): Uint8Array {
  fixedBytes(fingerprint, 32);
  requireCondition(epoch > 0n && !isZero(fingerprint), "Empty active key identity");
  return domainHash("RESILIENCE_AUTH_ACTIVE_KEY_V1", encodeUint64(epoch), fingerprint);
}
function recipientAction(action: number): Uint8Array {
  requireCondition(
    action === 0 || action === 5,
    "Action has no recipient set",
    "UNSUPPORTED_FEATURE",
  );
  return Uint8Array.of(action);
}
export function recipientLeafHash(
  context: ChainContext,
  action: number,
  recipient: Uint8Array,
): Uint8Array {
  fixedBytes(recipient, 20);
  requireCondition(!isZero(recipient), "Zero recipient");
  return domainHash(
    "RESILIENCE_RECIPIENT_LEAF_V1",
    chainDomain(context),
    recipientAction(action),
    recipient,
  );
}
export function recipientEmptyLeafHash(
  context: ChainContext,
  action: number,
  index: number,
): Uint8Array {
  const w = new Writer(4);
  w.number(index, 32);
  return domainHash(
    "RESILIENCE_RECIPIENT_EMPTY_LEAF_V1",
    chainDomain(context),
    recipientAction(action),
    w.finish(),
  );
}
export function recipientNodeHash(
  context: ChainContext,
  action: number,
  left: Uint8Array,
  right: Uint8Array,
): Uint8Array {
  return domainHash(
    "RESILIENCE_RECIPIENT_NODE_V1",
    chainDomain(context),
    recipientAction(action),
    fixedBytes(left, 32),
    fixedBytes(right, 32),
  );
}
export function validatorConsensusKeyHash(publicKey: Uint8Array): Uint8Array {
  checkedBytes(publicKey, 65_536 - 8);
  requireCondition(
    publicKey.length > 0 && publicKey.length <= 65_536 - 8,
    "Validator key length exceeds bounds",
    "LIMIT_EXCEEDED",
  );
  const writer = new Writer();
  writer.number(publicKey.length, 32);
  writer.fixed(publicKey);
  return domainHash("RESILIENCE_VALIDATOR_CONSENSUS_KEY_V1", writer.finish());
}
