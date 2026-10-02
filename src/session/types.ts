export const Action = Object.freeze({
  Transfer: 0x00,
  SessionCancel: 0x07,
  CleanupGrant: 0x08,
  ActivateAuthorization: 0x80,
  CreateGrant: 0x81,
  RevokeGrant: 0x82,
  ReplaceGrant: 0x83,
  RevokeAllGrants: 0x84,
  RotateRoot: 0x85,
  SetSecurityReserve: 0x86,
} as const);
export type ActionType = (typeof Action)[keyof typeof Action];
export const AuthMode = Object.freeze({ Direct: 0, Root: 1, Session: 2 } as const);
export const KeyScheme = Object.freeze({ Ed25519: 1, P256: 2 } as const);
export type Scheme = 1 | 2;
export interface ChainContext {
  chainId: bigint;
  genesisHash: Uint8Array;
}
export interface RootKey {
  keyScheme: 1;
  publicKey: Uint8Array;
}
export interface RootConfig {
  version: 1;
  threshold: number;
  keys: readonly RootKey[];
}
export interface RootWitnessEntry {
  rootKeyId: Uint8Array;
  signature: Uint8Array;
}
export interface RecipientProof {
  leafIndex: number;
  leafCount: number;
  siblings: readonly Uint8Array[];
}
export interface SessionWitness {
  signature: Uint8Array;
  recipientProof?: RecipientProof;
}
export interface TokenBucket {
  capacity: bigint;
  refillPerBlock: bigint;
}
export type RecipientSet =
  | { kind: 0; recipients: readonly Uint8Array[] }
  | { kind: 1; merkleRoot: Uint8Array; leafCount: number };
export interface LimitSet {
  maxPerTransaction: bigint;
  lifetimeLimit: bigint;
  valueTokenBucket?: TokenBucket;
}
export interface FeePolicy {
  maxGasLimit: bigint;
  maxGasPrice: bigint;
  maxFeePerTransaction: bigint;
  lifetimeFeeLimit: bigint;
  feeTokenBucket?: TokenBucket;
}
export interface TransferPolicy {
  recipients: RecipientSet;
  limits: LimitSet;
  allowZeroValue: boolean;
  allowSelfTransfer: boolean;
}
/** Initial policy scope is transfer-only, including inline/Merkle recipients and buckets. */
export interface Policy {
  version: 1;
  actionMask: bigint;
  maxAttempts: bigint;
  fee: FeePolicy;
  transfer: TransferPolicy;
}
/** Public keys use their wire width: Ed25519 32 bytes, P-256 X||Y 64 bytes. */
export interface GrantSpec {
  keyScheme: Scheme;
  publicKey: Uint8Array;
  validAfterHeight: bigint;
  validUntilHeight: bigint;
  policy: Policy;
  storageDeposit: bigint;
}
export interface ActivateAuthorization {
  version: 1;
  config: RootConfig;
  securityReserve: bigint;
}
export interface CreateGrant {
  version: 1;
  grant: GrantSpec;
}
export interface RevokeGrant {
  version: 1;
  grantId: Uint8Array;
}
export interface ReplaceGrant {
  version: 1;
  oldGrantId: Uint8Array;
  newGrant: GrantSpec;
}
export interface RotateRoot {
  version: 1;
  config: RootConfig;
  reserveMode: 0 | 1;
  replacementReserve: bigint;
}
export interface SetSecurityReserve {
  version: 1;
  securityReserve: bigint;
}
export interface CleanupGrant {
  version: 1;
  owner: Uint8Array;
  grantId: Uint8Array;
}
export interface TxIntent {
  version: 2;
  chainId: bigint;
  sender: Uint8Array;
  actionType: ActionType;
  flags: 0;
  destination: Uint8Array;
  value: bigint;
  gasLimit: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  sponsor: Uint8Array;
  data: Uint8Array;
}
export interface AuthEnvelope {
  version: 1;
  mode: 0 | 1 | 2;
  keyScheme: Scheme;
  credentialId: Uint8Array;
  authEpoch: bigint;
  policyHash: Uint8Array;
  nonce: bigint;
  sponsorNonce: bigint;
  witness: Uint8Array;
  sponsorWitness: Uint8Array;
}
export interface Transaction {
  intent: TxIntent;
  envelope: AuthEnvelope;
}
export interface SessionCredential {
  grantId: Uint8Array;
  authEpoch: bigint;
  policyHash: Uint8Array;
  nonce: bigint;
}
