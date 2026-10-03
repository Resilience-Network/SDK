import {
  bytesToHex,
  checkedNumber,
  checkedUint,
  compareBytes,
  encodeUint64,
  fixedBytes,
  hexToBytes,
  isZero,
  objectFields,
  requireCondition,
} from "../core/bytes.js";
import { domainHash, keccak256 } from "../core/hash.js";
import { ChainRpcClient } from "../rpc/methods.js";
import { RpcClientError } from "../rpc/errors.js";
import { Deadline, systemClock } from "../rpc/deadline.js";
import type {
  AccountAuthorizationSnapshot,
  FundedGrantSnapshot,
  SessionGrantObservation,
} from "../rpc/contracts.js";
import type { ReconcileOptions } from "../rpc/submission.js";
import { NonceCoordinator, CoordinatorError } from "./coordinator.js";
import type { NonceAuthoritySnapshot } from "./coordinator.js";
import {
  activateAuthorizationCodec,
  createGrantCodec,
  revokeGrantCodec,
  replaceGrantCodec,
  rotateRootCodec,
  setSecurityReserveCodec,
  cleanupGrantCodec,
} from "./actions.js";
import {
  chainDomain,
  directDigest,
  rootDigest,
  sessionDigest,
  grantId,
  policyHash,
  rootConfigHash,
} from "./hash.js";
import { rootKeyId, validateSessionPublicKey } from "./keys.js";
import {
  rootConfigCodec,
  encodeRootWitness,
  recipientProofCodec,
  sessionWitnessCodec,
} from "./root.js";
import { transactionCodec, txIntentCodec } from "./transaction.js";
import { buildSigningReview } from "./signing-review.js";
import type { ReviewApproval, SigningReview } from "./signing-review.js";
import {
  signDirectTransaction,
  signRootTransaction,
  signSessionTransaction,
} from "./signers.js";
import type { RawSigner, SessionSigningCredential } from "./signers.js";
import {
  checkSessionTransfer,
  MAX_SESSION_LIFETIME_BLOCKS,
  MINIMUM_SECURITY_RESERVE,
  requiredGrantStorageDeposit,
} from "./lifecycle-policy.js";
import { Action } from "./types.js";
import type {
  AuthEnvelope,
  ChainContext,
  GrantSpec,
  RecipientProof,
  RootConfig,
  TxIntent,
} from "./types.js";

export type LifecycleErrorCode =
  | "INVALID_ARGUMENT"
  | "STATE_DENIED"
  | "STALE_AUTHORITY"
  | "MUTATED_INPUT"
  | "REVIEW_REJECTED"
  | "REVIEW_FAILED"
  | "READ_FAILED"
  | "FLOW_FAILED"
  | "ABORTED"
  | "TIMEOUT";
/** Sanitized: no adapter exceptions, endpoints, signatures or private material. */
export class LifecycleError extends Error {
  override readonly name = "LifecycleError";
  constructor(readonly code: LifecycleErrorCode) {
    super(`Session lifecycle failed: ${code}`);
  }
}
type RootSelection = { readonly signers: readonly RawSigner<1>[] };
export type LifecycleOperation =
  | {
      readonly kind: "activate";
      readonly config: RootConfig;
      readonly securityReserve: bigint;
      readonly signer: RawSigner<1>;
    }
  | (RootSelection & { readonly kind: "create-grant"; readonly grant: GrantSpec })
  | {
      readonly kind: "transfer";
      readonly credential: SessionSigningCredential;
      readonly signer: RawSigner;
      readonly destination: Uint8Array;
      readonly value: bigint;
      readonly recipientProof?: RecipientProof;
    }
  | (RootSelection & { readonly kind: "revoke-grant"; readonly grantId: Uint8Array })
  | (RootSelection & {
      readonly kind: "replace-grant";
      readonly oldGrantId: Uint8Array;
      readonly newGrant: GrantSpec;
    })
  | (RootSelection & { readonly kind: "revoke-all" })
  | (RootSelection & {
      readonly kind: "rotate-root";
      readonly config: RootConfig;
      readonly reserveMode: 0 | 1;
      readonly replacementReserve: bigint;
    })
  | (RootSelection & { readonly kind: "set-reserve"; readonly securityReserve: bigint })
  | {
      readonly kind: "cleanup-grant";
      readonly grantOwner: Uint8Array;
      readonly grantId: Uint8Array;
      readonly authority:
        | { readonly mode: 0; readonly signer: RawSigner<1> }
        | (RootSelection & { readonly mode: 1 });
    };
export interface LifecycleOptions {
  readonly owner: Uint8Array;
  readonly operation: LifecycleOperation;
  readonly gasLimit: bigint;
  readonly maxFeePerGas: bigint;
  readonly maxPriorityFeePerGas: bigint;
  readonly reservationId: string;
  /** Explicit canonical approval required before reserving/signing. */
  readonly approve: ReviewApproval;
  readonly signal?: AbortSignal;
  /** Whole flow including approval, reads, signing, reconciliation and post-read. */
  readonly timeoutMs?: number;
  readonly reconciliation?: Omit<ReconcileOptions, "signal">;
}
export type LifecycleFlow = Awaited<ReturnType<NonceCoordinator["execute"]>>;
export type LifecycleResult = {
  readonly flow: LifecycleFlow;
  readonly review: SigningReview;
  readonly verification: "node-observation";
} & (
  | {
      readonly postcondition: "reported-state";
      readonly account: AccountAuthorizationSnapshot;
      readonly grant?: SessionGrantObservation;
      readonly createdGrantId?: Uint8Array;
    }
  | { readonly postcondition: "unknown" | "included-failure" | "not-finalized" }
);
export function sessionCredentialFromGrant(
  grant: SessionGrantObservation,
): SessionSigningCredential {
  return {
    grantId: new Uint8Array(grant.grantId),
    authEpoch: grant.authEpoch,
    policyHash: new Uint8Array(grant.policyHash),
    nonce: grant.sessionNonce,
    keyScheme: grant.keyScheme,
    publicKey: new Uint8Array(grant.publicKey),
  };
}
const zero = (n: number) => new Uint8Array(n),
  same = (a: Uint8Array, b: Uint8Array) => compareBytes(a, b) === 0;
function insist(ok: unknown, code: LifecycleErrorCode = "STATE_DENIED"): asserts ok {
  if (!ok) throw new LifecycleError(code);
}
function signerBytes(s: RawSigner): string {
  objectFields(s, ["keyScheme", "publicKey", "sign"]);
  validateSessionPublicKey(s.keyScheme, s.publicKey);
  requireCondition(typeof s.sign === "function", "Missing signer");
  return `${s.keyScheme}:${bytesToHex(s.publicKey)}`;
}
function signers(op: LifecycleOperation): readonly RawSigner[] {
  return op.kind === "activate" || op.kind === "transfer"
    ? [op.signer]
    : op.kind === "cleanup-grant"
      ? op.authority.mode === 0
        ? [op.authority.signer]
        : op.authority.signers
      : op.signers;
}
function action(op: LifecycleOperation): {
  actionType: TxIntent["actionType"];
  data: Uint8Array;
  destination: Uint8Array;
  value: bigint;
} {
  const common = { destination: zero(20), value: 0n };
  switch (op.kind) {
    case "activate":
      objectFields(op, ["kind", "config", "securityReserve", "signer"]);
      return {
        ...common,
        actionType: Action.ActivateAuthorization,
        data: activateAuthorizationCodec.encode({
          version: 1,
          config: op.config,
          securityReserve: op.securityReserve,
        }),
      };
    case "create-grant":
      objectFields(op, ["kind", "grant", "signers"]);
      return {
        ...common,
        actionType: Action.CreateGrant,
        data: createGrantCodec.encode({ version: 1, grant: op.grant }),
      };
    case "revoke-grant":
      objectFields(op, ["kind", "grantId", "signers"]);
      return {
        ...common,
        actionType: Action.RevokeGrant,
        data: revokeGrantCodec.encode({ version: 1, grantId: op.grantId }),
      };
    case "replace-grant":
      objectFields(op, ["kind", "oldGrantId", "newGrant", "signers"]);
      return {
        ...common,
        actionType: Action.ReplaceGrant,
        data: replaceGrantCodec.encode({
          version: 1,
          oldGrantId: op.oldGrantId,
          newGrant: op.newGrant,
        }),
      };
    case "revoke-all":
      objectFields(op, ["kind", "signers"]);
      return { ...common, actionType: Action.RevokeAllGrants, data: zero(0) };
    case "rotate-root":
      objectFields(op, [
        "kind",
        "config",
        "reserveMode",
        "replacementReserve",
        "signers",
      ]);
      return {
        ...common,
        actionType: Action.RotateRoot,
        data: rotateRootCodec.encode({
          version: 1,
          config: op.config,
          reserveMode: op.reserveMode,
          replacementReserve: op.replacementReserve,
        }),
      };
    case "set-reserve":
      objectFields(op, ["kind", "securityReserve", "signers"]);
      return {
        ...common,
        actionType: Action.SetSecurityReserve,
        data: setSecurityReserveCodec.encode({
          version: 1,
          securityReserve: op.securityReserve,
        }),
      };
    case "cleanup-grant":
      objectFields(op, ["kind", "grantOwner", "grantId", "authority"]);
      objectFields(
        op.authority,
        op.authority.mode === 0 ? ["mode", "signer"] : ["mode", "signers"],
      );
      insist(op.authority.mode === 0 || op.authority.mode === 1, "INVALID_ARGUMENT");
      return {
        ...common,
        actionType: Action.CleanupGrant,
        data: cleanupGrantCodec.encode({
          version: 1,
          owner: op.grantOwner,
          grantId: op.grantId,
        }),
      };
    case "transfer":
      objectFields(op, [
        "kind",
        "credential",
        "signer",
        "destination",
        "value",
        "recipientProof",
      ]);
      objectFields(op.credential, [
        "grantId",
        "authEpoch",
        "policyHash",
        "nonce",
        "keyScheme",
        "publicKey",
      ]);
      return {
        actionType: Action.Transfer,
        data: zero(0),
        destination: fixedBytes(op.destination, 20),
        value: checkedUint(op.value, 256),
      };
    default:
      throw new LifecycleError("INVALID_ARGUMENT");
  }
}
function mode(op: LifecycleOperation): 0 | 1 | 2 {
  return op.kind === "activate"
    ? 0
    : op.kind === "transfer"
      ? 2
      : op.kind === "cleanup-grant"
        ? op.authority.mode
        : 1;
}
function additional(op: LifecycleOperation): string {
  if (op.kind !== "transfer") return "";
  const c = op.credential;
  validateSessionPublicKey(c.keyScheme, c.publicKey);
  return [
    bytesToHex(fixedBytes(c.grantId, 32)),
    checkedUint(c.authEpoch, 64),
    bytesToHex(fixedBytes(c.policyHash, 32)),
    checkedUint(c.nonce, 64),
    c.keyScheme,
    bytesToHex(c.publicKey),
    op.recipientProof === undefined
      ? ""
      : bytesToHex(recipientProofCodec.encode(op.recipientProof)),
  ].join(":");
}
type State = { account: AccountAuthorizationSnapshot; target?: FundedGrantSnapshot };
function stateParts(s: State): Uint8Array[] {
  return [
    s.account.root.authorizationMode === 0
      ? Uint8Array.of(0)
      : s.account.root.authority.canonical,
    encodeUint64(s.account.accountNonce),
    new TextEncoder().encode(s.account.balance.toString()),
    ...(s.target
      ? [
          s.target.grant.canonical,
          s.target.root.authorizationMode === 0
            ? Uint8Array.of(0)
            : s.target.root.authority.canonical,
        ]
      : []),
  ];
}
function stateHash(s: State): Uint8Array {
  return domainHash("RESILIENCE_SDK_LIFECYCLE_AUTHORITY_V1", ...stateParts(s));
}
function fundedAccount(s: FundedGrantSnapshot): AccountAuthorizationSnapshot {
  return { identity: s.identity, root: s.root, balance: s.balance, accountNonce: 0n };
}
function checkIdentity(c: ChainContext, s: State): void {
  for (const o of [s.account, ...(s.target ? [s.target] : [])])
    insist(
      o.identity.chainId === c.chainId && same(o.identity.genesisHash, c.genesisHash),
      "STALE_AUTHORITY",
    );
}
function grantSpec(op: LifecycleOperation): GrantSpec | undefined {
  return op.kind === "create-grant"
    ? op.grant
    : op.kind === "replace-grant"
      ? op.newGrant
      : undefined;
}
function checkGrantSpec(spec: GrantSpec, s: State, intent: TxIntent): void {
  const r = s.account.root;
  insist(r.authorizationMode === 1);
  const a = r.authority,
    h = checkedUint(s.account.identity.state.height + 1n, 64);
  insist(
    a.securityReserve >= MINIMUM_SECURITY_RESERVE &&
      a.nextGrantSequence < (1n << 64n) - 1n,
  );
  insist(
    spec.validAfterHeight > h &&
      spec.validUntilHeight - h <= MAX_SESSION_LIFETIME_BLOCKS,
  );
  insist(spec.storageDeposit === requiredGrantStorageDeposit(spec));
  insist(
    spec.keyScheme !== 1 ||
      !a.rootConfig.keys.some((k) => same(k.publicKey, spec.publicKey)),
  );
  const refund = s.target?.grant.storageDeposit ?? 0n;
  const debit = checkedUint(
    intent.gasLimit * intent.maxFeePerGas + spec.storageDeposit,
    256,
  );
  insist(
    checkedUint(s.account.balance + refund, 256) >=
      checkedUint(debit + a.securityReserve, 256),
  );
}
function preflight(
  context: ChainContext,
  op: LifecycleOperation,
  intent: TxIntent,
  s: State,
): void {
  checkIdentity(context, s);
  const a = s.account.root;
  const m = mode(op),
    fee = checkedUint(intent.gasLimit * intent.maxFeePerGas, 256);
  insist(s.account.balance >= fee);
  if (m === 0) {
    insist(a.authorizationMode === 0 && s.account.accountNonce < (1n << 64n) - 1n);
    insist(
      signers(op)[0]!.keyScheme === 1 &&
        same(keccak256(signers(op)[0]!.publicKey).subarray(12), intent.sender),
    );
  } else {
    insist(a.authorizationMode === 1);
    if (m === 1)
      insist(a.authority.rootNonce < (1n << 64n) - 1n || op.kind === "rotate-root");
  }
  if (op.kind === "activate") insist(op.securityReserve <= s.account.balance - fee);
  if (op.kind === "create-grant" || op.kind === "replace-grant") {
    checkGrantSpec(grantSpec(op)!, s, intent);
    insist(a.authorizationMode === 1);
    if (op.kind === "create-grant") insist(a.authority.activeGrantCount < 64);
    else
      insist(
        s.target !== undefined && s.target.grant.authEpoch === a.authority.authEpoch,
      );
  }
  if (op.kind === "revoke-grant")
    insist(
      a.authorizationMode === 1 && s.target?.grant.authEpoch === a.authority.authEpoch,
    );
  if (op.kind === "set-reserve")
    insist(
      a.authorizationMode === 1 &&
        op.securityReserve <= s.account.balance - fee &&
        (a.authority.activeGrantCount === 0 ||
          op.securityReserve >= MINIMUM_SECURITY_RESERVE),
    );
  if (op.kind === "rotate-root" || op.kind === "revoke-all") {
    insist(a.authorizationMode === 1 && a.authority.authEpoch < (1n << 64n) - 1n);
    if (op.kind === "rotate-root")
      insist(
        (op.reserveMode === 0 ? a.authority.securityReserve : op.replacementReserve) <=
          s.account.balance - fee,
      );
  }
  if (op.kind === "cleanup-grant") {
    insist(s.target !== undefined && s.target.root.authorizationMode === 1);
    insist(
      s.target.grant.authEpoch < s.target.root.authority.authEpoch ||
        s.target.identity.state.height >= s.target.grant.validUntilHeight,
    );
  }
  if (op.kind === "transfer") {
    insist(s.target !== undefined);
    const g = s.target.grant,
      c = op.credential;
    insist(
      same(c.grantId, g.grantId) &&
        c.authEpoch === g.authEpoch &&
        same(c.policyHash, g.policyHash) &&
        c.nonce === g.sessionNonce &&
        c.keyScheme === g.keyScheme &&
        same(c.publicKey, g.publicKey) &&
        op.signer.keyScheme === g.keyScheme &&
        same(op.signer.publicKey, g.publicKey),
    );
    checkSessionTransfer(context, intent, s.target, op.recipientProof);
  }
}
function authority(
  context: ChainContext,
  op: LifecycleOperation,
  intent: TxIntent,
  s: State,
): NonceAuthoritySnapshot {
  const m = mode(op),
    r = s.account.root,
    g = s.target?.grant;
  insist(m === 0 || r.authorizationMode === 1);
  const root = r.authorizationMode === 1 ? r.authority : null;
  return {
    context,
    owner: intent.sender,
    mode: m,
    keyScheme: m === 2 ? g!.keyScheme : 1,
    credentialId: m === 0 ? zero(32) : m === 1 ? root!.rootConfigHash : g!.grantId,
    authEpoch: m === 0 ? 0n : m === 1 ? root!.authEpoch : g!.authEpoch,
    policyHash: m === 2 ? g!.policyHash : zero(32),
    nonce:
      m === 0 ? s.account.accountNonce : m === 1 ? root!.rootNonce : g!.sessionNonce,
    authorityHash: stateHash(s),
    height: s.account.identity.state.height,
    blockHash: s.account.identity.state.blockHash,
    stateRoot: s.account.identity.state.stateRoot,
  };
}
function review(
  context: ChainContext,
  op: LifecycleOperation,
  intent: TxIntent,
  s: State,
): SigningReview {
  const snap = authority(context, op, intent, s),
    selected = signers(op);
  let witness: Uint8Array,
    digest: Uint8Array,
    config: RootConfig | undefined,
    ids: Uint8Array[] | undefined;
  if (snap.mode === 0) {
    witness = zero(96);
    witness.set(selected[0]!.publicKey);
    digest = directDigest(context, intent, snap.nonce);
  } else if (snap.mode === 1) {
    insist(s.account.root.authorizationMode === 1);
    config = s.account.root.authority.rootConfig;
    insist(
      selected.length === config.threshold &&
        selected.length > 0 &&
        selected.length <= 8,
    );
    ids = selected
      .map((k) => {
        insist(k.keyScheme === 1);
        const id = rootKeyId({ keyScheme: 1, publicKey: k.publicKey });
        insist(config!.keys.some((r) => same(rootKeyId(r), id)));
        return id;
      })
      .sort(compareBytes);
    for (let i = 1; i < ids.length; i++) insist(!same(ids[i - 1]!, ids[i]!));
    witness = encodeRootWitness(
      ids.map((id) => ({ rootKeyId: id, signature: zero(64) })),
      config.threshold,
    );
    digest = rootDigest(context, intent, snap.credentialId, snap.authEpoch, snap.nonce);
  } else {
    insist(op.kind === "transfer");
    witness = sessionWitnessCodec.encode({
      signature: zero(64),
      ...(op.recipientProof ? { recipientProof: op.recipientProof } : {}),
    });
    digest = sessionDigest(context, intent, op.credential);
  }
  const envelope: AuthEnvelope = {
    version: 1,
    mode: snap.mode,
    keyScheme: snap.keyScheme,
    credentialId: snap.credentialId,
    authEpoch: snap.authEpoch,
    policyHash: snap.policyHash,
    nonce: snap.nonce,
    sponsorNonce: 0n,
    witness,
    sponsorWitness: zero(0),
  };
  return buildSigningReview(
    context,
    { intent, envelope },
    digest,
    snap.mode === 1 ? undefined : selected[0]!.publicKey,
    config,
    ids,
  );
}
/** Explicit operations, external custody, one coordinated send and bounded node observations. */
export class SessionLifecycle {
  readonly #context: ChainContext;
  readonly #client: ChainRpcClient;
  readonly #coordinator: NonceCoordinator;
  constructor(options: {
    readonly context: ChainContext;
    readonly client: ChainRpcClient;
    readonly coordinator: NonceCoordinator;
  }) {
    objectFields(options, ["context", "client", "coordinator"]);
    objectFields(options.context, ["chainId", "genesisHash"]);
    chainDomain(options.context);
    insist(
      options.client instanceof ChainRpcClient &&
        options.coordinator instanceof NonceCoordinator,
      "INVALID_ARGUMENT",
    );
    this.#context = {
      chainId: options.context.chainId,
      genesisHash: new Uint8Array(options.context.genesisHash),
    };
    this.#client = options.client;
    this.#coordinator = options.coordinator;
  }
  async #read(
    owner: Uint8Array,
    op: LifecycleOperation,
    signal: AbortSignal,
  ): Promise<State> {
    const client = this.#client,
      opts = { signal };
    if (
      op.kind === "transfer" ||
      op.kind === "revoke-grant" ||
      op.kind === "replace-grant"
    ) {
      const id =
        op.kind === "transfer"
          ? op.credential.grantId
          : op.kind === "replace-grant"
            ? op.oldGrantId
            : op.grantId;
      const target = await client.getFundedGrantSnapshot(owner, id, opts);
      return { account: fundedAccount(target), target };
    }
    if (op.kind === "cleanup-grant") {
      for (let attempt = 0; attempt < 4; attempt++) {
        const account = await client.getAccountAuthorizationSnapshot(owner, opts),
          target = await client.getFundedGrantSnapshot(op.grantOwner, op.grantId, opts);
        if (
          same(account.identity.state.blockHash, target.identity.state.blockHash) &&
          same(account.identity.state.stateRoot, target.identity.state.stateRoot) &&
          account.identity.state.height === target.identity.state.height
        )
          return { account, target };
      }
      throw new LifecycleError("STALE_AUTHORITY");
    }
    return { account: await client.getAccountAuthorizationSnapshot(owner, opts) };
  }
  async execute(options: LifecycleOptions): Promise<LifecycleResult> {
    let timeout: number,
      intent: TxIntent,
      serialized: string,
      callbacks: readonly unknown[],
      methods: readonly unknown[],
      op: LifecycleOperation;
    const client = this.#client,
      context = this.#context;
    const fingerprint = () => {
      objectFields(options, [
        "owner",
        "operation",
        "gasLimit",
        "maxFeePerGas",
        "maxPriorityFeePerGas",
        "reservationId",
        "approve",
        "signal",
        "timeoutMs",
        "reconciliation",
      ]);
      insist(
        typeof options.approve === "function" &&
          typeof options.reservationId === "string" &&
          /^[A-Za-z0-9._:-]{16,80}$/.test(options.reservationId),
        "INVALID_ARGUMENT",
      );
      const a = action(options.operation);
      const i: TxIntent = {
        version: 2,
        chainId: context.chainId,
        sender: fixedBytes(options.owner, 20),
        flags: 0,
        sponsor: zero(20),
        ...a,
        gasLimit: options.gasLimit,
        maxFeePerGas: options.maxFeePerGas,
        maxPriorityFeePerGas: options.maxPriorityFeePerGas,
      };
      if (options.reconciliation) {
        objectFields(options.reconciliation, [
          "timeoutMs",
          "maxPolls",
          "pollIntervalMs",
        ]);
        for (const [k, max] of [
          ["timeoutMs", 300000],
          ["maxPolls", 1000],
          ["pollIntervalMs", 60000],
        ] as const) {
          const v = options.reconciliation[k];
          insist(
            v === undefined || (Number.isSafeInteger(v) && v >= 1 && v <= max),
            "INVALID_ARGUMENT",
          );
        }
      }
      return [
        bytesToHex(txIntentCodec.encode(i)),
        options.operation.kind,
        mode(options.operation),
        additional(options.operation),
        ...signers(options.operation).map(signerBytes),
        options.reservationId,
        options.timeoutMs ?? 30000,
        JSON.stringify(options.reconciliation ?? {}),
      ].join("|");
    };
    const functions = () => [
      options.approve,
      ...signers(options.operation).map((s) => s.sign),
    ];
    const clientMethods = () => [
      client.getAccountAuthorizationSnapshot,
      client.getFundedGrantSnapshot,
      client.getSessionGrant,
      client.submitTransaction,
      client.reconcileTransaction,
    ];
    const external = options.signal;
    try {
      timeout = options.timeoutMs ?? 30000;
      checkedNumber(timeout, 300000);
      insist(timeout > 0, "INVALID_ARGUMENT");
      serialized = fingerprint();
      callbacks = functions();
      methods = clientMethods();
      op = options.operation;
      intent = txIntentCodec.decode(hexToBytes(serialized.split("|")[0]!));
    } catch {
      throw new LifecycleError("INVALID_ARGUMENT");
    }
    const unchanged = () => {
      try {
        insist(
          fingerprint() === serialized &&
            functions().every((f, i) => f === callbacks[i]) &&
            functions().length === callbacks.length &&
            options.signal === external &&
            clientMethods().every((f, i) => f === methods[i]),
          "MUTATED_INPUT",
        );
      } catch {
        throw new LifecycleError("MUTATED_INPUT");
      }
    };
    const deadline = new Deadline(systemClock, timeout, external);
    const step = async <T>(promise: Promise<T>): Promise<T> => {
      try {
        const value = await deadline.race(promise);
        deadline.check();
        unchanged();
        return value;
      } catch (e) {
        unchanged();
        throw e;
      }
    };
    let authorityError: LifecycleError | undefined;
    try {
      deadline.check();
      const initial = await step(
        this.#read(intent.sender, op, deadline.controller.signal),
      );
      preflight(context, op, intent, initial);
      const initialHash = bytesToHex(stateHash(initial));
      const signingReview = review(context, op, intent, initial);
      let approved: boolean;
      try {
        approved = await step(
          Promise.resolve(
            options.approve(
              Object.freeze({
                review: signingReview,
                signal: deadline.controller.signal,
              }),
            ),
          ),
        );
      } catch (e) {
        if (e instanceof LifecycleError || e instanceof RpcClientError) throw e;
        throw new LifecycleError("REVIEW_FAILED");
      }
      insist(approved === true, "REVIEW_REJECTED");
      // Review happens before reserving, so rejecting a review cannot strand a nonce.
      const readAuthority = async (signal: AbortSignal) => {
        try {
          const current = await this.#read(intent.sender, op, signal);
          unchanged();
          preflight(context, op, intent, current);
          insist(bytesToHex(stateHash(current)) === initialHash, "STALE_AUTHORITY");
          return authority(context, op, intent, current);
        } catch (error) {
          if (error instanceof LifecycleError) authorityError = error;
          throw error;
        }
      };
      const flow = await step(
        this.#coordinator.execute({
          context,
          intent,
          reservationId: options.reservationId,
          readAuthority,
          client,
          signal: deadline.controller.signal,
          timeoutMs: timeout,
          reconciliation: options.reconciliation ?? {},
          sign: async (request) => {
            unchanged();
            const snapshot = request.snapshot;
            const common = {
              context,
              intent,
              signal: request.signal,
              timeoutMs: timeout,
              approve: ({ review: r }: { review: SigningReview }) => {
                unchanged();
                insist(r.reviewHash === signingReview.reviewHash, "STALE_AUTHORITY");
                return true;
              },
            };
            const selected = signers(op);
            if (snapshot.mode === 0)
              return signDirectTransaction({
                ...common,
                nonce: BigInt(snapshot.nonce),
                signer: selected[0] as RawSigner<1>,
              });
            if (snapshot.mode === 1) {
              insist(initial.account.root.authorizationMode === 1);
              return signRootTransaction({
                ...common,
                config: initial.account.root.authority.rootConfig,
                authEpoch: BigInt(snapshot.authEpoch),
                nonce: BigInt(snapshot.nonce),
                signers: selected as readonly RawSigner<1>[],
              });
            }
            insist(op.kind === "transfer");
            return signSessionTransaction({
              ...common,
              credential: op.credential,
              signer: op.signer,
              ...(op.recipientProof ? { recipientProof: op.recipientProof } : {}),
            });
          },
        }),
      );
      const base = {
        flow,
        review: signingReview,
        verification: "node-observation" as const,
      };
      if (flow.reconciliation.status === "reported-finalized-failure")
        return { ...base, postcondition: "included-failure" };
      if (flow.reconciliation.status === "unknown")
        return { ...base, postcondition: "not-finalized" };
      // Post-read failure never discards a finalized receipt or treats an uncertain send as reusable.
      try {
        const account = await step(
          client.getAccountAuthorizationSnapshot(intent.sender, {
            signal: deadline.controller.signal,
          }),
        );
        insist(
          account.identity.state.height >= flow.reconciliation.receipt.blockNumber,
        );
        checkIdentity(context, { account });
        const before = initial.account.root,
          after = account.root;
        let grant: SessionGrantObservation | undefined,
          createdGrantId: Uint8Array | undefined;
        if (op.kind === "activate")
          insist(
            after.authorizationMode === 1 &&
              after.authority.authEpoch === 1n &&
              after.authority.rootNonce === 0n &&
              after.authority.nextGrantSequence === 0n &&
              after.authority.activeGrantCount === 0 &&
              after.authority.securityReserve === op.securityReserve &&
              same(after.authority.rootConfigHash, rootConfigHash(op.config)) &&
              account.accountNonce === initial.account.accountNonce + 1n,
          );
        else if (mode(op) === 1) {
          insist(before.authorizationMode === 1 && after.authorizationMode === 1);
          const b = before.authority,
            a = after.authority;
          const epochAdvance = op.kind === "rotate-root" || op.kind === "revoke-all";
          insist(
            a.authEpoch === b.authEpoch + (epochAdvance ? 1n : 0n) &&
              a.rootNonce === (op.kind === "rotate-root" ? 0n : b.rootNonce + 1n),
          );
          insist(
            same(
              a.rootConfigHash,
              op.kind === "rotate-root" ? rootConfigHash(op.config) : b.rootConfigHash,
            ),
          );
          insist(
            a.nextGrantSequence === b.nextGrantSequence + (grantSpec(op) ? 1n : 0n),
          );
          const count = epochAdvance
            ? 0
            : b.activeGrantCount +
              (op.kind === "create-grant"
                ? 1
                : op.kind === "revoke-grant"
                  ? -1
                  : op.kind === "cleanup-grant" &&
                      same(op.grantOwner, intent.sender) &&
                      initial.target?.grant.authEpoch === b.authEpoch
                    ? -1
                    : 0);
          insist(a.activeGrantCount === count);
          const reserve =
            op.kind === "set-reserve"
              ? op.securityReserve
              : op.kind === "rotate-root" && op.reserveMode === 1
                ? op.replacementReserve
                : b.securityReserve;
          insist(a.securityReserve === reserve);
          const spec = grantSpec(op);
          if (spec) {
            createdGrantId = grantId(
              context,
              intent.sender,
              b.authEpoch,
              b.nextGrantSequence,
              spec.keyScheme,
              spec.publicKey,
            );
            grant = await step(
              client.getSessionGrant(intent.sender, createdGrantId, {
                signal: deadline.controller.signal,
              }),
            );
            insist(
              grant.state.height >= flow.reconciliation.receipt.blockNumber &&
                grant.createdHeight === flow.reconciliation.receipt.blockNumber &&
                grant.validAfterHeight === spec.validAfterHeight &&
                grant.validUntilHeight === spec.validUntilHeight &&
                same(grant.policyHash, policyHash(spec.policy)) &&
                grant.keyScheme === spec.keyScheme &&
                same(grant.publicKey, spec.publicKey) &&
                grant.storageDeposit === spec.storageDeposit &&
                grant.sessionNonce === 0n &&
                grant.usage.attempts === 0n,
            );
          }
        } else if (op.kind === "transfer") {
          grant = await step(
            client.getSessionGrant(intent.sender, op.credential.grantId, {
              signal: deadline.controller.signal,
            }),
          );
          insist(
            after.authorizationMode === 1 &&
              after.authority.authEpoch === op.credential.authEpoch &&
              grant.state.height >= flow.reconciliation.receipt.blockNumber &&
              grant.sessionNonce >= op.credential.nonce + 1n &&
              same(grant.policyHash, op.credential.policyHash),
          );
        } else insist(account.accountNonce === initial.account.accountNonce + 1n);
        return {
          ...base,
          postcondition: "reported-state",
          account,
          ...(grant ? { grant } : {}),
          ...(createdGrantId ? { createdGrantId } : {}),
        };
      } catch {
        unchanged();
        return { ...base, postcondition: "unknown" };
      }
    } catch (e) {
      unchanged();
      if (e instanceof LifecycleError) throw e;
      if (e instanceof RpcClientError && ["ABORTED", "TIMEOUT"].includes(e.code))
        throw new LifecycleError(e.code as "ABORTED" | "TIMEOUT");
      if (e instanceof CoordinatorError) {
        if (e.code === "FLOW_FAILED" && authorityError) throw authorityError;
        if (["STALE_AUTHORITY", "MUTATED_INPUT", "ABORTED", "TIMEOUT"].includes(e.code))
          throw new LifecycleError(e.code as LifecycleErrorCode);
        throw new LifecycleError("FLOW_FAILED");
      }
      throw new LifecycleError("READ_FAILED");
    } finally {
      deadline.dispose();
    }
  }
}
