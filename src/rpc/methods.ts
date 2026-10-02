import { checkedUint, compareBytes } from "../core/bytes.js";
import { policyCodec, transactionCodec, transactionId } from "../session/index.js";
import { AUTHORIZATION_CAPABILITY, RpcContractError } from "./contracts.js";
import type {
  AuthorizationFinalityStatus,
  AuthorizationGasEstimate,
  AuthorizationSnapshot,
  AuthorizedSimulation,
  ChainRpcOptions,
  DecodedPolicy,
  ExpectedChainIdentity,
  FeeHistory,
  FeeHistoryRequest,
  FeeSuggestions,
  FinalizedState,
  PolicyPreview,
  RootAuthorityObservation,
  SessionGrantObservation,
  SessionNonceObservation,
  SessionUsageObservation,
} from "./contracts.js";
import { Deadline, systemClock } from "./deadline.js";
import { HttpRpcClient } from "./http.js";
import type { RpcCall, RpcClock, RpcRequestOptions } from "./types.js";
import {
  amount,
  array,
  boolean,
  bytesToHex,
  decodedPolicy,
  fixedInput,
  grantObservation,
  identity,
  inputBytes,
  inputGuard,
  nonceObservation,
  quantity,
  record,
  requireResult,
  resultGuard,
  rootObservation,
  sameBytes,
  sameState,
  sameUsage,
  state,
  toQuantity,
  usageObservation,
  wireBytes,
} from "./validate.js";

const identityCall: RpcCall = { method: "rsc_getAuthorizationFinalityStatus" };
type ReadResult = {
  identity: AuthorizationFinalityStatus;
  results: readonly unknown[];
};

function feeHistoryShape(value: unknown, percentiles: number): Record<string, unknown> {
  const r = record(value, ["oldestBlock", "baseFeePerGas", "gasUsedRatio", "reward"]);
  quantity(r.oldestBlock);
  const ratios = array(r.gasUsedRatio, 1, 64);
  array(r.baseFeePerGas, ratios.length + 1, ratios.length + 1).forEach((q) =>
    quantity(q, 256),
  );
  ratios.forEach((ratio) =>
    requireResult(
      typeof ratio === "number" && Number.isFinite(ratio) && ratio >= 0 && ratio <= 1,
    ),
  );
  array(r.reward, ratios.length, ratios.length).forEach((row) =>
    array(row, percentiles, percentiles).forEach((q) => quantity(q, 256)),
  );
  return r;
}

/** Validates pinned method contracts and identity. Node observations are not proofs. */
export class ChainRpcClient {
  readonly #http: HttpRpcClient;
  readonly #expected: ExpectedChainIdentity;
  readonly #refreshes: number;
  readonly #clock: RpcClock;
  readonly #timeoutMs: number;

  constructor(options: ChainRpcOptions) {
    const config = inputGuard(() => {
      const expected = options.expected;
      checkedUint(expected.chainId, 64);
      requireResult(expected.authorizationCapability === AUTHORIZATION_CAPABILITY);
      const refreshes = options.maxContextRefreshes ?? 1;
      requireResult(
        Number.isSafeInteger(refreshes) && refreshes >= 0 && refreshes <= 3,
      );
      // The largest logical read is identity + four authorization reads + identity.
      requireResult((options.maxBatchSize ?? 32) >= 6);
      return {
        expected: {
          chainId: expected.chainId,
          genesisHash: fixedInput(expected.genesisHash, 32),
          authorizationCapability: AUTHORIZATION_CAPABILITY,
        },
        refreshes,
      };
    });
    this.#http = new HttpRpcClient(options);
    this.#expected = config.expected;
    this.#refreshes = config.refreshes;
    this.#clock = options.clock ?? systemClock;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
  }

  async #read(
    calls: readonly RpcCall[],
    contextual: boolean,
    options: RpcRequestOptions,
    refresh = true,
    validateInconsistent?: (read: ReadResult) => void,
  ): Promise<ReadResult> {
    const deadline = new Deadline(this.#clock, this.#timeoutMs, options.signal);
    try {
      for (let pass = 0; pass <= (refresh ? this.#refreshes : 0); pass++) {
        deadline.check();
        const outcomes = await deadline.race(
          this.#http.batch([identityCall, ...calls, identityCall], {
            signal: deadline.controller.signal,
          }),
        );
        deadline.check();
        const results = outcomes.map((outcome) => {
          if (!outcome.ok) throw outcome.error;
          return outcome.result;
        });
        const first = resultGuard(() => identity(results[0], this.#expected));
        const last = resultGuard(() => identity(results.at(-1), this.#expected));
        const values = results.slice(1, -1);
        const contexts = contextual
          ? values.map((value) =>
              resultGuard(() => {
                requireResult(
                  value !== null &&
                    typeof value === "object" &&
                    !Array.isArray(value) &&
                    Object.hasOwn(value, "state"),
                );
                return state((value as Record<string, unknown>).state);
              }),
            )
          : [];
        if (
          sameState(first.state, last.state) &&
          contexts.every((context) => sameState(first.state, context))
        )
          return { identity: first, results: values };
        // A moving head must not hide malformed method data behind a refresh.
        if (validateInconsistent)
          resultGuard(() => validateInconsistent({ identity: first, results: values }));
      }
      throw new RpcContractError("STATE_CONTEXT_MISMATCH");
    } catch (error) {
      if (deadline.controller.signal.aborted) {
        // Overall observation errors carry no misleading per-attempt transport count.
        throw new RpcContractError(
          options.signal?.aborted ? "OBSERVATION_ABORTED" : "OBSERVATION_TIMEOUT",
        );
      }
      throw error;
    } finally {
      deadline.dispose();
    }
  }

  async getAuthorizationFinalityStatus(
    options: RpcRequestOptions = {},
  ): Promise<AuthorizationFinalityStatus> {
    return (await this.#read([], false, options)).identity;
  }
  async getRootAuthority(
    owner: Uint8Array,
    options: RpcRequestOptions = {},
  ): Promise<RootAuthorityObservation> {
    const address = inputGuard(() => fixedInput(owner, 20));
    const read = await this.#read(
      [{ method: "rsc_getRootAuthority", params: [bytesToHex(address)] }],
      true,
      options,
      true,
      (read) => {
        rootObservation(read.results[0], address);
      },
    );
    return resultGuard(() => rootObservation(read.results[0], address));
  }
  async getSessionGrant(
    owner: Uint8Array,
    grantId: Uint8Array,
    options: RpcRequestOptions = {},
  ): Promise<SessionGrantObservation> {
    const [address, id] = this.#grantInputs(owner, grantId);
    const read = await this.#read(
      [
        {
          method: "rsc_getSessionGrant",
          params: [bytesToHex(address), bytesToHex(id)],
        },
      ],
      true,
      options,
      true,
      (read) => {
        grantObservation(read.results[0], address, id, this.#expected);
      },
    );
    return resultGuard(() =>
      grantObservation(read.results[0], address, id, this.#expected),
    );
  }
  async getSessionNonce(
    owner: Uint8Array,
    grantId: Uint8Array,
    options: RpcRequestOptions = {},
  ): Promise<SessionNonceObservation> {
    const [address, id] = this.#grantInputs(owner, grantId);
    const read = await this.#read(
      [
        {
          method: "rsc_getSessionNonce",
          params: [bytesToHex(address), bytesToHex(id)],
        },
      ],
      true,
      options,
      true,
      (read) => {
        nonceObservation(read.results[0], address, id);
      },
    );
    return resultGuard(() => nonceObservation(read.results[0], address, id));
  }
  async getSessionUsage(
    owner: Uint8Array,
    grantId: Uint8Array,
    options: RpcRequestOptions = {},
  ): Promise<SessionUsageObservation> {
    const [address, id] = this.#grantInputs(owner, grantId);
    const read = await this.#read(
      [
        {
          method: "rsc_getSessionUsage",
          params: [bytesToHex(address), bytesToHex(id)],
        },
      ],
      true,
      options,
      true,
      (read) => {
        usageObservation(read.results[0], address, id);
      },
    );
    return resultGuard(() => usageObservation(read.results[0], address, id));
  }
  #grantInputs(
    owner: Uint8Array,
    grantId: Uint8Array,
  ): readonly [Uint8Array, Uint8Array] {
    return inputGuard(
      () => [fixedInput(owner, 20, true), fixedInput(grantId, 32, true)] as const,
    );
  }
  async getAuthorizationSnapshot(
    owner: Uint8Array,
    grantId: Uint8Array,
    options: RpcRequestOptions = {},
  ): Promise<AuthorizationSnapshot> {
    const [address, id] = this.#grantInputs(owner, grantId),
      params = [bytesToHex(address), bytesToHex(id)];
    const read = await this.#read(
      [
        { method: "rsc_getRootAuthority", params: [params[0]!] },
        { method: "rsc_getSessionGrant", params },
        { method: "rsc_getSessionNonce", params },
        { method: "rsc_getSessionUsage", params },
      ],
      true,
      options,
      true,
      (read) => {
        rootObservation(read.results[0], address);
        grantObservation(read.results[1], address, id, this.#expected);
        nonceObservation(read.results[2], address, id);
        usageObservation(read.results[3], address, id);
      },
    );
    return resultGuard(() => {
      const root = rootObservation(read.results[0], address),
        grant = grantObservation(read.results[1], address, id, this.#expected),
        nonce = nonceObservation(read.results[2], address, id),
        usage = usageObservation(read.results[3], address, id);
      requireResult(
        root.authorizationMode === 1 &&
          nonce.sessionNonce === grant.sessionNonce &&
          nonce.usableAtObservedBlock === grant.usableAtObservedBlock,
      );
      if (root.authority.authEpoch === grant.authEpoch)
        requireResult(root.authority.activeGrantCount > 0);
      requireResult(
        grant.authEpoch <= root.authority.authEpoch &&
          grant.generationSequence < root.authority.nextGrantSequence,
      );
      sameBytes(usage.policyHash, grant.policyHash);
      sameUsage(usage.usage, grant.usage);
      const usable =
        root.authority.authEpoch === grant.authEpoch &&
        grant.state.height >= grant.validAfterHeight &&
        grant.state.height < grant.validUntilHeight;
      requireResult(usable === grant.usableAtObservedBlock);
      return { identity: read.identity, root, grant, nonce, usage };
    });
  }
  async decodePolicy(
    canonical: Uint8Array,
    options: RpcRequestOptions = {},
  ): Promise<DecodedPolicy> {
    const bytes = inputGuard(() => {
      const bytes = inputBytes(canonical, 16_384);
      policyCodec.decode(bytes);
      return bytes;
    });
    const read = await this.#read(
      [{ method: "rsc_decodePolicy", params: [bytesToHex(bytes)] }],
      false,
      options,
      true,
      (read) => {
        decodedPolicy(read.results[0], bytes, false);
      },
    );
    return resultGuard(() => decodedPolicy(read.results[0], bytes, false));
  }
  async previewPolicy(
    canonical: Uint8Array,
    options: RpcRequestOptions = {},
  ): Promise<PolicyPreview> {
    const bytes = inputGuard(() => {
      const bytes = inputBytes(canonical, 16_384);
      policyCodec.decode(bytes);
      return bytes;
    });
    const read = await this.#read(
      [{ method: "rsc_previewPolicy", params: [bytesToHex(bytes)] }],
      false,
      options,
      true,
      (read) => {
        decodedPolicy(read.results[0], bytes, true);
      },
    );
    return resultGuard(
      () => decodedPolicy(read.results[0], bytes, true) as PolicyPreview,
    );
  }
  async getFeeSuggestions(options: RpcRequestOptions = {}): Promise<FeeSuggestions> {
    const read = await this.#read(
      [{ method: "rsc_gasPrice" }, { method: "rsc_maxPriorityFeePerGas" }],
      false,
      options,
      true,
      (read) => {
        quantity(read.results[0], 256);
        quantity(read.results[1], 256);
      },
    );
    return resultGuard(() => ({
      identity: read.identity,
      gasPrice: quantity(read.results[0], 256),
      maxPriorityFeePerGas: quantity(read.results[1], 256),
      advisory: true,
    }));
  }
  async getFeeHistory(
    request: FeeHistoryRequest,
    options: RpcRequestOptions = {},
  ): Promise<FeeHistory> {
    const args = inputGuard(() => {
      requireResult(
        Number.isSafeInteger(request.blockCount) &&
          request.blockCount >= 1 &&
          request.blockCount <= 64,
      );
      const newest = request.newestBlock;
      if (newest !== "latest") checkedUint(newest, 64);
      const percentiles = [...(request.rewardPercentiles ?? [])];
      requireResult(
        percentiles.length <= 64 &&
          percentiles.every(
            (p) => typeof p === "number" && Number.isFinite(p) && p >= 0 && p <= 100,
          ),
      );
      return { count: request.blockCount, newest, percentiles };
    });
    const read = await this.#read(
      [
        {
          method: "rsc_feeHistory",
          params: [
            toQuantity(BigInt(args.count)),
            args.newest === "latest" ? "latest" : toQuantity(args.newest),
            args.percentiles,
          ],
        },
      ],
      false,
      options,
      true,
      (read) => {
        feeHistoryShape(read.results[0], args.percentiles.length);
      },
    );
    return resultGuard(() => {
      const r = feeHistoryShape(read.results[0], args.percentiles.length);
      const newest =
        args.newest === "latest" || args.newest > read.identity.state.height
          ? read.identity.state.height
          : args.newest;
      const count = Number(
        newest + 1n < BigInt(args.count) ? newest + 1n : BigInt(args.count),
      );
      const oldestBlock = quantity(r.oldestBlock);
      requireResult(oldestBlock === newest + 1n - BigInt(count));
      const baseFeePerGas = array(r.baseFeePerGas, count + 1, count + 1).map((q) =>
        quantity(q, 256),
      );
      const gasUsedRatio = array(r.gasUsedRatio, count, count).map((ratio) => {
        requireResult(
          typeof ratio === "number" &&
            Number.isFinite(ratio) &&
            ratio >= 0 &&
            ratio <= 1,
        );
        return ratio;
      });
      const reward = array(r.reward, count, count).map((row) =>
        array(row, args.percentiles.length, args.percentiles.length).map((q) =>
          quantity(q, 256),
        ),
      );
      return {
        identity: read.identity,
        oldestBlock,
        baseFeePerGas,
        gasUsedRatio,
        reward,
        advisory: true,
      };
    });
  }
  #transactionInput(canonical: Uint8Array): {
    bytes: Uint8Array;
    id: Uint8Array;
    sponsor: Uint8Array;
    gasLimit: bigint;
    maxFeePerGas: bigint;
  } {
    return inputGuard(() => {
      const bytes = inputBytes(canonical, 67_011),
        transaction = transactionCodec.decode(bytes);
      return {
        bytes,
        id: transactionId(this.#expected, transaction.intent, transaction.envelope),
        sponsor: transaction.intent.sponsor,
        gasLimit: transaction.intent.gasLimit,
        maxFeePerGas: transaction.intent.maxFeePerGas,
      };
    });
  }
  async estimateAuthorizationGas(
    canonical: Uint8Array,
    options: RpcRequestOptions = {},
  ): Promise<AuthorizationGasEstimate> {
    const input = this.#transactionInput(canonical);
    const read = await this.#read(
      [{ method: "rsc_estimateAuthorizationGas", params: [bytesToHex(input.bytes)] }],
      true,
      options,
      false,
    );
    return resultGuard(() => {
      const r = record(read.results[0], [
          "state",
          "authorizationGas",
          "candidateHeight",
          "warning",
        ]),
        observed = state(r.state),
        authorizationGas = quantity(r.authorizationGas),
        candidateHeight = this.#candidate(r.candidateHeight, observed);
      requireResult(
        r.warning ===
          "Estimate is state-dependent and can become stale before inclusion." &&
          authorizationGas > 0n &&
          authorizationGas <= input.gasLimit,
      );
      return {
        state: observed,
        authorizationGas,
        candidateHeight,
        warning: r.warning,
        advisory: true,
      };
    });
  }
  #candidate(value: unknown, observed: FinalizedState): bigint {
    const height = quantity(value);
    requireResult(height === observed.height + 1n);
    return height;
  }
  async simulateAuthorizedTransaction(
    canonical: Uint8Array,
    options: RpcRequestOptions = {},
  ): Promise<AuthorizedSimulation> {
    const input = this.#transactionInput(canonical);
    const read = await this.#read(
      [
        {
          method: "rsc_simulateAuthorizedTransaction",
          params: [bytesToHex(input.bytes)],
        },
      ],
      true,
      options,
      false,
    );
    return resultGuard(() => {
      const r = record(read.results[0], [
        "state",
        "transactionHash",
        "authorized",
        "candidateHeight",
        "actionStatus",
        "failureCode",
        "gasUsed",
        "authorizationGasUsed",
        "actualFee",
        "burnedFee",
        "effectiveGasPrice",
        "sponsor",
        "counterDeltaHash",
        "eventsRoot",
        "authorizationEvents",
        "contractAddress",
        "warning",
      ]);
      const observed = state(r.state),
        actionStatus = quantity(r.actionStatus),
        failureCode = quantity(r.failureCode),
        gasUsed = quantity(r.gasUsed),
        authorizationGasUsed = quantity(r.authorizationGasUsed),
        actualFee = amount(r.actualFee),
        burnedFee = amount(r.burnedFee),
        effectiveGasPrice = quantity(r.effectiveGasPrice, 256);
      requireResult(
        boolean(r.authorized) &&
          (actionStatus === 0n || actionStatus === 1n) &&
          (failureCode <= 8n || failureCode === 0x100n) &&
          (actionStatus === 1n ? failureCode === 0n : failureCode !== 0n) &&
          authorizationGasUsed > 0n &&
          authorizationGasUsed <= gasUsed &&
          gasUsed <= input.gasLimit &&
          actualFee === effectiveGasPrice * gasUsed &&
          effectiveGasPrice <= input.maxFeePerGas &&
          burnedFee <= actualFee,
      );
      requireResult(
        r.warning ===
          "Simulation used the reported finalized state and candidate block context; it can become stale before inclusion.",
      );
      const hash = wireBytes(r.transactionHash, 32, 32),
        sponsor = wireBytes(r.sponsor, 20, 20);
      sameBytes(hash, input.id);
      sameBytes(sponsor, input.sponsor);
      const authorizationEvents = array(r.authorizationEvents, 0, 2).map((event) => {
        const e = record(event, ["type", "data"]),
          type = quantity(e.type),
          data = wireBytes(e.data, 303, 303);
        requireResult(
          type >= 0x100n &&
            type <= 0x10dn &&
            data[0] === 0 &&
            data[1] === 1 &&
            ((data[2]! << 8) | data[3]!) === Number(type),
        );
        return { type: Number(type), data };
      });
      return {
        state: observed,
        transactionHash: hash,
        authorized: true,
        candidateHeight: this.#candidate(r.candidateHeight, observed),
        actionStatus: Number(actionStatus) as 0 | 1,
        failureCode: Number(failureCode),
        gasUsed,
        authorizationGasUsed,
        actualFee,
        burnedFee,
        effectiveGasPrice,
        sponsor,
        counterDeltaHash: wireBytes(r.counterDeltaHash, 32, 32),
        eventsRoot: wireBytes(r.eventsRoot, 32, 32),
        authorizationEvents,
        contractAddress: wireBytes(r.contractAddress, 20, 20),
        warning: r.warning,
        advisory: true,
      };
    });
  }
}
