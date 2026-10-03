import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import {
  AUTHORIZATION_CAPABILITY,
  ChainRpcClient,
  RpcClientError,
  RpcContractError,
  bytesToHex,
  hexToBytes,
  policyCodec,
  transactionCodec,
  transactionId,
} from "../dist/index.js";
import { quantity, wireBytes } from "../dist/rpc/validate.js";
import {
  expected,
  findFixture,
  fixtureFile,
  fixtures,
  invokeFixture,
  methodHarness,
} from "./rpc-methods-helpers.mjs";
import { flush, url } from "./rpc-helpers.mjs";

const clone = structuredClone;
const contractFailure =
  (code = "INVALID_RESULT") =>
  (e) =>
    e instanceof RpcContractError && e.code === code;
const fixture = (method, scenario = "ed25519") =>
  findFixture(scenario, `rsc_${method}`);

test("41 native production-handler fixtures cover all typed methods and both grant schemes", async () => {
  const pin = JSON.parse(
    readFileSync(new URL("../protocol-source.json", import.meta.url), "utf8"),
  );
  assert.equal(fixtureFile.revision, pin.revision);
  const methods = new Set();
  for (const f of fixtures) {
    const h = methodHarness(f);
    methods.add(f.method);
    if (f.response.error) {
      await assert.rejects(
        invokeFixture(h.client, f),
        (e) =>
          e instanceof RpcClientError &&
          e.rpcCode === f.response.error.code &&
          e.authorizationFamily === f.response.error.data.family,
      );
    } else {
      const result = await invokeFixture(h.client, f);
      assert(result !== undefined);
      if (result.state)
        assert.equal(result.state.height, BigInt(f.identity.result.state.height));
      if (f.method === "rsc_getSessionGrant") {
        assert.equal(result.keyScheme, f.scenario.startsWith("p256") ? 2 : 1);
        assert.equal(result.publicKey.length, f.scenario.startsWith("p256") ? 64 : 32);
        assert.equal(result.sessionNonce, 0n);
      }
      if (
        f.method.includes("simulate") ||
        f.method.includes("estimate") ||
        f.method.includes("feeHistory")
      )
        assert.equal(result.advisory, true);
    }
    assert.equal(h.calls.length, 1);
    assert.equal(h.clock.tasks.size, 0);
  }
  assert.equal(methods.size, 14);
});

function fieldPaths(value, path = []) {
  if (value === null || typeof value !== "object") return [];
  if (Array.isArray(value)) return value.flatMap((v, i) => fieldPaths(v, [...path, i]));
  return Object.entries(value).flatMap(([key, child]) => [
    [...path, key],
    ...fieldPaths(child, [...path, key]),
  ]);
}
function locate(value, path) {
  for (const key of path) value = value[key];
  return value;
}
function objectPaths(value, path = []) {
  if (value === null || typeof value !== "object") return [];
  if (Array.isArray(value))
    return value.flatMap((v, i) => objectPaths(v, [...path, i]));
  return [
    path,
    ...Object.entries(value).flatMap(([key, child]) =>
      objectPaths(child, [...path, key]),
    ),
  ];
}

test("every native result rejects each missing field and unknown fields at every object level", async () => {
  let checked = 0;
  for (const f of fixtures.filter(
    (f) => Object.hasOwn(f.response, "result") && typeof f.response.result === "object",
  )) {
    for (const path of fieldPaths(f.response.result)) {
      const h = methodHarness(f, {
        mutate(response, request) {
          if (request.method !== f.method) return;
          const parent = locate(response.result, path.slice(0, -1));
          delete parent[path.at(-1)];
        },
      });
      await assert.rejects(
        invokeFixture(h.client, f),
        contractFailure(),
        `${f.scenario}/${f.method}: missing ${path.join(".")}`,
      );
      checked++;
    }
    for (const path of objectPaths(f.response.result)) {
      const h = methodHarness(f, {
        mutate(response, request) {
          if (request.method === f.method)
            locate(response.result, path).futureField = "untrusted";
        },
      });
      await assert.rejects(
        invokeFixture(h.client, f),
        contractFailure(),
        `${f.method}: unknown field at ${path.join(".")}`,
      );
      checked++;
    }
  }
  assert.equal(
    checked,
    905,
    "Update this count only after inspecting fixture coverage changes",
  );
});

test("quantities are exact, minimal, bounded and distinct from byte strings", () => {
  assert.equal(quantity("0x0"), 0n);
  assert.equal(quantity("0xffffffffffffffff"), (1n << 64n) - 1n);
  assert.equal(quantity(`0x${"f".repeat(64)}`, 256), (1n << 256n) - 1n);
  for (const q of [
    "0x",
    "0x00",
    "0x01",
    "0X1",
    "0xA",
    "0x-1",
    "1",
    " 0x1",
    "0x1.0",
    "0x10000000000000000",
    1,
    9007199254740992,
    null,
  ])
    assert.throws(() => quantity(q), contractFailure());
  assert.throws(() => quantity(`0x1${"0".repeat(64)}`, 256), contractFailure());
  assert.equal(wireBytes("0x00", 1, 1)[0], 0);
  for (const h of ["0x0", "0x0000", "00", "0xzz", "0x"])
    assert.throws(() => wireBytes(h, 1, 1));
});

test("trusted chain ID, genesis, capability and finalized status are mandatory on every read", async () => {
  for (const [key, value, code] of [
    ["chainId", "0x1", "CHAIN_IDENTITY_MISMATCH"],
    ["genesisHash", `0x${"ff".repeat(32)}`, "CHAIN_IDENTITY_MISMATCH"],
    ["authorizationCapability", "resilience/tx-auth/3", "CHAIN_IDENTITY_MISMATCH"],
    ["chainId", "0x0539", "INVALID_RESULT"],
    ["genesisHash", "0xaa", "INVALID_RESULT"],
  ]) {
    const h = methodHarness(fixture("getRootAuthority"), {
      mutate(r, request) {
        if (request.method.includes("Finality")) r.result[key] = value;
      },
    });
    await assert.rejects(
      invokeFixture(h.client, fixture("getRootAuthority")),
      contractFailure(code),
    );
    assert.equal(h.calls.length, 1);
  }
  const h = methodHarness(fixture("getRootAuthority"), {
    mutate(r, request, _pass, index) {
      if (request.method.includes("Finality") && index === 2) r.result.chainId = "0x1";
    },
  });
  await assert.rejects(
    invokeFixture(h.client, fixture("getRootAuthority")),
    contractFailure("CHAIN_IDENTITY_MISMATCH"),
  );
  for (const expectedValue of [
    undefined,
    { ...expected, chainId: -1n },
    { ...expected, chainId: 1 },
    { ...expected, genesisHash: new Uint8Array(31) },
    { ...expected, authorizationCapability: "other" },
  ])
    assert.throws(
      () => new ChainRpcClient({ url, expected: expectedValue }),
      contractFailure("INVALID_ARGUMENT"),
    );
  for (const options of [
    { maxContextRefreshes: 4 },
    { maxContextRefreshes: -1 },
    { maxContextRefreshes: 1.5 },
    { maxBatchSize: 5 },
  ])
    assert.throws(
      () => new ChainRpcClient({ url, expected, ...options }),
      contractFailure("INVALID_ARGUMENT"),
    );
  const finality = methodHarness(fixture("getAuthorizationFinalityStatus"), {
    mutate(r) {
      r.result.state.finality = "pending";
    },
  });
  await assert.rejects(
    finality.client.getAuthorizationFinalityStatus(),
    contractFailure(),
  );
});

test("changing block hash, state root or height refreshes the whole read within a fixed bound", async () => {
  const f = fixture("getRootAuthority");
  for (const [key, value] of [
    ["height", "0xc"],
    ["blockHash", `0x${"ff".repeat(32)}`],
    ["stateRoot", `0x${"ff".repeat(32)}`],
  ]) {
    const h = methodHarness(f, {
      mutate(r, req, pass) {
        if (pass === 1 && req.method === f.method) r.result.state[key] = value;
      },
    });
    const result = await invokeFixture(h.client, f);
    assert.equal(result.state.height, 11n);
    assert.equal(h.calls.length, 2);
    assert.deepEqual(
      h.calls[0].requests.map((r) => r.method),
      h.calls[1].requests.map((r) => r.method),
    );
    assert(
      h.calls.every((c) => c.requests.every((r) => r.params.length <= 1)),
      "No invented historical selectors",
    );
    const forever = methodHarness(f, {
      mutate(r, req) {
        if (req.method === f.method) r.result.state[key] = value;
      },
      options: { maxContextRefreshes: 3 },
    });
    await assert.rejects(
      invokeFixture(forever.client, f),
      contractFailure("STATE_CONTEXT_MISMATCH"),
    );
    assert.equal(forever.calls.length, 4);
    assert.equal(forever.clock.tasks.size, 0);
  }
  const movingIdentity = methodHarness(f, {
    mutate(r, req, pass, index) {
      if (pass === 1 && index === 2) r.result.state.height = "0xc";
    },
  });
  await invokeFixture(movingIdentity.client, f);
  assert.equal(movingIdentity.calls.length, 2);
  const malformed = methodHarness(f, {
    mutate(r, req) {
      if (req.method === f.method) delete r.result.state.blockHash;
    },
  });
  await assert.rejects(invokeFixture(malformed.client, f), contractFailure());
  assert.equal(malformed.calls.length, 1);
  const malformedMoving = methodHarness(f, {
    mutate(r, req) {
      if (req.method === f.method) {
        r.result.state.height = "0xc";
        delete r.result.authority.rootNonce;
      }
    },
  });
  await assert.rejects(invokeFixture(malformedMoving.client, f), contractFailure());
  assert.equal(
    malformedMoving.calls.length,
    1,
    "A moving head must not hide malformed contract data",
  );
});

test("atomic-looking batches still require matching contexts and redundant state invariants", async () => {
  const f = fixture("getSessionGrant"),
    owner = hexToBytes(f.params[0]),
    id = hexToBytes(f.params[1]);
  const h = methodHarness(f);
  const result = await h.client.getAuthorizationSnapshot(owner, id);
  assert.equal(result.grant.sessionNonce, result.nonce.sessionNonce);
  assert.equal(h.calls[0].requests.length, 6);
  for (const mutate of [
    (r, req) => {
      if (req.method === "rsc_getSessionNonce") r.result.sessionNonce = "0x1";
    },
    (r, req) => {
      if (req.method === "rsc_getSessionNonce") r.result.usableAtObservedBlock = false;
    },
    (r, req) => {
      if (req.method === "rsc_getSessionUsage") r.result.usage.attempts = "0x1";
    },
    (r, req) => {
      if (req.method === "rsc_getSessionUsage")
        r.result.policyHash = `0x${"ff".repeat(32)}`;
    },
    (r, req) => {
      if (req.method === "rsc_getRootAuthority") {
        // Keep the authority projection internally consistent while violating
        // the cross-record generation invariant (pinned state-codec offset).
        r.result.authority.nextGrantSequence = "0x0";
        const canonical = hexToBytes(r.result.authority.canonical);
        canonical.fill(0, 18, 26);
        r.result.authority.canonical = bytesToHex(canonical);
      }
    },
  ]) {
    const bad = methodHarness(f, { mutate });
    await assert.rejects(
      bad.client.getAuthorizationSnapshot(owner, id),
      contractFailure(),
    );
  }
  const moving = methodHarness(f, {
    mutate(r, req, pass) {
      if (pass === 1 && req.method === "rsc_getSessionNonce")
        r.result.state.height = "0xc";
    },
  });
  await moving.client.getAuthorizationSnapshot(owner, id);
  assert.equal(moving.calls.length, 2);
});

test("root/grant policy, public key, canonical bytes, identity, deposit and usage are cross-checked", async () => {
  const f = fixture("getSessionGrant");
  const mutations = [
    (r) => {
      r.canonical += "00";
    },
    (r) => {
      r.policyHash = `0x${"ff".repeat(32)}`;
    },
    (r) => {
      r.publicKey = `0x${"00".repeat(32)}`;
    },
    (r) => {
      r.owner = `0x${"01".repeat(20)}`;
    },
    (r) => {
      r.grantId = `0x${"ff".repeat(32)}`;
    },
    (r) => {
      r.authEpoch = "0x0";
    },
    (r) => {
      r.generationSequence = "0x1";
    },
    (r) => {
      r.storageDeposit = `0x${"00".repeat(32)}`;
    },
    (r) => {
      r.sessionNonce = "0x1";
    },
    (r) => {
      r.usage.successes = "0x1";
    },
    (r) => {
      r.usage.attempts = "0xb";
    },
    (r) => {
      r.usage.valueBuckets = [];
    },
    (r) => {
      r.usage.feeBucket.available = `0x${"ff".repeat(32)}`;
    },
    (r) => {
      r.usage.valueBuckets[0].lastRefillHeight = "0x9";
    },
    (r) => {
      r.usage.claims = "0x1";
    },
    (r) => {
      r.policyVersion = 2;
    },
    (r) => {
      r.validAfterHeight = r.createdHeight;
    },
    (r) => {
      r.validUntilHeight = "0xffffffffffffffff";
    },
    (r) => {
      r.activeIndexPresent = false;
    },
    (r) => {
      r.policy.transfer.allowZeroValue = "false";
    },
    (r) => {
      r.policy.fee.maxGasPrice = "0xa";
    },
    (r) => {
      r.policy.transfer.recipients.merkleRoot = `0x${"01".repeat(32)}`;
    },
  ];
  for (const mutate of mutations) {
    const h = methodHarness(f, {
      mutate(r, req) {
        if (req.method === f.method) mutate(r.result);
      },
    });
    await assert.rejects(
      invokeFixture(h.client, f),
      (e) => e instanceof RpcContractError,
    );
  }
  const root = fixture("getRootAuthority");
  for (const mutate of [
    (r) => {
      r.authority.canonical += "00";
    },
    (r) => {
      r.authority.rootConfigHash = `0x${"ff".repeat(32)}`;
    },
    (r) => {
      r.authority.rootConfig.keys[0].rootKeyId = `0x${"ff".repeat(32)}`;
    },
    (r) => {
      r.authority.activeGrantCount = 65;
    },
    (r) => {
      r.authority.rootConfig.threshold = 0;
    },
    (r) => {
      r.authority.securityReserve = `0x${"00".repeat(32)}`;
    },
  ]) {
    const h = methodHarness(root, {
      mutate(r, req) {
        if (req.method === root.method) mutate(r.result);
      },
    });
    await assert.rejects(
      invokeFixture(h.client, root),
      (e) => e instanceof RpcContractError,
    );
  }
});

test("revoke-all keeps both schemes readable while epoch mismatch removes usability", async () => {
  for (const scheme of ["ed25519", "p256"]) {
    const f = fixture("getSessionGrant", `${scheme}-revoked`),
      h = methodHarness(f);
    const result = await h.client.getAuthorizationSnapshot(
      hexToBytes(f.params[0]),
      hexToBytes(f.params[1]),
    );
    assert.equal(result.root.authority.authEpoch, 2n);
    assert.equal(result.root.authority.activeGrantCount, 0);
    assert.equal(result.grant.authEpoch, 1n);
    assert.equal(result.grant.activeIndexPresent, true);
    assert.equal(result.grant.usableAtObservedBlock, false);
    assert.equal(result.nonce.usableAtObservedBlock, false);
    const bad = methodHarness(f, {
      mutate(r, req) {
        if (["rsc_getSessionGrant", "rsc_getSessionNonce"].includes(req.method))
          r.result.usableAtObservedBlock = true;
      },
    });
    await assert.rejects(
      bad.client.getAuthorizationSnapshot(
        hexToBytes(f.params[0]),
        hexToBytes(f.params[1]),
      ),
      contractFailure(),
    );
  }
});

test("policy preview is bound to the requested bytes and exact derived actions/warnings", async () => {
  const f = fixture("previewPolicy", "ed25519-warnings"),
    h = methodHarness(f);
  const result = await invokeFixture(h.client, f);
  assert.equal(result.policy.maxAttempts, (1n << 64n) - 1n);
  assert.equal(result.warnings.length, 2);
  for (const mutate of [
    (r) => {
      r.enabledActions = [];
    },
    (r) => {
      r.warnings = [];
    },
    (r) => {
      r.securityNotice = "TRUST ME";
    },
    (r) => {
      r.canonical = "0x00";
    },
    (r) => {
      r.policy.actionMask = "0x3";
    },
  ]) {
    const bad = methodHarness(f, {
      mutate(r, req) {
        if (req.method === f.method) mutate(r.result);
      },
    });
    await assert.rejects(
      invokeFixture(bad.client, f),
      (e) => e instanceof RpcContractError,
    );
  }
});

test("fee suggestions and history preserve exact amounts and bound dimensions/percentiles", async () => {
  const gas = fixture("gasPrice", "direct");
  const h = methodHarness(gas, {
    mutate(r, req) {
      if (req.method === "rsc_gasPrice") r.result = `0x${"f".repeat(64)}`;
    },
  });
  assert.equal((await h.client.getFeeSuggestions()).gasPrice, (1n << 256n) - 1n);
  for (const method of ["rsc_gasPrice", "rsc_maxPriorityFeePerGas"])
    for (const value of ["0x00", "0x1" + "0".repeat(64), 1, null, {}]) {
      const bad = methodHarness(gas, {
        mutate(r, req) {
          if (req.method === method) r.result = value;
        },
      });
      await assert.rejects(bad.client.getFeeSuggestions(), contractFailure());
    }
  const f = fixture("feeHistory", "direct");
  for (const mutate of [
    (r) => {
      r.baseFeePerGas = [];
    },
    (r) => {
      r.gasUsedRatio = [1.1];
    },
    (r) => {
      r.oldestBlock = "0x1";
    },
    (r) => {
      r.reward[0].pop();
    },
    (r) => {
      r.reward.push([]);
    },
    (r) => {
      r.baseFeePerGas[0] = "0x01";
    },
  ]) {
    const bad = methodHarness(f, {
      mutate(r, req) {
        if (req.method === f.method) mutate(r.result);
      },
    });
    await assert.rejects(invokeFixture(bad.client, f), contractFailure());
  }
  const valid = {
    blockCount: 2,
    newestBlock: "latest",
    rewardPercentiles: [0, 50, 100],
  };
  for (const args of [
    { ...valid, blockCount: 0 },
    { ...valid, blockCount: 65 },
    { ...valid, newestBlock: -1n },
    { ...valid, newestBlock: "pending" },
    { ...valid, rewardPercentiles: [NaN] },
    { ...valid, rewardPercentiles: [101] },
    { ...valid, rewardPercentiles: Array(65).fill(1) },
  ]) {
    const bad = methodHarness(f);
    await assert.rejects(
      bad.client.getFeeHistory(args),
      contractFailure("INVALID_ARGUMENT"),
    );
    assert.equal(bad.calls.length, 0);
  }
});

test("estimates/simulations are advisory, bind transaction identity and never silently repeat", async () => {
  for (const name of ["estimateAuthorizationGas", "simulateAuthorizedTransaction"]) {
    const f = fixture(name, "session"),
      h = methodHarness(f),
      result = await invokeFixture(h.client, f);
    assert.equal(result.advisory, true);
    assert.equal(result.candidateHeight, 12n);
    const moving = methodHarness(f, {
      mutate(r, req) {
        if (req.method === f.method) r.result.state.height = "0xc";
      },
    });
    await assert.rejects(
      invokeFixture(moving.client, f),
      contractFailure("STATE_CONTEXT_MISMATCH"),
    );
    assert.equal(moving.calls.length, 1);
    for (const mutate of [
      (r) => {
        r.candidateHeight = "0xb";
      },
      (r) => {
        r.warning = "guaranteed";
      },
    ]) {
      const bad = methodHarness(f, {
        mutate(r, req) {
          if (req.method === f.method) mutate(r.result);
        },
      });
      await assert.rejects(invokeFixture(bad.client, f), contractFailure());
    }
    const network = methodHarness(f, {
      fetch: async () => {
        throw new Error("SECRET");
      },
    });
    await assert.rejects(
      invokeFixture(network.client, f),
      (e) => e instanceof RpcClientError && e.code === "NETWORK_ERROR",
    );
    assert.equal(network.calls.length, 1);
  }
  const f = fixture("simulateAuthorizedTransaction", "session");
  for (const mutate of [
    (r) => {
      r.transactionHash = `0x${"ff".repeat(32)}`;
    },
    (r) => {
      r.authorized = false;
    },
    (r) => {
      r.actionStatus = "0x2";
    },
    (r) => {
      r.failureCode = "0x1";
    },
    (r) => {
      r.gasUsed = "0x0";
    },
    (r) => {
      r.actualFee = `0x${"00".repeat(32)}`;
    },
    (r) => {
      r.burnedFee = `0x${"ff".repeat(32)}`;
    },
    (r) => {
      r.authorizationEvents[0].type = "0x9999";
    },
    (r) => {
      r.authorizationEvents[0].data += "00";
    },
    (r) => {
      r.authorizationEvents.push(...r.authorizationEvents, ...r.authorizationEvents);
    },
    (r) => {
      r.sponsor = `0x${"ff".repeat(20)}`;
    },
  ]) {
    const bad = methodHarness(f, {
      mutate(r, req) {
        if (req.method === f.method) mutate(r.result);
      },
    });
    await assert.rejects(invokeFixture(bad.client, f), contractFailure());
  }
  // A structurally valid failure remains authorized, advisory and distinct from success.
  const failed = methodHarness(f, {
    mutate(r, req) {
      if (req.method === f.method) {
        r.result.actionStatus = "0x0";
        r.result.failureCode = "0x100";
      }
    },
  });
  assert.equal((await invokeFixture(failed.client, f)).actionStatus, 0);
});

test("input buffers and expected configuration are copied before asynchronous dispatch", async () => {
  const f = fixture("getSessionGrant"),
    trusted = { ...expected, genesisHash: expected.genesisHash.slice() },
    owner = hexToBytes(f.params[0]),
    id = hexToBytes(f.params[1]);
  const h = methodHarness(f, { options: { expected: trusted } }),
    pending = h.client.getSessionGrant(owner, id);
  owner.fill(9);
  id.fill(9);
  trusted.genesisHash.fill(9);
  trusted.chainId = 1n;
  const result = await pending;
  assert.equal(bytesToHex(result.owner), f.params[0]);
  assert.equal(bytesToHex(result.grantId), f.params[1]);
  const p = fixture("previewPolicy"),
    canonical = hexToBytes(p.params[0]),
    policyHarness = methodHarness(p),
    read = policyHarness.client.previewPolicy(canonical);
  canonical.fill(0);
  await read;
  const bad = methodHarness(p);
  await assert.rejects(
    bad.client.previewPolicy(new Uint8Array([0])),
    contractFailure("INVALID_ARGUMENT"),
  );
  assert.equal(bad.calls.length, 0);
  const tx = fixture("simulateAuthorizedTransaction", "direct"),
    wrong = transactionCodec.decode(hexToBytes(tx.params[0]));
  wrong.intent.chainId = 1n;
  const txh = methodHarness(tx);
  await assert.rejects(
    txh.client.simulateAuthorizedTransaction(transactionCodec.encode(wrong)),
    contractFailure("INVALID_ARGUMENT"),
  );
  assert.equal(txh.calls.length, 0);
});

test("overall read budget spans refreshes; abort/deadline dispose timers even when fetch ignores signal", async () => {
  const f = fixture("getRootAuthority");
  const pre = methodHarness(f),
    controller = new AbortController();
  controller.abort("SECRET");
  await assert.rejects(
    invokeFixture(pre.client, f, { signal: controller.signal }),
    contractFailure("OBSERVATION_ABORTED"),
  );
  assert.equal(pre.calls.length, 0);
  assert.equal(pre.clock.tasks.size, 0);
  const mid = methodHarness(f, { fetch: async () => new Promise(() => {}) }),
    cancel = new AbortController(),
    pending = invokeFixture(mid.client, f, { signal: cancel.signal });
  await flush();
  cancel.abort("SECRET");
  await assert.rejects(pending, contractFailure("OBSERVATION_ABORTED"));
  assert.equal(mid.clock.tasks.size, 0);
  const timeout = methodHarness(f, {
      options: { timeoutMs: 100 },
      fetch: async () => new Promise(() => {}),
    }),
    timed = invokeFixture(timeout.client, f);
  await timeout.clock.advance(100);
  await assert.rejects(timed, contractFailure("OBSERVATION_TIMEOUT"));
  assert.equal(timeout.clock.tasks.size, 0);
  const refresh = methodHarness(f, {
      options: { timeoutMs: 100 },
      fetch: async (req, pass) => {
        if (pass === 1) {
          refresh.clock.time = 80;
          return new Response(
            JSON.stringify(
              req.map((r) => ({
                jsonrpc: "2.0",
                id: r.id,
                result:
                  r.method === f.method
                    ? {
                        ...clone(f.response.result),
                        state: { ...f.response.result.state, height: "0xc" },
                      }
                    : f.identity.result,
              })),
            ),
          );
        }
        return new Promise(() => {});
      },
    }),
    bounded = invokeFixture(refresh.client, f);
  for (let i = 0; i < 10 && refresh.calls.length < 2; i++) await flush();
  assert.equal(refresh.calls.length, 2);
  await refresh.clock.advance(20);
  await assert.rejects(bounded, contractFailure("OBSERVATION_TIMEOUT"));
  assert.equal(refresh.calls.length, 2);
  assert.equal(refresh.clock.tasks.size, 0);
});

test("node error families retain only fixed tokens and never leak arbitrary diagnostics", async () => {
  const f = fixture("getSessionGrant", "ed25519-unknown");
  for (const family of [
    "AUTH_MALFORMED",
    "AUTH_UNKNOWN_CREDENTIAL",
    "AUTH_UNSUPPORTED_VERSION",
    "AUTH_LIMIT_EXCEEDED",
    "AUTH_ACTION_DENIED",
    "AUTH_BAD_SIGNATURE",
    "SECRET",
    null,
    {},
  ]) {
    const h = methodHarness(f, {
      mutate(r, req) {
        if (req.method === f.method)
          r.error = {
            code: -32000,
            message: "SECRET",
            data: { family, payload: "SECRET" },
          };
      },
    });
    await assert.rejects(invokeFixture(h.client, f), (e) => {
      assert(e instanceof RpcClientError);
      assert.equal(
        e.authorizationFamily,
        typeof family === "string" && family.startsWith("AUTH_") ? family : undefined,
      );
      assert(!JSON.stringify(e).includes("SECRET"));
      assert(!e.message.includes("SECRET"));
      assert.equal(e.cause, undefined);
      return true;
    });
    assert.equal(h.calls.length, 1);
  }
});
