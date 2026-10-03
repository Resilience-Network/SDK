import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import test from "node:test";
import * as sdk from "../dist/index.js";
import { FakeClock } from "./rpc-helpers.mjs";
const commitments = JSON.parse(
  readFileSync(new URL("./fixtures/receipt-commitments.json", import.meta.url)),
);
const rpc = JSON.parse(
  readFileSync(new URL("./fixtures/rpc-receipts.json", import.meta.url)),
);
const pin = JSON.parse(
  readFileSync(new URL("../protocol-source.json", import.meta.url)),
);
const bytes = sdk.hexToBytes,
  hex = sdk.bytesToHex;
const codecs = {
  counter: sdk.receiptCounterDeltaCodec,
  event: sdk.authorizationEventCodec,
  decision: sdk.sessionDecisionCommitmentCodec,
};
const hashes = {
  counter: sdk.receiptCounterDeltaHash,
  event: (v) => sdk.keccak256(sdk.authorizationEventCodec.encode(v)),
  decision: sdk.sessionDecisionCommitmentHash,
};
function harness(
  fixture,
  { mutate = () => {}, options = {}, fetch: customFetch } = {},
) {
  const clock = new FakeClock(),
    calls = [];
  const expected = {
    chainId: 1337n,
    genesisHash: bytes(fixture.identity.result.genesisHash),
    authorizationCapability: sdk.AUTHORIZATION_CAPABILITY,
  };
  const fetch = async (_url, init) => {
    const requests = JSON.parse(init.body);
    calls.push(requests);
    if (customFetch) return customFetch(requests, init);
    const responses = requests.map((request) => {
      const response = structuredClone(
        request.method === "rsc_getAuthorizationFinalityStatus"
          ? fixture.identity
          : request.method === "rsc_getTransactionReceipt"
            ? fixture.receipt
            : fixture.transaction,
      );
      response.id = request.id;
      mutate(response, request, calls.length);
      return response;
    });
    return new Response(JSON.stringify(responses.reverse()));
  };
  return {
    client: new sdk.ChainRpcClient({
      url: "https://rpc.example.invalid",
      expected,
      clock,
      fetch,
      ...options,
    }),
    clock,
    calls,
  };
}
const bad = async (p, code = "INVALID_RESULT") =>
  assert.rejects(p, (e) => e instanceof sdk.RpcContractError && e.code === code);
const id = (f) => bytes(f.transactionHash);

test("166 native receipt/event/decision fixtures retain exact encoding and typed hashes at the immutable pin", () => {
  assert.equal(commitments.revision, pin.revision);
  assert.equal(rpc.revision, pin.revision);
  assert.equal(commitments.fixtures.length, 166);
  assert.equal(rpc.fixtures.length, 11);
  for (const fixture of commitments.fixtures) {
    const value = codecs[fixture.kind].decode(bytes(fixture.hex));
    assert.equal(hex(codecs[fixture.kind].encode(value)), fixture.hex);
    assert.equal(hex(hashes[fixture.kind](value)), fixture.hash);
  }
});
test("canonical receipt codecs reject every truncated length, trailing bytes, unsupported versions and unknown fields", () => {
  for (const fixture of commitments.fixtures) {
    const input = bytes(fixture.hex);
    for (let size = 0; size < input.length; size++)
      assert.throws(
        () => codecs[fixture.kind].decode(input.slice(0, size)),
        sdk.CodecError,
      );
    assert.throws(
      () => codecs[fixture.kind].decode(new Uint8Array([...input, 0])),
      sdk.CodecError,
    );
    const value = codecs[fixture.kind].decode(input);
    assert.throws(
      () => codecs[fixture.kind].encode({ ...value, invented: 1 }),
      sdk.CodecError,
    );
  }
  for (const kind of ["counter", "event"]) {
    const value = codecs[kind].decode(
      bytes(commitments.fixtures.find((f) => f.kind === kind).hex),
    );
    assert.throws(
      () => codecs[kind].encode({ ...value, version: 2 }),
      (e) => e instanceof sdk.CodecError && e.code === "UNSUPPORTED_VERSION",
    );
  }
});
test("authorization event roots enforce exact order/count and attempt/cancel linkage", () => {
  const attempt = sdk.authorizationEventCodec.decode(
    bytes(commitments.fixtures.find((f) => f.name === "event-0107").hex),
  );
  const cancel = { ...structuredClone(attempt), type: 0x108 };
  assert.equal(hex(sdk.authorizationEventsRoot([])), `0x${"00".repeat(32)}`);
  assert.equal(
    hex(sdk.authorizationEventsRoot([attempt])),
    hex(sdk.keccak256(sdk.authorizationEventCodec.encode(attempt))),
  );
  const a = sdk.keccak256(sdk.authorizationEventCodec.encode(attempt)),
    b = sdk.keccak256(sdk.authorizationEventCodec.encode(cancel));
  assert.equal(
    hex(sdk.authorizationEventsRoot([attempt, cancel])),
    hex(sdk.keccak256(a, b)),
  );
  for (const events of [
    [cancel],
    [cancel, attempt],
    [attempt, cancel, attempt],
    [attempt, { ...cancel, blockHeight: 1n }],
    [attempt, { ...cancel, sessionNonce: 1n }],
    [attempt, { ...cancel, transactionId: new Uint8Array(32).fill(2) }],
  ])
    assert.throws(() => sdk.authorizationEventsRoot(events), sdk.CodecError);
});
test("native included success/failure/cancellation receipts preserve exact fee/nonce/attempt effects and canonical binding", async () => {
  for (const fixture of rpc.fixtures) {
    const h = harness(fixture);
    const observation = await h.client.getTransactionReceipt(id(fixture), {
      canonicalTransaction: bytes(fixture.canonical),
    });
    assert.equal(observation.status, "reported-included");
    assert.equal(observation.verification, "node-observation");
    assert.equal(
      observation.receipt.actionStatus,
      fixture.scenario.endsWith("failure") ? 0 : 1,
    );
    const delta = observation.receipt.counterDelta;
    assert.equal(delta.feeDelta, observation.receipt.actualFee);
    assert(delta.feeDelta > 0n);
    assert.equal(delta.nonceDelta, fixture.scenario.startsWith("sponsored") ? 2 : 1);
    assert.equal(
      delta.attemptsDelta,
      fixture.scenario.startsWith("session") ||
        fixture.scenario.startsWith("p256Session")
        ? 1
        : 0,
    );
    if (observation.receipt.actionStatus === 0) {
      assert.equal(delta.successesDelta, 0);
      assert.equal(delta.valueDelta, 0n);
      assert.equal(delta.succeeded, false);
    }
    if (fixture.scenario.startsWith("sessionCancel")) {
      assert.equal(delta.successesDelta, 0);
      assert.equal(delta.valueDelta, 0n);
      assert.equal(observation.receipt.authorizationEvents.length, 2);
    }
    assert.equal(h.calls.length, 1);
    assert.equal(h.clock.tasks.size, 0);
    const transaction = await h.client.getTransactionByHash(id(fixture), {
      canonicalTransaction: bytes(fixture.canonical),
    });
    assert.equal(transaction.status, "reported-included");
    assert.equal(hex(transaction.transaction.hash), fixture.transactionHash);
  }
});
test("null receipt/transaction and pending transaction remain unknown receipt observations, never rejection", async () => {
  const fixture = rpc.fixtures[0];
  for (const pending of [false, true]) {
    const h = harness(fixture, {
      mutate: (r, request) => {
        if (request.method === "rsc_getTransactionReceipt") r.result = null;
        if (request.method === "rsc_getTransactionByHash") {
          if (!pending) r.result = null;
          else
            for (const key of ["blockHash", "blockNumber", "transactionIndex"])
              r.result[key] = null;
        }
      },
    });
    const receipt = await h.client.getTransactionReceipt(id(fixture));
    assert.equal(receipt.status, "unknown");
    assert.equal(receipt.receipt, null);
    assert.equal(receipt.transaction === null, !pending);
    const transaction = await h.client.getTransactionByHash(id(fixture));
    assert.equal(transaction.status, pending ? "reported-pending" : "unknown");
  }
});
test("receipt and transaction validators reject all deleted/unknown required fields and precision loss", async () => {
  let cases = 0;
  for (const fixture of rpc.fixtures) {
    for (const method of ["rsc_getTransactionReceipt", "rsc_getTransactionByHash"]) {
      const result = method.endsWith("Receipt")
        ? fixture.receipt.result
        : fixture.transaction.result;
      for (const field of Object.keys(result).filter(
        (f) => !["sponsor", "sponsorNonce"].includes(f),
      )) {
        const h = harness(fixture, {
          mutate: (r, request) => {
            if (request.method === method) delete r.result[field];
          },
        });
        await bad(h.client.getTransactionReceipt(id(fixture)));
        cases++;
      }
      const h = harness(fixture, {
        mutate: (r, request) => {
          if (request.method === method) r.result.unknown = true;
        },
      });
      await bad(h.client.getTransactionReceipt(id(fixture)));
      cases++;
    }
  }
  assert.equal(cases, 473);
  for (const [method, field, value] of [
    ["rsc_getTransactionReceipt", "actualFee", 9007199254740993],
    ["rsc_getTransactionReceipt", "blockNumber", "0x10000000000000000"],
    ["rsc_getTransactionByHash", "value", Number.MAX_SAFE_INTEGER],
    ["rsc_getTransactionByHash", "nonce", "0x00"],
    ["rsc_getTransactionByHash", "type", "0xff"],
  ]) {
    const h = harness(rpc.fixtures[0], {
      mutate: (r, request) => {
        if (request.method === method) r.result[field] = value;
      },
    });
    await assert.rejects(h.client.getTransactionReceipt(id(rpc.fixtures[0])), (e) =>
      typeof value === "number" && !Number.isSafeInteger(value)
        ? e instanceof sdk.RpcClientError && e.code === "INVALID_JSON"
        : e instanceof sdk.RpcContractError && e.code === "INVALID_RESULT",
    );
  }
});
test("receipts reject conflicting IDs, context, execution/fee/nonce commitments, event data and sponsored fields", async () => {
  const fixture = rpc.fixtures.find((f) => f.scenario === "sessionTransfer-success");
  const mutations = [
    (r) => (r.transactionHash = `0x${"00".repeat(32)}`),
    (r) => (r.blockHash = `0x${"01".repeat(32)}`),
    (r) => (r.blockNumber = "0xc"),
    (r) => (r.transactionIndex = "0x1"),
    (r) => (r.from = `0x${"01".repeat(20)}`),
    (r) => (r.to = null),
    (r) => (r.authorizationNonce = "0x2"),
    (r) => (r.authorizationMode = "0x1"),
    (r) => (r.credentialId = `0x${"01".repeat(32)}`),
    (r) => (r.policyHash = `0x${"01".repeat(32)}`),
    (r) => (r.status = "0x0"),
    (r) => (r.failureCode = "0x1"),
    (r) => (r.actualFee = `0x${"00".repeat(32)}`),
    (r) => (r.burnedFee = `0x${"ff".repeat(32)}`),
    (r) => (r.effectiveGasPrice = "0x0"),
    (r) => (r.authorizationGasUsed = "0xffff"),
    (r) => (r.counterDeltaHash = `0x${"01".repeat(32)}`),
    (r) => (r.eventsRoot = `0x${"01".repeat(32)}`),
    (r) => (r.authorizationEvents = []),
    (r) => (r.authorizationEvents[0].type = "0x108"),
    (r) => (r.authorizationEvents[0].data += "00"),
    (r) => (r.sponsor = `0x${"01".repeat(20)}`),
  ];
  for (const mutate of mutations) {
    const h = harness(fixture, {
      mutate: (r, request) => {
        if (request.method === "rsc_getTransactionReceipt") mutate(r.result);
      },
    });
    await bad(h.client.getTransactionReceipt(id(fixture)));
    assert.equal(h.calls.length, 1);
  }
  const version = harness(fixture, {
    mutate: (r, request) => {
      if (request.method === "rsc_getTransactionReceipt")
        r.result.authorizationEvents[0].data =
          "0x0002" + r.result.authorizationEvents[0].data.slice(6);
    },
  });
  await bad(version.client.getTransactionReceipt(id(fixture)), "UNSUPPORTED_RESULT");
  const missingTx = harness(fixture, {
    mutate: (r, request) => {
      if (request.method === "rsc_getTransactionByHash") r.result = null;
    },
  });
  await bad(missingTx.client.getTransactionReceipt(id(fixture)));
});
test("lookup canonical input is copied before dispatch; wrong canonical transaction rejects before network", async () => {
  const fixture = rpc.fixtures[0],
    h = harness(fixture),
    canonical = bytes(fixture.canonical),
    hash = id(fixture);
  const pending = h.client.getTransactionReceipt(hash, {
    canonicalTransaction: canonical,
  });
  canonical.fill(0);
  hash.fill(0);
  assert.equal((await pending).status, "reported-included");
  const invalid = harness(fixture);
  await bad(
    invalid.client.getTransactionReceipt(id(fixture), {
      canonicalTransaction: bytes(rpc.fixtures[2].canonical),
    }),
    "INVALID_ARGUMENT",
  );
  assert.equal(invalid.calls.length, 0);
  const changed = harness(fixture, {
    mutate: (r, request) => {
      if (request.method === "rsc_getTransactionByHash") r.result.value = "0x1";
    },
  });
  await bad(
    changed.client.getTransactionReceipt(id(fixture), {
      canonicalTransaction: bytes(fixture.canonical),
    }),
  );
});
test("receipt moving context cannot mask invalid results and all lookups respect abort/deadline", async () => {
  const fixture = rpc.fixtures[0];
  const moving = harness(fixture, {
    mutate: (r, request) => {
      if (request.method === "rsc_getTransactionReceipt")
        r.result.transactionHash = "bad";
      if (request.method === "rsc_getAuthorizationFinalityStatus")
        r.result.state.height = request.id % 2 ? "0xa" : "0xb";
    },
  });
  await bad(moving.client.getTransactionReceipt(id(fixture)));
  assert.equal(moving.calls.length, 1);
  const controller = new AbortController();
  controller.abort();
  const pre = harness(fixture);
  await bad(
    pre.client.getTransactionReceipt(id(fixture), { signal: controller.signal }),
    "OBSERVATION_ABORTED",
  );
  assert.equal(pre.calls.length, 0);
  const stalled = harness(fixture, {
    options: { timeoutMs: 20 },
    fetch: async () => new Promise(() => {}),
  });
  const operation = bad(
    stalled.client.getTransactionReceipt(id(fixture)),
    "OBSERVATION_TIMEOUT",
  );
  await stalled.clock.advance(20);
  await operation;
  assert.equal(stalled.clock.tasks.size, 0);
});

test("receipt logs bind all indices/identities and cannot introduce removed events or unbounded data", async () => {
  const fixture = rpc.fixtures.find((f) => f.scenario === "directTransfer-success");
  assert.equal(fixture.receipt.result.logs.length, 1);
  const log = fixture.receipt.result.logs[0];
  for (const field of Object.keys(log)) {
    const h = harness(fixture, {
      mutate: (r, request) => {
        if (request.method === "rsc_getTransactionReceipt")
          delete r.result.logs[0][field];
      },
    });
    await bad(h.client.getTransactionReceipt(id(fixture)));
  }
  for (const mutation of [
    (l) => (l.logIndex = "0x1"),
    (l) => (l.blockNumber = "0xa"),
    (l) => (l.transactionIndex = "0x1"),
    (l) => (l.transactionHash = `0x${"01".repeat(32)}`),
    (l) => (l.blockHash = `0x${"01".repeat(32)}`),
    (l) => (l.removed = true),
    (l) => (l.topics = Array(5).fill(`0x${"01".repeat(32)}`)),
    (l) => (l.data = "0x" + "00".repeat(65537)),
    (l) => (l.extra = true),
  ]) {
    const h = harness(fixture, {
      mutate: (r, request) => {
        if (request.method === "rsc_getTransactionReceipt") mutation(r.result.logs[0]);
      },
    });
    await bad(h.client.getTransactionReceipt(id(fixture)));
  }
});
test(
  "actual Node HTTP concurrently validates native receipt/transaction batches with isolated output ownership",
  { timeout: 10000 },
  async (t) => {
    const fixture = rpc.fixtures.find((f) => f.scenario === "sessionTransfer-failure");
    let calls = 0;
    const failures = [];
    const server = createServer(async (request, response) => {
      try {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const requests = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        calls++;
        const output = requests.map((r) => {
          assert.equal(r.jsonrpc, "2.0");
          const value = structuredClone(
            r.method === "rsc_getAuthorizationFinalityStatus"
              ? fixture.identity
              : r.method === "rsc_getTransactionReceipt"
                ? fixture.receipt
                : fixture.transaction,
          );
          value.id = r.id;
          return value;
        });
        response.setHeader("Content-Type", "application/json");
        response.end(JSON.stringify(output.reverse()));
      } catch (failure) {
        failures.push(failure);
        response.destroy();
      }
    });
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    t.after(async () => {
      server.closeAllConnections();
      await new Promise((resolve, reject) =>
        server.close((e) => (e ? reject(e) : resolve())),
      );
      assert.deepEqual(failures, []);
    });
    const client = new sdk.ChainRpcClient({
      url: `http://127.0.0.1:${server.address().port}/`,
      expected: {
        chainId: 1337n,
        genesisHash: bytes(fixture.identity.result.genesisHash),
        authorizationCapability: sdk.AUTHORIZATION_CAPABILITY,
      },
    });
    const observations = await Promise.all(
      Array.from({ length: 32 }, () =>
        client.getTransactionReceipt(id(fixture), {
          canonicalTransaction: bytes(fixture.canonical),
        }),
      ),
    );
    assert.equal(calls, 32);
    for (const observation of observations) {
      assert.equal(observation.status, "reported-included");
      assert.equal(observation.receipt.actionStatus, 0);
      assert.equal(observation.receipt.counterDelta.attemptsDelta, 1);
      assert.equal(observation.receipt.counterDelta.successesDelta, 0);
    }
    observations[0].receipt.transactionHash.fill(0);
    observations[0].receipt.authorizationEvents[0].grantId.fill(0);
    assert.equal(hex(observations[1].receipt.transactionHash), fixture.transactionHash);
    assert.notEqual(
      hex(observations[1].receipt.authorizationEvents[0].grantId),
      `0x${"00".repeat(32)}`,
    );
  },
);

test("a valid receipt appearing during a moving head refreshes the whole observation once", async () => {
  const fixture = rpc.fixtures[0];
  let identityCalls = 0;
  const h = harness(fixture, {
    mutate: (r, request, pass) => {
      if (request.method === "rsc_getAuthorizationFinalityStatus") {
        identityCalls++;
        if (pass === 1 && identityCalls === 1) {
          r.result.state.height = "0xa";
          r.result.state.blockHash = `0x${"01".repeat(32)}`;
        }
      }
    },
  });
  const observed = await h.client.getTransactionReceipt(id(fixture));
  assert.equal(observed.status, "reported-included");
  assert.equal(h.calls.length, 2);
  assert.equal(observed.identity.state.height, 11n);
  const exhausted = harness(fixture, {
    options: { maxContextRefreshes: 0 },
    mutate: (r, request) => {
      if (request.method === "rsc_getAuthorizationFinalityStatus" && request.id === 1) {
        r.result.state.height = "0xa";
        r.result.state.blockHash = `0x${"01".repeat(32)}`;
      }
    },
  });
  await bad(
    exhausted.client.getTransactionReceipt(id(fixture)),
    "STATE_CONTEXT_MISMATCH",
  );
  assert.equal(exhausted.calls.length, 1);
});

test("lookup rejects non-byte canonical input and validates pending sponsor field pairs", async () => {
  const fixture = rpc.fixtures[0];
  const invalid = harness(fixture);
  await bad(
    invalid.client.getTransactionReceipt(id(fixture), {
      canonicalTransaction: Array.from(bytes(fixture.canonical)),
    }),
    "INVALID_ARGUMENT",
  );
  assert.equal(invalid.calls.length, 0);
  const sponsored = rpc.fixtures.find(
    (f) => f.scenario === "sponsoredTransfer-success",
  );
  for (const field of ["sponsor", "sponsorNonce"]) {
    const h = harness(sponsored, {
      mutate: (r, request) => {
        if (request.method === "rsc_getTransactionByHash") delete r.result[field];
      },
    });
    await bad(h.client.getTransactionReceipt(id(sponsored)));
  }
});
