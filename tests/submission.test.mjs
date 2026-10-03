import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import test from "node:test";
import * as sdk from "../dist/index.js";
import { FakeClock, flush } from "./rpc-helpers.mjs";
const record = JSON.parse(
  readFileSync(new URL("./fixtures/rpc-reconciliation.json", import.meta.url)),
);
const fixtures = record.fixtures,
  bytes = sdk.hexToBytes,
  hex = sdk.bytesToHex;
function harness(
  fixture,
  { mutate = () => {}, send, options = {}, fetch: customFetch } = {},
) {
  const clock = new FakeClock(),
    calls = [];
  const fetch = async (_url, init) => {
    const request = JSON.parse(init.body);
    calls.push(request);
    if (customFetch) return customFetch(request, init);
    if (!Array.isArray(request)) {
      assert.equal(request.method, "rsc_sendRawTransaction");
      assert.equal(request.params[0], fixture.canonical);
      if (send) return send(request, init);
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: request.id,
          result: fixture.transactionHash,
        }),
      );
    }
    const responses = request.map((r) => {
      const key = {
        rsc_getAuthorizationFinalityStatus: "identity",
        rsc_getTransactionReceipt: "receipt",
        rsc_getTransactionByHash: "transaction",
        rsc_getRootAuthority: "root",
        rsc_getSessionGrant: "grant",
        rsc_getBlockByNumber: "block",
      }[r.method];
      let native = key
        ? fixture[key]
        : r.params[0] === fixture.transaction.result.from
          ? fixture.accountNonce
          : fixture.sponsorNonce;
      assert(native, `No native fixture for ${r.method}`);
      const response = structuredClone(native);
      response.id = r.id;
      mutate(response, r, calls.length);
      return response;
    });
    return new Response(JSON.stringify(responses.reverse()));
  };
  return {
    client: new sdk.ChainRpcClient({
      url: "https://rpc.example.invalid",
      expected: {
        chainId: 1337n,
        genesisHash: bytes(fixture.identity.result.genesisHash),
        authorizationCapability: sdk.AUTHORIZATION_CAPABILITY,
      },
      fetch,
      clock,
      ...options,
    }),
    clock,
    calls,
    sends: () => calls.filter((r) => !Array.isArray(r)).length,
  };
}
const fixture = fixtures[0];
test("submission freezes canonical bytes/ID before preflight and sends exactly once after identity validation", async () => {
  const h = harness(fixture),
    canonical = bytes(fixture.canonical);
  const pending = h.client.submitTransaction(canonical);
  canonical.fill(0);
  const result = await pending;
  assert.equal(result.status, "reported-accepted");
  assert.equal(result.sendAttempts, 1);
  assert.equal(hex(result.transactionHash), fixture.transactionHash);
  assert.equal(h.sends(), 1);
  assert.equal(h.clock.tasks.size, 0);
  const wrong = harness(fixture, {
    mutate: (r) => {
      if (r.result?.chainId) r.result.chainId = "0x1";
    },
  });
  const rejected = await wrong.client.submitTransaction(bytes(fixture.canonical));
  assert.equal(rejected.status, "not-sent");
  assert.equal(rejected.diagnostic.code, "CHAIN_IDENTITY_MISMATCH");
  assert.equal(wrong.sends(), 0);
});
test("accepted-with-lost-response, malformed/wrong ID and node rejection never trigger write retries", async () => {
  for (const kind of ["lost", "bad-id", "malformed", "rejected"]) {
    const h = harness(fixture, {
      options: { maxRetries: 3 },
      send: (r) => {
        if (kind === "lost") throw new Error("private-node-url-secret");
        if (kind === "malformed") return new Response("broken");
        return new Response(
          JSON.stringify(
            kind === "bad-id"
              ? { jsonrpc: "2.0", id: r.id, result: `0x${"01".repeat(32)}` }
              : {
                  jsonrpc: "2.0",
                  id: r.id,
                  error: {
                    code: -32000,
                    message: "private-node-secret",
                    data: "private-data",
                  },
                },
          ),
        );
      },
    });
    const result = await h.client.submitTransaction(bytes(fixture.canonical));
    assert.equal(result.status, kind === "rejected" ? "reported-rejected" : "unknown");
    assert.equal(result.sendAttempts, 1);
    assert.equal(h.sends(), 1);
    assert.equal(JSON.stringify(result).includes("private"), false);
    const reconciled = await h.client.reconcileTransaction(bytes(fixture.canonical), {
      maxPolls: 1,
    });
    assert.equal(reconciled.status, "reported-finalized-success");
    assert.equal(h.sends(), 1);
  }
});
test("preabort/preflight failure cannot send; write abort/deadline retain uncertain consumption", async () => {
  const before = new AbortController();
  before.abort();
  const pre = harness(fixture);
  const notSent = await pre.client.submitTransaction(bytes(fixture.canonical), {
    signal: before.signal,
  });
  assert.equal(notSent.status, "not-sent");
  assert.equal(pre.calls.length, 0);
  for (const reason of ["abort", "timeout"]) {
    const controller = new AbortController(),
      h = harness(fixture, {
        options: { timeoutMs: 20 },
        send: () => new Promise(() => {}),
      });
    const pending = h.client.submitTransaction(bytes(fixture.canonical), {
      signal: controller.signal,
    });
    await flush();
    assert.equal(h.sends(), 1);
    if (reason === "abort") controller.abort("private-reason");
    else await h.clock.advance(20);
    const result = await pending;
    assert.equal(result.status, "unknown");
    assert.equal(result.sendAttempts, 1);
    assert.equal(h.clock.tasks.size, 0);
  }
});
test("native reconciliation preserves successful/failed finality, consumption and authority nonce without another send", async () => {
  assert.equal(
    record.revision,
    JSON.parse(readFileSync(new URL("../protocol-source.json", import.meta.url)))
      .revision,
  );
  for (const f of fixtures) {
    const h = harness(f);
    const result = await h.client.reconcileTransaction(bytes(f.canonical), {
      maxPolls: 1,
    });
    assert.equal(
      result.status,
      f.scenario.endsWith("failure")
        ? "reported-finalized-failure"
        : "reported-finalized-success",
      f.scenario,
    );
    assert.equal(result.verification, "node-observation");
    assert.equal(result.polls, 1);
    assert.equal(result.authority.authorityMatches, true);
    assert.equal(result.authority.comparison, "advanced");
    assert.equal(result.authority.observedNonce, result.authority.expectedNonce + 1n);
    if (result.authority.sponsor)
      assert.equal(
        result.authority.sponsor.observedNonce,
        result.authority.sponsor.expectedNonce + 1n,
      );
    assert.equal(h.sends(), 0);
    assert.equal(h.clock.tasks.size, 0);
  }
});
test("unknown/pruned/pending history and advanced nonce never authorize replay or claim inclusion", async () => {
  for (const pending of [false, true]) {
    const h = harness(fixture, {
      mutate: (r, request) => {
        if (request.method === "rsc_getTransactionReceipt") r.result = null;
        if (request.method === "rsc_getTransactionByHash") {
          if (!pending) r.result = null;
          else
            for (const field of ["blockHash", "blockNumber", "transactionIndex"])
              r.result[field] = null;
        }
      },
    });
    const result = await h.client.reconcileTransaction(bytes(fixture.canonical), {
      maxPolls: 1,
    });
    assert.equal(result.status, "unknown");
    assert.equal(result.reason, "poll-limit");
    assert.equal(result.lastObservation.status, "unknown");
    assert.equal(result.authority.comparison, "advanced");
    assert.equal(h.sends(), 0);
  }
  const pruned = harness(fixture, {
    mutate: (r, request) => {
      if (request.method === "rsc_getBlockByNumber") r.result = null;
    },
  });
  const unknown = await pruned.client.reconcileTransaction(bytes(fixture.canonical), {
    maxPolls: 1,
  });
  assert.equal(unknown.status, "unknown");
  assert.equal(unknown.lastObservation.status, "reported-included");
});
test("polling unknown to finalized repeats only reads and observes the finite poll interval", async () => {
  let missing = true;
  const h = harness(fixture, {
    mutate: (r, request) => {
      if (missing && request.method === "rsc_getTransactionReceipt") r.result = null;
      if (missing && request.method === "rsc_getTransactionByHash") r.result = null;
    },
  });
  const pending = h.client.reconcileTransaction(bytes(fixture.canonical), {
    maxPolls: 2,
    pollIntervalMs: 5,
    timeoutMs: 100,
  });
  await flush();
  missing = false;
  await h.clock.advance(5);
  const result = await pending;
  assert.equal(result.status, "reported-finalized-success");
  assert.equal(result.polls, 2);
  assert.equal(h.sends(), 0);
  assert(h.clock.delays.includes(5));
  assert.equal(h.clock.tasks.size, 0);
});
test("receipt/authority/block contradictions stay unknown with sanitized diagnostics", async () => {
  for (const mutation of [
    (r, request) => {
      if (request.method === "rsc_getBlockByNumber")
        r.result.hash = `0x${"01".repeat(32)}`;
    },
    (r, request) => {
      if (request.method === "rsc_getBlockByNumber") r.result.transactions = [];
    },
    (r, request) => {
      if (request.method === "rsc_getBlockByNumber") r.result.round = "4294967296";
    },
    (r, request) => {
      if (request.method === "rsc_getTransactionCount") r.result = "0x0";
    },
    (r, request) => {
      if (request.method === "rsc_getRootAuthority") r.result.state.height = "0x1";
    },
  ]) {
    const h = harness(fixture, {
      mutate: mutation,
      options: { maxContextRefreshes: 0 },
    });
    const result = await h.client.reconcileTransaction(bytes(fixture.canonical), {
      maxPolls: 1,
    });
    assert.equal(result.status, "unknown");
    assert.equal(result.reason, "observation-error");
    assert.equal(h.sends(), 0);
  }
});
test("reconciliation is bounded under ignored cancellation, deadline, exhausted polling and invalid options", async () => {
  const controller = new AbortController();
  controller.abort();
  const pre = harness(fixture);
  const result = await pre.client.reconcileTransaction(bytes(fixture.canonical), {
    signal: controller.signal,
  });
  assert.equal(result.reason, "aborted");
  assert.equal(result.polls, 0);
  assert.equal(pre.calls.length, 0);
  const stalled = harness(fixture, { fetch: () => new Promise(() => {}) });
  const pending = stalled.client.reconcileTransaction(bytes(fixture.canonical), {
    timeoutMs: 20,
  });
  await stalled.clock.advance(20);
  const timeout = await pending;
  assert.equal(timeout.reason, "deadline");
  assert.equal(stalled.clock.tasks.size, 0);
  for (const options of [
    { maxPolls: 0 },
    { maxPolls: 1001 },
    { timeoutMs: 0 },
    { timeoutMs: Infinity },
    { pollIntervalMs: 0 },
    { pollIntervalMs: 60001 },
  ]) {
    const h = harness(fixture);
    await assert.rejects(
      h.client.reconcileTransaction(bytes(fixture.canonical), options),
      (e) => e instanceof sdk.RpcContractError && e.code === "INVALID_ARGUMENT",
    );
    assert.equal(h.calls.length, 0);
  }
});

test(
  "actual HTTP lost write response reconciles the same native ID without hidden resubmission",
  { timeout: 10000 },
  async (t) => {
    const f = fixtures[0];
    let sends = 0;
    const errors = [];
    let recorded = null;
    const server = createServer(async (request, response) => {
      try {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (!Array.isArray(input)) {
          assert.equal(input.method, "rsc_sendRawTransaction");
          sends++;
          recorded = input.params[0];
          response.writeHead(200, {
            "Content-Length": "1000",
            "Content-Type": "application/json",
          });
          response.write('{"jsonrpc":"2.0",');
          response.socket.destroy();
          return;
        }
        const output = input.map((r) => {
          const key = {
            rsc_getAuthorizationFinalityStatus: "identity",
            rsc_getTransactionReceipt: "receipt",
            rsc_getTransactionByHash: "transaction",
            rsc_getRootAuthority: "root",
            rsc_getBlockByNumber: "block",
            rsc_getTransactionCount: "accountNonce",
          }[r.method];
          assert(key);
          const native = structuredClone(f[key]);
          native.id = r.id;
          return native;
        });
        response.setHeader("Content-Type", "application/json");
        response.end(JSON.stringify(output.reverse()));
      } catch (error) {
        errors.push(error);
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
      assert.deepEqual(errors, []);
    });
    const client = new sdk.ChainRpcClient({
      url: `http://127.0.0.1:${server.address().port}/`,
      expected: {
        chainId: 1337n,
        genesisHash: bytes(f.identity.result.genesisHash),
        authorizationCapability: sdk.AUTHORIZATION_CAPABILITY,
      },
      maxRetries: 3,
    });
    const submitted = await client.submitTransaction(bytes(f.canonical));
    assert.equal(submitted.status, "unknown");
    assert.equal(submitted.sendAttempts, 1);
    assert.equal(sends, 1);
    assert.equal(recorded, f.canonical);
    const reconciled = await client.reconcileTransaction(bytes(f.canonical), {
      maxPolls: 1,
    });
    assert.equal(reconciled.status, "reported-finalized-success");
    assert.equal(hex(reconciled.transactionHash), hex(submitted.transactionHash));
    assert.equal(sends, 1);
  },
);
test("request byte rejection stays not-sent and returned diagnostics never infer reusable nonces", async () => {
  const h = harness(fixture, { options: { maxRequestBytes: 256 } });
  const result = await h.client.submitTransaction(bytes(fixture.canonical));
  assert.equal(result.status, "not-sent");
  assert.equal(result.sendAttempts, 0);
  assert.equal(result.diagnostic.code, "REQUEST_LIMIT");
  assert.equal(h.sends(), 0);
  assert.equal(Object.hasOwn(result, "nonceReusable"), false);
});
test("revoked/stale authority is preserved explicitly and does not invent reusable nonce history", async () => {
  const f = fixtures.find((f) => f.scenario === "sessionTransfer-success");
  const h = harness(f, {
    mutate: (r, request) => {
      if (
        request.method === "rsc_getTransactionReceipt" ||
        request.method === "rsc_getTransactionByHash"
      )
        r.result = null;
      if (request.method === "rsc_getSessionGrant")
        r.result.usableAtObservedBlock = false;
      if (request.method === "rsc_getRootAuthority") {
        r.result.authority.authEpoch = "0x2";
        const canonical = bytes(r.result.authority.canonical);
        canonical[9] = 2;
        r.result.authority.canonical = hex(canonical);
      }
    },
  });
  const result = await h.client.reconcileTransaction(bytes(f.canonical), {
    maxPolls: 1,
  });
  assert.equal(result.status, "unknown");
  assert.equal(result.authority.authorityMatches, false);
  assert.equal(result.authority.comparison, "authority-changed");
  assert.equal(h.sends(), 0);
});
