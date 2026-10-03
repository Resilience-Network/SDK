import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import test from "node:test";
import { HttpRpcClient, RpcClientError, error } from "./rpc-helpers.mjs";

const record = JSON.parse(
  readFileSync(new URL("./fixtures/rpc-envelopes.json", import.meta.url)),
);
const pin = JSON.parse(
  readFileSync(new URL("../protocol-source.json", import.meta.url)),
);

// Replay native production output through actual HTTP; only bind fresh client IDs.
// This qualifies envelope interoperability, not an authenticated live node.
async function replay(t, fixture, mutate = () => {}, reverse = false) {
  let calls = 0;
  const failures = [];
  const server = createServer(async (request, response) => {
    try {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const incoming = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      calls++;
      const nativeRequests = Array.isArray(fixture.request)
        ? fixture.request
        : [fixture.request];
      const requests = Array.isArray(incoming) ? incoming : [incoming];
      assert.equal(requests.length, nativeRequests.length);
      const ids = new Map(
        nativeRequests.map((native, at) => {
          assert.equal(requests[at].method, native.method);
          assert.deepEqual(requests[at].params, native.params);
          return [native.id, requests[at].id];
        }),
      );
      const output = structuredClone(fixture.response);
      const responses = Array.isArray(output) ? output : [output];
      for (const item of responses) {
        assert(ids.has(item.id));
        item.id = ids.get(item.id);
      }
      mutate(responses);
      if (Array.isArray(output) && reverse) output.reverse();
      response.setHeader("Content-Type", "application/json");
      response.end(JSON.stringify(output));
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
      server.close((failure) => (failure ? reject(failure) : resolve())),
    );
    assert.deepEqual(failures, []);
  });
  const client = new HttpRpcClient({
    url: `http://127.0.0.1:${server.address().port}/`,
    maxRetries: 0,
  });
  const invoke = () =>
    Array.isArray(fixture.request)
      ? client.batch(fixture.request.map(({ method, params }) => ({ method, params })))
      : client.request(fixture.request.method, fixture.request.params);
  return { invoke, calls: () => calls };
}

test("native RPC envelope provenance matches pin and public absent lookups explicitly carry null", () => {
  assert.equal(record.revision, pin.revision);
  assert.equal(record.envelopes.length, 19);
  for (const fixture of record.envelopes) {
    for (const response of Array.isArray(fixture.response)
      ? fixture.response
      : [fixture.response]) {
      assert.equal(response.jsonrpc, "2.0");
      assert(Object.hasOwn(response, "id"));
      assert.notEqual(
        Object.hasOwn(response, "result"),
        Object.hasOwn(response, "error"),
      );
    }
    if (fixture.scenario.endsWith("-absent")) {
      assert.equal(fixture.source, "public-api");
      assert.equal(fixture.response.result, null);
    }
  }
});

test(
  "actual Node fetch accepts every native single/batch null, error and falsy response",
  { timeout: 20_000 },
  async (t) => {
    for (const fixture of record.envelopes) {
      const http = await replay(t, fixture, undefined, true);
      if (Array.isArray(fixture.request)) {
        const results = await http.invoke();
        for (const [at, expected] of fixture.response.entries()) {
          if (Object.hasOwn(expected, "result"))
            assert.deepEqual(results[at], { ok: true, result: expected.result });
          else {
            assert.equal(results[at].ok, false);
            assert(results[at].error instanceof RpcClientError);
            assert.equal(results[at].error.code, "NODE_ERROR");
            assert.equal(results[at].error.rpcCode, expected.error.code);
          }
        }
      } else if (Object.hasOwn(fixture.response, "result"))
        assert.deepEqual(await http.invoke(), fixture.response.result);
      else
        await assert.rejects(
          http.invoke(),
          (failure) =>
            failure instanceof RpcClientError &&
            failure.code === "NODE_ERROR" &&
            failure.rpcCode === fixture.response.error.code,
        );
      assert.equal(http.calls(), 1);
    }
  },
);

test(
  "native envelopes fail closed under omitted results, ambiguous outcomes and mismatched IDs without replay",
  { timeout: 20_000 },
  async (t) => {
    const single = record.envelopes.find(
      (f) => f.scenario === "rsc_getTransactionReceipt-absent",
    );
    const batch = record.envelopes.find((f) => f.scenario === "mixed-public-batch");
    for (const fixture of [single, batch]) {
      for (const mutation of [
        (items) => {
          delete items[0].result;
        },
        (items) => {
          items[0].error = { code: -32000, message: "untrusted" };
        },
        (items) => {
          items[0].id = "wrong";
        },
      ]) {
        const http = await replay(t, fixture, mutation);
        await error(http.invoke(), "INVALID_RESPONSE", 1);
        assert.equal(http.calls(), 1);
      }
    }
  },
);
