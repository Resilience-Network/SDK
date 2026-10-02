import assert from "node:assert/strict";
import test from "node:test";
import { RETRYABLE_RPC_METHODS } from "../dist/rpc/index.js";
import {
  RpcClientError,
  encoder,
  envelope,
  error,
  flush,
  harness,
  reply,
  stream,
} from "./rpc-helpers.mjs";

test("RPC dependency exceptions cannot impersonate SDK diagnostics or leak payloads", async () => {
  for (const stage of ["fetch", "body"]) {
    const tainted = new RpcClientError("NODE_ERROR", 99, undefined, -32000);
    tainted.message = "secret-from-dependency";
    tainted.payload = "secret-from-dependency";
    const h = harness(
      () => {
        if (stage === "fetch") throw tainted;
        return new Response(
          new ReadableStream({
            start(controller) {
              controller.error(tainted);
            },
          }),
        );
      },
      { maxRetries: 0 },
    );
    await assert.rejects(h.client.request("rsc_chainId"), (failure) => {
      assert.equal(failure.code, "NETWORK_ERROR");
      assert.equal(failure.attempts, 1);
      assert.equal(failure.rpcCode, undefined);
      assert.equal(failure.message.includes("secret"), false);
      assert.equal(JSON.stringify(failure).includes("secret"), false);
      return true;
    });
  }
});

test("RPC pre-abort prevents dispatch and listener/timer ownership ends on completion", async () => {
  const controller = new AbortController();
  controller.abort("secret-reason");
  const h = harness((request) => reply(request));
  await error(
    h.client.request("rsc_chainId", [], { signal: controller.signal }),
    "ABORTED",
    0,
  );
  assert.equal(h.calls.length, 0);
  assert.equal(h.clock.tasks.size, 0);
  const active = new AbortController();
  let listeners = 0;
  const signal = {
    get aborted() {
      return active.signal.aborted;
    },
    addEventListener(...args) {
      listeners++;
      active.signal.addEventListener(...args);
    },
    removeEventListener(...args) {
      listeners--;
      active.signal.removeEventListener(...args);
    },
  };
  await h.client.request("rsc_chainId", [], { signal });
  assert.equal(listeners, 0);
  assert.equal(h.clock.tasks.size, 0);
});

test("RPC fake-clock deadline settles an ignored fetch abort and cancels a late response", async () => {
  let resolveFetch;
  let cancelled = 0;
  const h = harness(
    () =>
      new Promise((resolve) => {
        resolveFetch = resolve;
      }),
    { timeoutMs: 50 },
  );
  const failed = error(h.client.request("rsc_chainId"), "TIMEOUT", 1);
  await h.clock.advance(49);
  assert.equal(h.calls[0].init.signal.aborted, false);
  await h.clock.advance(1);
  await failed;
  assert.equal(h.calls[0].init.signal.aborted, true);
  assert.equal(h.calls.length, 1);
  assert.equal(h.clock.tasks.size, 0);
  resolveFetch(stream([], { stall: true, cancel: () => cancelled++ }));
  await flush();
  assert.equal(cancelled, 1);
});

test("RPC caller cancellation wins during fetch and does not expose a supplied abort reason", async () => {
  const controller = new AbortController();
  const h = harness(() => new Promise(() => {}));
  const failed = error(
    h.client.request("rsc_chainId", [], { signal: controller.signal }),
    "ABORTED",
    1,
  );
  controller.abort(new Error("secret-reason"));
  await failed;
  assert.equal(h.calls[0].init.signal.aborted, true);
  assert.equal(h.clock.tasks.size, 0);
});

test("RPC deadline and caller cancellation interrupt stalled body reads and release the reader", async () => {
  for (const cause of ["abort", "timeout"]) {
    let cancelled = 0;
    let response;
    const controller = new AbortController();
    const h = harness(
      () => {
        response = stream([encoder.encode('{"jsonrpc":"2.0",')], {
          stall: true,
          cancel: () => cancelled++,
        });
        return response;
      },
      { timeoutMs: 50 },
    );
    const failed = error(
      h.client.request("rsc_chainId", [], { signal: controller.signal }),
      cause === "abort" ? "ABORTED" : "TIMEOUT",
      1,
    );
    await flush();
    if (cause === "abort") controller.abort();
    else await h.clock.advance(50);
    await failed;
    assert.equal(cancelled, 1);
    assert.equal(response.body.locked, false);
    assert.equal(h.calls[0].init.signal.aborted, true);
    assert.equal(h.calls.length, 1);
    assert.equal(h.clock.tasks.size, 0);
  }
});

test("RPC read retries use bounded exponential delays and reuse frozen request bytes", async () => {
  const params = ["snapshot"];
  const h = harness(
    (request, at) => {
      if (at === 1) throw new Error("sensitive network diagnostic");
      if (at === 2) return new Response("busy", { status: 503 });
      return reply(request);
    },
    { retryDelayMs: 10, maxRetryDelayMs: 15, maxRetries: 2 },
  );
  const pending = h.client.request("rsc_chainId", params);
  params[0] = "mutated";
  await h.clock.advance(9);
  assert.equal(h.calls.length, 1);
  await h.clock.advance(1);
  assert.equal(h.calls.length, 2);
  await h.clock.advance(14);
  assert.equal(h.calls.length, 2);
  await h.clock.advance(1);
  assert.equal(await pending, "0x1");
  assert.equal(h.calls.length, 3);
  assert.equal(new Set(h.calls.map((call) => call.init.body)).size, 1);
  assert.deepEqual(h.calls[2].request.params, ["snapshot"]);
  assert.deepEqual(h.clock.delays, [10_000, 10, 15]);
  assert(h.calls.every((call) => call.init.signal.aborted));
  assert.equal(h.clock.tasks.size, 0);
});

test("RPC exhausted network and retryable HTTP failures expose attempt counts with redacted diagnostics", async () => {
  for (const status of [null, 429, 502, 503, 504]) {
    const h = harness(
      () => {
        if (status === null) throw new Error("secret-exception");
        return new Response("secret-body", { status, headers: { "Retry-After": "0" } });
      },
      { retryDelayMs: 10, maxRetries: 2 },
    );
    const failed = error(
      h.client.request("rsc_chainId"),
      status === null ? "NETWORK_ERROR" : "HTTP_ERROR",
      3,
    );
    await h.clock.advance(30);
    await failed;
    assert.equal(h.calls.length, 3);
    assert.equal(h.clock.tasks.size, 0);
  }
  const h = harness(
    () =>
      new Response("secret-body", {
        status: 429,
        headers: { "Retry-After": "secret-header" },
      }),
  );
  await assert.rejects(h.client.request("rsc_chainId"), (failure) => {
    assert.equal(failure.httpStatus, 429);
    assert.equal(failure.kind, "http");
    assert.equal(JSON.stringify(failure).includes("secret"), false);
    assert.equal(failure.stack.includes("secret"), false);
    return true;
  });
  assert.equal(h.calls.length, 1);
});

test("RPC honors bounded numeric Retry-After and avoids oversized, date and invalid hints", async () => {
  const h = harness(
    (request, at) =>
      at === 1
        ? new Response("busy", { status: 429, headers: { "Retry-After": "1" } })
        : reply(request),
    { retryDelayMs: 10 },
  );
  const pending = h.client.request("rsc_chainId");
  await h.clock.advance(999);
  assert.equal(h.calls.length, 1);
  await h.clock.advance(1);
  assert.equal(await pending, "0x1");
  for (const hint of [
    "2",
    "-1",
    "0.5",
    "invalid",
    "Wed, 21 Oct 2030 07:28:00 GMT",
    "9".repeat(100),
  ]) {
    const bounded = harness(
      () => new Response(null, { status: 429, headers: { "Retry-After": hint } }),
    );
    await error(bounded.client.request("rsc_chainId"), "HTTP_ERROR", 1);
    assert.equal(bounded.calls.length, 1);
  }
});

test("RPC non-retryable HTTP statuses are separate from JSON parsing and discard bodies", async () => {
  for (const status of [301, 307, 400, 401, 403, 404, 413, 500]) {
    let cancelled = 0;
    const h = harness(
      () =>
        new Response(
          new ReadableStream({
            cancel() {
              cancelled++;
            },
          }),
          { status },
        ),
    );
    await error(h.client.request("rsc_chainId"), "HTTP_ERROR", 1);
    assert.equal(cancelled, 1);
    assert.equal(h.calls.length, 1);
  }
});

test("RPC retries interrupted body reads for allowlisted reads and consumes late rejections", async () => {
  const h = harness(
    (request, at) => {
      if (at !== 1) return reply(request);
      return new Response(
        new ReadableStream({
          start(controller) {
            controller.error(new Error("secret-disconnect"));
          },
        }),
      );
    },
    { retryDelayMs: 10 },
  );
  const pending = h.client.request("rsc_chainId");
  await h.clock.advance(10);
  assert.equal(await pending, "0x1");
  assert.equal(h.calls.length, 2);
  let rejectFetch;
  const stalled = harness(
    () =>
      new Promise((_, reject) => {
        rejectFetch = reject;
      }),
    { timeoutMs: 10 },
  );
  const failed = error(stalled.client.request("rsc_chainId"), "TIMEOUT", 1);
  await stalled.clock.advance(10);
  await failed;
  rejectFetch(new Error("late-failure"));
  await flush(); // node:test also fails on an unhandled rejection.
});

test("RPC overall deadline includes backoff and does not start another attempt after expiry", async () => {
  const h = harness(() => new Response("busy", { status: 503 }), {
    timeoutMs: 25,
    retryDelayMs: 10,
  });
  const failed = error(h.client.request("rsc_chainId"), "TIMEOUT", 2);
  await h.clock.advance(25);
  await failed;
  assert.equal(h.calls.length, 2);
  assert.equal(h.clock.tasks.size, 0);
  const controller = new AbortController();
  const cancelled = harness(() => new Response("busy", { status: 429 }));
  const aborted = error(
    cancelled.client.request("rsc_chainId", [], { signal: controller.signal }),
    "ABORTED",
    1,
  );
  await flush();
  controller.abort();
  await aborted;
  await cancelled.clock.advance(1_000);
  assert.equal(cancelled.calls.length, 1);
  assert.equal(cancelled.clock.tasks.size, 0);
});

test("RPC elapsed monotonic deadline is enforced even when a timer callback is delayed", async () => {
  const h = harness(
    (request) => {
      h.clock.time = 51; // Simulate a long synchronous phase delaying timer delivery.
      return reply(request);
    },
    { timeoutMs: 50 },
  );
  await error(h.client.request("rsc_chainId"), "TIMEOUT", 1);
  assert.equal(h.calls.length, 1);
  assert.equal(h.clock.tasks.size, 0);
});

test("RPC sends, unknown methods and mixed batches never automatically replay", async () => {
  assert(Object.isFrozen(RETRYABLE_RPC_METHODS));
  for (const method of [
    "rsc_sendRawTransaction",
    "eth_sendRawTransaction",
    "custom_write",
    "eth_subscribe",
    "rsc_simulateAuthorizedTransaction",
  ])
    assert.equal(RETRYABLE_RPC_METHODS.includes(method), false);
  for (const method of [
    "rsc_sendRawTransaction",
    "eth_sendRawTransaction",
    "custom_write",
  ]) {
    for (const failure of ["fetch", "body", "http"]) {
      const h = harness(
        () => {
          if (failure === "fetch") throw new Error("connection lost");
          if (failure === "http") return new Response("busy", { status: 503 });
          return new Response(
            new ReadableStream({
              start(controller) {
                controller.error(new Error("disconnect"));
              },
            }),
          );
        },
        { maxRetries: 3 },
      );
      await error(
        h.client.request(method, ["signed-public-transaction"]),
        failure === "http" ? "HTTP_ERROR" : "NETWORK_ERROR",
        1,
      );
      assert.equal(h.calls.length, 1);
      assert.deepEqual(h.clock.delays, [10_000]);
    }
  }
  const mixed = harness(() => new Response("busy", { status: 429 }));
  await error(
    mixed.client.batch([
      { method: "rsc_chainId" },
      { method: "rsc_sendRawTransaction", params: ["0x00"] },
    ]),
    "HTTP_ERROR",
    1,
  );
  assert.equal(mixed.calls.length, 1);
});

test("RPC wholly allowlisted batches retry as one frozen request and maxRetries zero disables retries", async () => {
  const h = harness(
    (requests, at) =>
      at === 1
        ? new Response("busy", { status: 503 })
        : new Response(
            JSON.stringify(requests.map((request) => envelope(request.id)).reverse()),
          ),
    { retryDelayMs: 10 },
  );
  const pending = h.client.batch([
    { method: "rsc_chainId" },
    { method: "rsc_getRootAuthority", params: ["0x00"] },
  ]);
  await h.clock.advance(10);
  assert.deepEqual(await pending, [
    { ok: true, result: "0x1" },
    { ok: true, result: "0x1" },
  ]);
  assert.equal(h.calls[0].init.body, h.calls[1].init.body);
  const disabled = harness(
    () => {
      throw new Error("lost");
    },
    { maxRetries: 0 },
  );
  await error(disabled.client.request("rsc_chainId"), "NETWORK_ERROR", 1);
  assert.equal(disabled.calls.length, 1);
});
