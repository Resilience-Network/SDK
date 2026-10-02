import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";
import {
  HttpRpcClient,
  RpcClientError,
  encoder,
  envelope,
  error,
  harness,
  reply,
  stream,
  url,
} from "./rpc-helpers.mjs";

test("RPC single requests own JSON bytes, use unique IDs and preserve null/false/zero results", async () => {
  const values = [null, false, 0, "", { nested: ["é", true] }];
  const h = harness((request, at) => reply(request, values[at - 1]));
  const params = [{ name: "before" }];
  const pending = h.client.request("rsc_chainId", params);
  params[0].name = "after";
  assert.equal(await pending, null);
  for (const expected of values.slice(1))
    assert.deepEqual(await h.client.request("rsc_chainId"), expected);
  assert.deepEqual(h.calls[0].request.params, [{ name: "before" }]);
  assert.deepEqual(
    h.calls.map((call) => call.request.id),
    [1, 2, 3, 4, 5],
  );
  assert.equal(h.clock.tasks.size, 0);
  const { init, endpoint } = h.calls[0];
  assert.equal(endpoint, url);
  assert.equal(init.method, "POST");
  assert.equal(init.redirect, "error");
  assert.equal(init.credentials, "omit");
  assert.equal(init.cache, "no-store");
  assert.equal(init.referrerPolicy, "no-referrer");
  assert.equal(init.headers["Content-Type"], "application/json");
});

test("RPC batches restore caller order and retain partial node errors after full validation", async () => {
  const h = harness(
    (requests) =>
      new Response(
        JSON.stringify([
          envelope(requests[2].id, "third"),
          {
            jsonrpc: "2.0",
            id: requests[1].id,
            error: { code: -32000, message: "secret", data: "secret" },
          },
          envelope(requests[0].id, "first"),
        ]),
      ),
  );
  const results = await h.client.batch(
    Array.from({ length: 3 }, () => ({ method: "rsc_chainId" })),
  );
  assert.deepEqual(results[0], { ok: true, result: "first" });
  assert.equal(results[1].ok, false);
  assert(results[1].error instanceof RpcClientError);
  assert.equal(results[1].error.rpcCode, -32000);
  assert.equal(results[1].error.attempts, 1);
  assert.equal(JSON.stringify(results).includes("secret"), false);
  assert.deepEqual(results[2], { ok: true, result: "third" });
  assert.equal(h.calls.length, 1);
});

test("RPC concurrent requests get independent IDs and cancellation scopes", async () => {
  const resolvers = [];
  const h = harness(
    (request) =>
      new Promise((resolve) =>
        resolvers.push(() => resolve(reply(request, request.id))),
      ),
  );
  const first = h.client.request("rsc_chainId");
  const second = h.client.request("rsc_chainId");
  resolvers[1]();
  assert.equal(await second, 2);
  resolvers[0]();
  assert.equal(await first, 1);
  assert.equal(h.clock.tasks.size, 0);
});

test("RPC malformed envelopes fail without retries or partial batch results", async () => {
  const invalid = [
    null,
    true,
    [],
    {},
    { jsonrpc: "1.0", id: 1, result: 1 },
    { jsonrpc: "2.0", id: "1", result: 1 },
    { jsonrpc: "2.0", id: 2, result: 1 },
    { jsonrpc: "2.0", result: 1 },
    { jsonrpc: "2.0", id: null, result: 1 },
    { jsonrpc: "2.0", id: 1 }, // Pinned node's omitted nil result is not null.
    { jsonrpc: "2.0", id: 1, result: 1, error: null },
    { jsonrpc: "2.0", id: 1, error: null },
    { jsonrpc: "2.0", id: 1, error: {} },
    { jsonrpc: "2.0", id: 1, error: { code: "-32000", message: "bad" } },
    { jsonrpc: "2.0", id: 1, error: { code: -1.5, message: "bad" } },
    { jsonrpc: "2.0", id: 1, error: { code: -32000, message: 1 } },
  ];
  for (const value of invalid) {
    const h = harness(() => new Response(JSON.stringify(value)));
    await error(h.client.request("rsc_chainId"), "INVALID_RESPONSE", 1);
    assert.equal(h.calls.length, 1);
    assert.equal(h.clock.tasks.size, 0);
  }
  for (const value of [
    envelope(1),
    [],
    [envelope(1)],
    [envelope(1), envelope(1)],
    [envelope(1), envelope(3)],
    [envelope(1), envelope(2), envelope(3)],
    [envelope(1), { jsonrpc: "2.0", id: 2 }],
  ]) {
    const h = harness(() => new Response(JSON.stringify(value)));
    await error(
      h.client.batch([{ method: "rsc_chainId" }, { method: "rsc_blockNumber" }]),
      "INVALID_RESPONSE",
      1,
    );
    assert.equal(h.calls.length, 1);
  }
});

test("RPC node errors are typed and redact remote messages/data rather than triggering retries", async () => {
  const secret = "private-wallet-material";
  const h = harness(
    (request) =>
      new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: request.id,
          error: { code: -32602, message: secret, data: { secret } },
        }),
      ),
  );
  await assert.rejects(h.client.request("rsc_chainId", [secret]), (failure) => {
    assert.equal(failure.kind, "node");
    assert.equal(failure.rpcCode, -32602);
    assert.equal(failure.code, "NODE_ERROR");
    assert.equal(failure.message.includes(secret), false);
    assert.equal(failure.stack.includes(secret), false);
    assert.equal(JSON.stringify(failure).includes(secret), false);
    assert.equal("cause" in failure, false);
    return true;
  });
  assert.equal(h.calls.length, 1);
});

test("RPC strict JSON rejects duplicate escaped keys, malformed tokens, unsafe numbers and invalid UTF-8", async () => {
  const invalid = [
    "",
    " ",
    "not-json",
    "null garbage",
    "\ufeff{}",
    '{"jsonrpc":"2.0","id":1,"result":1,}',
    '{"jsonrpc":"2.0","id":1,"result":[1,]}',
    '{"jsonrpc":"2.0","id":1,"result":01}',
    '{"jsonrpc":"2.0","id":1,"result":+1}',
    '{"jsonrpc":"2.0","id":1,"result":1.}',
    '{"jsonrpc":"2.0","id":1,"result":1e}',
    '{"jsonrpc":"2.0","id":1,"result":1e309}',
    '{"jsonrpc":"2.0","id":1,"result":9007199254740993}',
    '{"jsonrpc":"2.0","id":1,"result":"\\x00"}',
    '{"jsonrpc":"2.0","id":1,"result":"unterminated}',
    '{"jsonrpc":"2.0","id":1,"id":2,"result":1}',
    '{"jsonrpc":"2.0","id":1,"\\u0069d":1,"result":1}',
    '{"jsonrpc":"2.0","id":1,"result":{"nested":1,"nested":2}}',
    Uint8Array.of(0xc3, 0x28),
  ];
  for (const value of invalid) {
    const h = harness(() => new Response(value));
    await error(h.client.request("rsc_chainId"), "INVALID_JSON", 1);
    assert.equal(h.calls.length, 1);
  }
});

test("RPC JSON parser agrees with independently generated valid JSON and does not pollute prototypes", async () => {
  const values = [
    -Number.MAX_SAFE_INTEGER,
    Number.MAX_SAFE_INTEGER,
    -0,
    1.25,
    -1e-30,
    'quote: " \\ \n \t \u0000 😀',
    { a: 1, b: [true, null, { c: "\ud800" }] },
    JSON.parse('{"__proto__":{"rpcPolluted":true},"constructor":{"prototype":1}}'),
  ];
  let seed = 0x14c0ffee;
  const random = () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed;
  };
  const generate = (depth) => {
    switch (random() % (depth > 4 ? 4 : 6)) {
      case 0:
        return null;
      case 1:
        return random() % 2 === 0;
      case 2:
        return (random() - 0x80000000) / 4;
      case 3:
        return `seed-${random()}-\\\"-😀`;
      case 4:
        return Array.from({ length: random() % 4 }, () => generate(depth + 1));
      default:
        return Object.fromEntries(
          Array.from({ length: random() % 4 }, (_, i) => [
            `k${i}`,
            generate(depth + 1),
          ]),
        );
    }
  };
  for (let i = 0; i < 200; i++) values.push(generate(0));
  for (const result of values) {
    const h = harness((request) => reply(request, result));
    assert.deepEqual(
      await h.client.request("custom_read", [result]),
      JSON.parse(JSON.stringify(result)),
    );
  }
  assert.equal({}.rpcPolluted, undefined);
});

test("RPC request byte limits measure UTF-8, allow the exact boundary and reject before dispatch", async () => {
  const params = ["é😀"];
  const expected = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "rsc_chainId",
    params,
  });
  const bytes = encoder.encode(expected).length;
  assert(bytes > expected.length);
  const valid = harness((request) => reply(request), { maxRequestBytes: bytes });
  await valid.client.request("rsc_chainId", params);
  const invalid = harness((request) => reply(request), { maxRequestBytes: bytes - 1 });
  await error(invalid.client.request("rsc_chainId", params), "REQUEST_LIMIT", 0);
  assert.equal(invalid.calls.length, 0);
});

test("RPC seeded JSON mutations and every truncation either reject or match the native JSON parser", async () => {
  const original = JSON.stringify(
    envelope(1, {
      text: 'quoted " \\ 😀',
      nested: [null, true, -1.5, { key: "value" }],
    }),
  );
  const cases = Array.from({ length: original.length }, (_, at) =>
    original.slice(0, at),
  );
  cases.push(original, '{"jsonrpc":"2.0","id":1,"result":-0}');
  let seed = 0x14badbee;
  const random = () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed;
  };
  const alphabet = '{}[],:"\\0123456789eE+- abcdef\n';
  for (let i = 0; i < 300; i++) {
    const at = random() % original.length;
    const replacement = alphabet[random() % alphabet.length];
    cases.push(original.slice(0, at) + replacement + original.slice(at + 1));
  }
  let accepted = 0;
  let rejected = 0;
  for (const raw of cases) {
    // Mutating half an emoji can create a lone UTF-16 surrogate. Compare the
    // actual encoded wire bytes, whose UTF-8 replacement is defined by Fetch.
    const body = encoder.encode(raw);
    const h = harness(() => new Response(body));
    let result;
    try {
      result = await h.client.request("rsc_chainId");
    } catch (failure) {
      assert(failure instanceof RpcClientError);
      assert(["INVALID_JSON", "INVALID_RESPONSE"].includes(failure.code));
      rejected++;
      assert.equal(h.calls.length, 1);
      assert.equal(h.clock.tasks.size, 0);
      continue;
    }
    const independentlyParsed = JSON.parse(new TextDecoder().decode(body));
    assert.deepEqual(result, independentlyParsed.result, `seed 0x14badbee: ${raw}`);
    accepted++;
    assert.equal(h.calls.length, 1);
    assert.equal(h.clock.tasks.size, 0);
  }
  assert(accepted > 0);
  assert(rejected >= original.length);
});

test("RPC growing response buffers preserve large multichunk data within the exact byte cap", async () => {
  const result = "é😀".repeat(8_000);
  const body = encoder.encode(JSON.stringify(envelope(1, result)));
  const parts = [];
  for (let at = 0; at < body.length; at += 997) parts.push(body.subarray(at, at + 997));
  const h = harness(() => stream(parts), { maxResponseBytes: body.length });
  assert.equal(await h.client.request("rsc_chainId"), result);
  const exceeded = harness(() => stream(parts), { maxResponseBytes: body.length - 1 });
  await error(exceeded.client.request("rsc_chainId"), "RESPONSE_LIMIT", 1);
});

test("RPC protocol validation rejects locked bodies and streams with non-byte chunks", async () => {
  const locked = harness(() => {
    const response = new Response("{}");
    const reader = response.body.getReader();
    void reader.cancel();
    return response;
  });
  await error(locked.client.request("rsc_chainId"), "INVALID_RESPONSE", 1);
  let cancelled = 0;
  const badChunk = harness(
    () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue("invalid stream chunk");
          },
          cancel() {
            cancelled++;
          },
        }),
      ),
  );
  await error(badChunk.client.request("rsc_chainId"), "INVALID_RESPONSE", 1);
  assert.equal(cancelled, 1);
  assert.equal(badChunk.calls.length, 1);
});

test("RPC rejects lossy/non-JSON params, holes, cycles and hooks without invoking them", async () => {
  const cyclic = [];
  cyclic.push(cyclic);
  let hooks = 0;
  const getter = Object.defineProperty({}, "secret", {
    enumerable: true,
    get() {
      hooks++;
      return 1;
    },
  });
  const withHook = {
    toJSON() {
      hooks++;
      return "secret";
    },
  };
  const symbol = { [Symbol("hidden")]: 1 };
  for (const params of [
    null,
    false,
    "[]",
    [undefined],
    [1n],
    [NaN],
    [Infinity],
    [2 ** 53],
    [new Date()],
    [new Uint8Array(1)],
    Array(1),
    cyclic,
    [getter],
    [withHook],
    [symbol],
    [() => 1],
    Object.defineProperty({}, "hidden", { value: 1 }),
  ]) {
    const h = harness((request) => reply(request));
    await error(h.client.request("rsc_chainId", params), "INVALID_REQUEST", 0);
    assert.equal(h.calls.length, 0);
  }
  const h = harness((request) => reply(request));
  await error(
    h.client.batch([
      {
        get method() {
          hooks++;
          return "rsc_chainId";
        },
      },
    ]),
    "INVALID_REQUEST",
    0,
  );
  assert.equal(hooks, 0);
  for (const method of ["", "rpc.hidden", "a".repeat(129), "rsc chainId", 1])
    await error(h.client.request(method), "INVALID_REQUEST", 0);
  await error(
    h.client.request("rsc_chainId", [], { signal: {} }),
    "INVALID_REQUEST",
    0,
  );
});

test("RPC transport limits cap batch size, structural depth and JSON node count", async () => {
  const h = harness(
    (requests) =>
      new Response(JSON.stringify(requests.map((request) => envelope(request.id)))),
  );
  assert.equal(
    (
      await h.client.batch(
        Array.from({ length: 32 }, () => ({ method: "rsc_chainId" })),
      )
    ).length,
    32,
  );
  for (const calls of [
    [],
    Array.from({ length: 33 }, () => ({ method: "rsc_chainId" })),
  ])
    await error(h.client.batch(calls), "REQUEST_LIMIT", 0);
  const small = harness(
    () => {
      throw new Error("must not send");
    },
    { maxBatchSize: 1 },
  );
  await error(
    small.client.batch([{ method: "rsc_chainId" }, { method: "rsc_chainId" }]),
    "REQUEST_LIMIT",
    0,
  );
  let deep = 1;
  for (let i = 0; i < 70; i++) deep = [deep];
  await error(h.client.request("rsc_chainId", [deep]), "REQUEST_LIMIT", 0);
  const wide = Array(100_000).fill(0);
  await error(h.client.request("rsc_chainId", wide), "REQUEST_LIMIT", 0);
  for (const result of [deep, wide]) {
    const bounded = harness((request) => reply(request, result));
    await error(bounded.client.request("rsc_chainId"), "RESPONSE_LIMIT", 1);
  }
});

test("RPC streams enforce actual bytes even with absent/lying Content-Length and cancel excess bodies", async () => {
  const body = encoder.encode(JSON.stringify(envelope(1, "é😀")));
  const valid = harness(() => stream(Array.from(body, (byte) => Uint8Array.of(byte))), {
    maxResponseBytes: body.length,
  });
  assert.equal(await valid.client.request("rsc_chainId"), "é😀");
  for (const declared of [null, "1", String(body.length)]) {
    let cancelled = 0;
    const h = harness(
      () => {
        const response = stream([body], { stall: true, cancel: () => cancelled++ });
        if (declared !== null) response.headers.set("Content-Length", declared);
        return response;
      },
      { maxResponseBytes: body.length - 1 },
    );
    await error(h.client.request("rsc_chainId"), "RESPONSE_LIMIT", 1);
    assert.equal(cancelled, 1);
    assert.equal(h.calls.length, 1);
    assert.equal(h.clock.tasks.size, 0);
  }
  const h = harness(() => new Response(null, { status: 204 }));
  await error(h.client.request("rsc_chainId"), "INVALID_RESPONSE", 1);
});

test("RPC chunk-count limit terminates a zero-byte stream without needing a cooperative producer", async () => {
  let cancelled = 0;
  const h = harness(
    () =>
      new Response(
        new ReadableStream({
          pull(controller) {
            controller.enqueue(new Uint8Array());
          },
          cancel() {
            cancelled++;
          },
        }),
      ),
  );
  await error(h.client.request("rsc_chainId"), "RESPONSE_LIMIT", 1);
  assert.equal(cancelled, 1);
});

test("RPC options reject unsupported URLs, embedded credentials and out-of-range limits", () => {
  for (const endpoint of [
    "invalid",
    "file:///tmp/rpc",
    "ftp://rpc.test",
    "https://user:secret@rpc.test",
    "https://rpc.test/?token=secret",
    "https://rpc.test/#fragment",
  ])
    assert.throws(
      () => new HttpRpcClient({ url: endpoint }),
      (failure) =>
        failure.code === "INVALID_OPTIONS" && !failure.message.includes("secret"),
    );
  for (const [key, values] of Object.entries({
    timeoutMs: [0, -1, 120_001, NaN, Infinity, 1.5, null, "100"],
    maxRequestBytes: [0, (2 << 20) + 1],
    maxResponseBytes: [0, (16 << 20) + 1],
    maxBatchSize: [0, 33],
    maxRetries: [-1, 4],
    retryDelayMs: [0, 5_001],
    maxRetryDelayMs: [0, 5_001],
  }))
    for (const value of values)
      assert.throws(
        () => new HttpRpcClient({ url, [key]: value }),
        (failure) => failure.code === "INVALID_OPTIONS",
      );
  assert.throws(
    () => new HttpRpcClient({ url, retryDelayMs: 101, maxRetryDelayMs: 100 }),
  );
  assert.throws(() => new HttpRpcClient({ url, fetch: 1 }));
  assert.throws(() => new HttpRpcClient({ url, fetch: null }));
  assert.throws(() => new HttpRpcClient({ url, clock: {} }));
});

test("RPC and core/root imports require no browser state or global fetch at module load", () => {
  const source = `
    import assert from "node:assert/strict";
    globalThis.fetch = undefined;
    for (const key of ["window", "navigator", "document"])
      Object.defineProperty(globalThis, key, { configurable: true, get() { throw new Error("Browser state accessed: " + key); } });
    const root = await import(${JSON.stringify(new URL("../dist/index.js", import.meta.url).href)});
    const core = await import(${JSON.stringify(new URL("../dist/core/index.js", import.meta.url).href)});
    const rpc = await import(${JSON.stringify(new URL("../dist/rpc/index.js", import.meta.url).href)});
    assert.equal(root.HttpRpcClient, rpc.HttpRpcClient);
    assert.equal(core.encodeUint64(1n).length, 8);
    assert.throws(() => new rpc.HttpRpcClient({ url: "https://rpc.example.invalid" }), (error) => error.code === "INVALID_OPTIONS");
    const client = new rpc.HttpRpcClient({ url: "https://rpc.example.invalid", fetch: async (_url, init) => new Response(JSON.stringify({ jsonrpc: "2.0", id: JSON.parse(init.body).id, result: 1 })) });
    assert.equal(await client.request("rsc_chainId"), 1);
  `;
  execFileSync(process.execPath, ["--input-type=module", "-e", source], {
    stdio: "pipe",
  });
});
