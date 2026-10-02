import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { gzipSync } from "node:zlib";
import { HttpRpcClient, envelope, error } from "./rpc-helpers.mjs";

// All servers bind a disposable OS-selected loopback port and own no wallet/node state.
async function server(t, handler) {
  const requests = [];
  const unexpected = [];
  const http = createServer(async (request, response) => {
    try {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      requests.push({ path: request.url, headers: request.headers, body });
      await handler(body, response, requests.length, request.url);
    } catch (failure) {
      // Client aborts can legitimately interrupt the request; handler bugs cannot.
      if (failure.code !== "ECONNRESET") unexpected.push(failure);
      response.destroy();
    }
  });
  await new Promise((resolve, reject) => {
    http.once("error", reject);
    http.listen(0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    http.closeAllConnections();
    await new Promise((resolve, reject) =>
      http.close((failure) => (failure ? reject(failure) : resolve())),
    );
    assert.deepEqual(unexpected, []);
  });
  return { url: `http://127.0.0.1:${http.address().port}/`, requests };
}

test(
  "RPC actual Node fetch sends canonical envelopes and maps out-of-order HTTP batches",
  { timeout: 10_000 },
  async (t) => {
    const http = await server(t, (body, response) => {
      const result = Array.isArray(body)
        ? body.map((call) => envelope(call.id, call.method)).reverse()
        : envelope(body.id, { params: body.params });
      response.setHeader("Content-Type", "application/json");
      response.end(JSON.stringify(result));
    });
    const client = new HttpRpcClient({ url: http.url });
    assert.deepEqual(await client.request("rsc_chainId", ["é😀"]), { params: ["é😀"] });
    assert.deepEqual(
      await client.batch([{ method: "rsc_chainId" }, { method: "rsc_blockNumber" }]),
      [
        { ok: true, result: "rsc_chainId" },
        { ok: true, result: "rsc_blockNumber" },
      ],
    );
    assert.equal(http.requests.length, 2);
    assert.equal(http.requests[0].headers["content-type"], "application/json");
    assert.equal(http.requests[0].headers.cookie, undefined);
  },
);

test(
  "RPC actual Node fetch retries read throttling and discards a malformed HTTP error body",
  { timeout: 10_000 },
  async (t) => {
    const http = await server(t, (body, response, at) => {
      if (at === 1) {
        response.writeHead(429, { "Retry-After": "0", "Content-Type": "text/plain" });
        response.end("not a JSON response");
      } else response.end(JSON.stringify(envelope(body.id)));
    });
    const client = new HttpRpcClient({ url: http.url, retryDelayMs: 1 });
    assert.equal(await client.request("rsc_chainId"), "0x1");
    assert.equal(http.requests.length, 2);
    assert.deepEqual(http.requests[0].body, http.requests[1].body);
  },
);

test(
  "RPC actual Node fetch retries a truncated read response but never a truncated submission",
  { timeout: 10_000 },
  async (t) => {
    for (const method of [
      "rsc_chainId",
      "rsc_sendRawTransaction",
      "eth_sendRawTransaction",
    ]) {
      const http = await server(t, (body, response, at) => {
        if (at === 1) {
          response.writeHead(200, { "Content-Length": "1000" });
          response.write('{"jsonrpc":"2.0",');
          response.end(); // Valid HTTP headers, deliberately incomplete body.
          response.socket?.destroy();
        } else response.end(JSON.stringify(envelope(body.id)));
      });
      const client = new HttpRpcClient({
        url: http.url,
        retryDelayMs: 1,
        maxRetries: 3,
      });
      if (method === "rsc_chainId") {
        assert.equal(await client.request(method), "0x1");
        assert.equal(http.requests.length, 2);
      } else {
        await error(client.request(method, ["0x00"]), "NETWORK_ERROR", 1);
        assert.equal(http.requests.length, 1);
      }
    }
  },
);

test(
  "RPC actual Node fetch bounds chunked and decompressed response bytes",
  { timeout: 10_000 },
  async (t) => {
    for (const compressed of [false, true]) {
      const http = await server(t, (body, response) => {
        const payload = Buffer.from(
          JSON.stringify(envelope(body.id, "x".repeat(10_000))),
        );
        if (compressed) {
          const gzip = gzipSync(payload);
          assert(gzip.length < 256);
          response.writeHead(200, {
            "Content-Encoding": "gzip",
            "Content-Length": gzip.length,
          });
          response.end(gzip);
        } else {
          response.write(payload.subarray(0, 100));
          response.end(payload.subarray(100));
        }
      });
      const client = new HttpRpcClient({ url: http.url, maxResponseBytes: 256 });
      await error(client.request("rsc_chainId"), "RESPONSE_LIMIT", 1);
      assert.equal(http.requests.length, 1);
    }
  },
);

test(
  "RPC actual Node fetch cannot follow a redirect that could replay a submitted transaction",
  { timeout: 10_000 },
  async (t) => {
    const http = await server(t, (body, response, _at, path) => {
      if (path === "/") {
        response.writeHead(307, { Location: "/replay" });
        response.end();
      } else response.end(JSON.stringify(envelope(body.id)));
    });
    const client = new HttpRpcClient({ url: http.url, maxRetries: 3 });
    await error(client.request("rsc_sendRawTransaction", ["0x00"]), "NETWORK_ERROR", 1);
    assert.deepEqual(
      http.requests.map((request) => request.path),
      ["/"],
    );
  },
);

test(
  "RPC actual Node fetch deadline aborts a stalled submission without replay",
  { timeout: 10_000 },
  async (t) => {
    let entered;
    const arrived = new Promise((resolve) => {
      entered = resolve;
    });
    const http = await server(t, (_body, response) => {
      response.writeHead(200);
      response.write('{"jsonrpc":"2.0",');
      entered(); // Deliberately leave the body open until the client aborts it.
    });
    const client = new HttpRpcClient({ url: http.url, timeoutMs: 500 });
    const failed = error(
      client.request("rsc_sendRawTransaction", ["0x00"]),
      "TIMEOUT",
      1,
    );
    await arrived;
    await failed;
    assert.equal(http.requests.length, 1);
  },
);

test(
  "RPC actual Node fetch caller abort interrupts a body read without cancelling another request",
  { timeout: 10_000 },
  async (t) => {
    let entered;
    const arrived = new Promise((resolve) => {
      entered = resolve;
    });
    const http = await server(t, (body, response) => {
      if (body.method === "custom_stall") {
        response.writeHead(200);
        response.write('{"jsonrpc":"2.0",');
        entered();
      } else response.end(JSON.stringify(envelope(body.id)));
    });
    const controller = new AbortController();
    const client = new HttpRpcClient({ url: http.url });
    const failed = error(
      client.request("custom_stall", [], { signal: controller.signal }),
      "ABORTED",
      1,
    );
    await arrived;
    assert.equal(await client.request("rsc_chainId"), "0x1");
    controller.abort();
    await failed;
    assert.equal(http.requests.length, 2);
  },
);
