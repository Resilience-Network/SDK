import assert from "node:assert/strict";
import { HttpRpcClient, RpcClientError } from "../dist/rpc/index.js";

export { HttpRpcClient, RpcClientError };
export const url = "https://rpc.example.invalid/";
export const encoder = new TextEncoder();

export async function flush() {
  for (let i = 0; i < 32; i++) await Promise.resolve();
}

export class FakeClock {
  time = 0;
  nextId = 1;
  tasks = new Map();
  delays = [];
  now = () => this.time;
  setTimeout = (callback, delay) => {
    const id = this.nextId++;
    this.tasks.set(id, { callback, at: this.time + delay });
    this.delays.push(delay);
    return id;
  };
  clearTimeout = (id) => this.tasks.delete(id);
  async advance(ms) {
    const end = this.time + ms;
    await flush();
    for (;;) {
      const next = [...this.tasks].sort((a, b) => a[1].at - b[1].at)[0];
      if (!next || next[1].at > end) break;
      const [id, task] = next;
      this.time = task.at;
      this.tasks.delete(id);
      task.callback();
      await flush();
    }
    this.time = end;
    await flush();
  }
}

export function envelope(id, result = "0x1") {
  return { jsonrpc: "2.0", id, result };
}

export function reply(request, result = "0x1") {
  return new Response(JSON.stringify(envelope(request.id, result)));
}

export function harness(responder, options = {}) {
  const clock = new FakeClock();
  const calls = [];
  const fetch = async (endpoint, init) => {
    const request = JSON.parse(init.body);
    calls.push({ endpoint, init, request });
    return responder(request, calls.length, init);
  };
  return {
    client: new HttpRpcClient({ url, fetch, clock, ...options }),
    clock,
    calls,
  };
}

export async function error(pending, code, attempts) {
  await assert.rejects(pending, (failure) => {
    assert(failure instanceof RpcClientError);
    assert.equal(failure.code, code);
    if (attempts !== undefined) {
      assert.equal(failure.attempts, attempts);
      assert.equal(failure.requestMayHaveReachedNode, attempts > 0);
    }
    return true;
  });
}

export function stream(parts, hooks = {}) {
  let at = 0;
  return new Response(
    new ReadableStream({
      pull(controller) {
        if (at < parts.length) controller.enqueue(parts[at++]);
        else if (!hooks.stall) controller.close();
      },
      cancel() {
        hooks.cancel?.();
      },
    }),
  );
}
