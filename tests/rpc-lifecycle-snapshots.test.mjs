import assert from "node:assert/strict";
import test from "node:test";
import { hexToBytes, RpcContractError } from "../dist/index.js";
import { findFixture, methodHarness } from "./rpc-methods-helpers.mjs";
const code = (c) => (e) => e instanceof RpcContractError && e.code === c;
test("native account/grant funding snapshots bracket scalar reads and decode u64/u256 precisely", async () => {
  for (const scenario of ["direct", "ed25519", "p256"]) {
    const f = findFixture(scenario, "rsc_getRootAuthority"),
      owner = hexToBytes(f.params[0]),
      h = methodHarness(f);
    const result = await h.client.getAccountAuthorizationSnapshot(owner);
    assert.equal(result.root.authorizationMode, scenario === "direct" ? 0 : 1);
    assert.equal(result.accountNonce, scenario === "direct" ? 0n : 1n);
    assert.equal(
      result.balance,
      BigInt(findFixture(scenario, "rsc_getBalance").response.result),
    );
    assert.equal(h.calls.length, 1);
    assert.equal(h.calls[0].requests.length, 5);
    assert.equal(h.clock.tasks.size, 0);
    if (scenario !== "direct") {
      const gf = findFixture(scenario, "rsc_getSessionGrant"),
        g = methodHarness(gf);
      const funded = await g.client.getFundedGrantSnapshot(
        owner,
        hexToBytes(gf.params[1]),
      );
      assert.equal(funded.grant.keyScheme, scenario === "p256" ? 2 : 1);
      assert.equal(funded.balance, result.balance);
      assert.equal(funded.grant.authEpoch, funded.root.authority.authEpoch);
      assert.equal(g.calls[0].requests.length, 5);
    }
  }
});
test("funding snapshot quantities reject nonminimal/out-of-range scalar data", async () => {
  const f = findFixture("ed25519", "rsc_getRootAuthority"),
    owner = hexToBytes(f.params[0]);
  for (const [method, values] of [
    ["rsc_getTransactionCount", ["0x00", "0X1", "0x" + "f".repeat(17), 1, null]],
    ["rsc_getBalance", ["0x00", "0X1", "0x" + "f".repeat(65), 1, null]],
  ]) {
    for (const value of values) {
      const h = methodHarness(f, {
        mutate(r, q) {
          if (q.method === method) r.result = value;
        },
      });
      await assert.rejects(
        h.client.getAccountAuthorizationSnapshot(owner),
        code("INVALID_RESULT"),
      );
    }
  }
  const h = methodHarness(f, {
    mutate(r, q) {
      if (q.method === "rsc_getBalance") r.result = "0x" + "f".repeat(64);
    },
  });
  assert.equal(
    (await h.client.getAccountAuthorizationSnapshot(owner)).balance,
    (1n << 256n) - 1n,
  );
});
test("funded grant snapshots reject mismatched epochs/counts/usability/context using native state", async () => {
  const f = findFixture("ed25519", "rsc_getSessionGrant"),
    owner = hexToBytes(f.params[0]),
    id = hexToBytes(f.params[1]);
  for (const mutation of [
    (r, q) => {
      if (q.method === "rsc_getSessionGrant") r.result.usableAtObservedBlock = false;
    },
    (r, q) => {
      if (q.method === "rsc_getSessionGrant") r.result.state.height = "0xa";
    },
    (r, q) => {
      if (q.method === "rsc_getRootAuthority") r.result.authorizationMode = 0;
    },
  ]) {
    const h = methodHarness(f, { mutate: mutation });
    await assert.rejects(
      h.client.getFundedGrantSnapshot(owner, id),
      (e) => e instanceof RpcContractError,
    );
  }
});
