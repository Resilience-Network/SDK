import assert from "node:assert/strict";
import test from "node:test";
import { ExampleApplicationGate } from "../examples/passkey-session/app-gate.mjs";
const verified = {
  status: "authenticated",
  applicationAuthenticated: true,
  accountId: "app",
};
test("example app gate rejects pending proof, wrong account and invalid lifetimes", () => {
  const gate = new ExampleApplicationGate(() => 1000);
  for (const result of [
    { ...verified, status: "awaiting-proof" },
    { ...verified, applicationAuthenticated: false },
    { ...verified, accountId: "other" },
  ]) {
    assert.throws(() => gate.accept(result, "app"));
    assert.equal(gate.allowed("app"), false);
  }
  for (const lifetime of [0, -1, 900001, NaN, 1.5])
    assert.throws(() => gate.accept(verified, "app", lifetime));
});
test("example app gate has exclusive expiry, abort, logout and replacement invalidation", () => {
  let now = 1000;
  const gate = new ExampleApplicationGate(() => now);
  gate.accept(verified, "app", 100);
  assert.equal(gate.allowed("app"), true);
  assert.equal(gate.allowed("other"), false);
  now = 999;
  assert.equal(gate.allowed("app"), false);
  now = 1000;
  const controller = new AbortController();
  controller.abort();
  assert.equal(gate.allowed("app", controller.signal), false);
  now = 1100;
  assert.equal(gate.allowed("app"), false);
  gate.accept(verified, "app");
  gate.clear();
  assert.equal(gate.allowed("app"), false);
  gate.accept(verified, "app");
  assert.throws(() => gate.accept({ ...verified, status: "awaiting-proof" }, "app"));
  assert.equal(gate.allowed("app"), false);
  now = NaN;
  assert.equal(gate.allowed("app"), false);
});
