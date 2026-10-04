import assert from "node:assert/strict";
import test from "node:test";
import { recordNativeTeardown } from "../scripts/localnet/outcome.mjs";

test("teardown failure invalidates successful native activity without preserving PASS", () => {
  // Reproduce the actual #93 snapshot independently of process timing/permission.
  const evidence = { status: "passed", checks: [{ name: "funded activity" }] };
  recordNativeTeardown(evidence, false);
  assert.equal(evidence.status, "failed");
  assert.equal(evidence.teardown.allOwnedChildrenClosed, false);
  assert.deepEqual(evidence.failure, { code: "TEARDOWN_FAILED" });
  assert.equal(evidence.checks.length, 1);
});
test("successful teardown preserves failed/interrupted activity and original diagnostics", () => {
  for (const status of ["passed", "failed", "interrupted"]) {
    const evidence = {
      status,
      ...(status === "passed" ? {} : { failure: { code: "NATIVE_RUN_FAILED" } }),
    };
    const before = structuredClone(evidence);
    recordNativeTeardown(evidence, true);
    assert.equal(evidence.status, before.status);
    assert.deepEqual(evidence.failure, before.failure);
    assert.equal(evidence.teardown.allOwnedChildrenClosed, true);
    recordNativeTeardown(evidence, false);
    assert.equal(evidence.status, "failed");
    assert.deepEqual(evidence.failure, { code: "TEARDOWN_FAILED" });
  }
});
test("cleanup procedure failure remains failed even after actual group closure", () => {
  const evidence = { status: "passed" };
  recordNativeTeardown(evidence, true, true);
  assert.equal(evidence.teardown.allOwnedChildrenClosed, true);
  assert.equal(evidence.status, "failed");
  assert.deepEqual(evidence.failure, { code: "TEARDOWN_FAILED" });
});
