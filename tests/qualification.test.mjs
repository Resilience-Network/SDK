import assert from "node:assert/strict";
import test from "node:test";
import { stages, verifyOutput } from "../scripts/qualification/profile.mjs";
test("candidate acceptance rejects empty, stale-minimum and skipped SDK evidence", () => {
  for (const stage of stages) assert.throws(() => verifyOutput(stage, ""));
  const sdk = stages.find((s) => s.id === "sdk");
  assert.throws(() =>
    verifyOutput(sdk, "ℹ tests 303\nℹ fail 0\nℹ skipped 0\nℹ todo 0"),
  );
  assert.throws(() =>
    verifyOutput(sdk, "ℹ tests 304\nℹ fail 0\nℹ skipped 1\nℹ todo 0"),
  );
  assert.equal(verifyOutput(sdk, "ℹ tests 304\nℹ fail 0\nℹ skipped 0\nℹ todo 0"), 304);
  const differential = stages.find((s) => s.id === "differential");
  assert.throws(() => verifyOutput(differential, "differential PASS: 1925 cases"));
  assert.equal(
    verifyOutput(
      differential,
      "differential PASS: 1925 cases\nreceipt commitment PASS: 166 independent fixtures, 26294 cases",
    ),
    1925,
  );
});
