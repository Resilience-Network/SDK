import assert from "node:assert/strict";
import test from "node:test";
import {
  stages,
  verifyOutput,
  verifyArtifact,
} from "../scripts/qualification/profile.mjs";
test("candidate acceptance rejects empty, stale-minimum and skipped SDK evidence", () => {
  for (const stage of stages) assert.throws(() => verifyOutput(stage, ""));
  const sdk = stages.find((s) => s.id === "sdk");
  assert.throws(() =>
    verifyOutput(sdk, "ℹ tests 304\nℹ fail 0\nℹ skipped 0\nℹ todo 0"),
  );
  assert.throws(() =>
    verifyOutput(sdk, "ℹ tests 305\nℹ fail 0\nℹ skipped 1\nℹ todo 0"),
  );
  assert.equal(verifyOutput(sdk, "ℹ tests 305\nℹ fail 0\nℹ skipped 0\nℹ todo 0"), 305);
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

test("candidate artifacts reject stale revisions, unproved cleanliness and differing installed bytes", () => {
  const revision = "a".repeat(40),
    digest = "b".repeat(64);
  const evidence = { revision, dirty: false, status: "PASS", archiveSha256: digest };
  verifyArtifact("api", evidence, revision, digest);
  assert.throws(
    () =>
      verifyArtifact(
        "api",
        { ...evidence, revision: "c".repeat(40) },
        revision,
        digest,
      ),
    /Stale/,
  );
  assert.throws(
    () => verifyArtifact("api", { ...evidence, dirty: undefined }, revision, digest),
    /cleanliness/,
  );
  assert.throws(
    () =>
      verifyArtifact(
        "api",
        { ...evidence, archiveSha256: "d".repeat(64) },
        revision,
        digest,
      ),
    /digest mismatch/,
  );
  assert.throws(
    () =>
      verifyArtifact(
        "installed",
        { sdkRevision: revision, result: "pass", archiveSha256: digest },
        revision,
        digest,
      ),
    /cleanliness/,
  );
});
