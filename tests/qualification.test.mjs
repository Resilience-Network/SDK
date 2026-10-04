import assert from "node:assert/strict";
import test from "node:test";
import {
  stages,
  verifyOutput,
  verifyArtifact,
  verifyNativeChecks,
} from "../scripts/qualification/profile.mjs";
test("candidate acceptance rejects empty, stale-minimum and skipped SDK evidence", () => {
  for (const stage of stages) assert.throws(() => verifyOutput(stage, ""));
  const sdk = stages.find((s) => s.id === "sdk");
  assert.throws(() =>
    verifyOutput(sdk, "ℹ tests 327\nℹ fail 0\nℹ cancelled 0\nℹ skipped 0\nℹ todo 0"),
  );
  assert.throws(() =>
    verifyOutput(sdk, "ℹ tests 328\nℹ fail 0\nℹ cancelled 0\nℹ skipped 1\nℹ todo 0"),
  );
  assert.equal(
    verifyOutput(sdk, "ℹ tests 328\nℹ fail 0\nℹ cancelled 0\nℹ skipped 0\nℹ todo 0"),
    328,
  );
  assert.throws(() =>
    verifyOutput(sdk, "ℹ tests 328\nℹ fail 0\nℹ cancelled 1\nℹ skipped 0\nℹ todo 0"),
  );
  assert.throws(() =>
    verifyOutput(sdk, "ℹ tests 328\nℹ fail 0\nℹ skipped 0\nℹ todo 0"),
  );
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

test("RP artifact coverage requires actual safe integer counts", () => {
  const revision = "a".repeat(40),
    digest = "b".repeat(64);
  const valid = {
    revision,
    trackedClean: true,
    tests: 76,
    failures: 0,
    skipped: 0,
    todo: 0,
    normativeCases: Array.from({ length: 67 }, (_, i) => ({
      id: `case-${i}`,
      result: "pass",
    })),
  };
  verifyArtifact("rp", valid, revision, digest);
  for (const tests of [
    undefined,
    "76",
    null,
    NaN,
    Infinity,
    -1,
    75,
    76.5,
    Number.MAX_SAFE_INTEGER + 1,
  ])
    assert.throws(
      () => verifyArtifact("rp", { ...valid, tests }, revision, digest),
      /Incomplete RP/,
    );
  for (const normativeCases of [
    undefined,
    null,
    [],
    Array(67),
    Array(67).fill(valid.normativeCases[0]),
  ])
    assert.throws(
      () => verifyArtifact("rp", { ...valid, normativeCases }, revision, digest),
      /Incomplete RP/,
    );
  for (const field of ["failures", "skipped", "todo"])
    for (const value of [undefined, "0", null, NaN, 1])
      assert.throws(() =>
        verifyArtifact("rp", { ...valid, [field]: value }, revision, digest),
      );
});

test("native evidence coverage requires a complete check array", () => {
  verifyNativeChecks([], 0);
  verifyNativeChecks([{ name: "both schemes" }, { name: "both schemes" }], 2);
  for (const checks of [
    undefined,
    null,
    { length: 67 },
    "x".repeat(67),
    [],
    Array(67),
    Array(67).fill(null),
    [{ name: "" }],
  ])
    assert.throws(() => verifyNativeChecks(checks, 1), /Incomplete native/);
  for (const minimum of [undefined, "0", -1, NaN, 1.5])
    assert.throws(() => verifyNativeChecks([], minimum), /Incomplete native/);
});

test("browser and combined evidence requires complete arrays of distinct passing checks", () => {
  const revision = "a".repeat(40),
    digest = "b".repeat(64);
  for (const name of ["browser", "combined"]) {
    const minimum = name === "browser" ? 24 : 17;
    const checks = Array.from({ length: minimum }, (_, i) => ({
      name: `case-${i}`,
      result: "pass",
    }));
    const valid = {
      sdkRevision: revision,
      trackedClean: true,
      result: "pass",
      archiveSha256: digest,
      failures: 0,
      skipped: 0,
      todo: 0,
      ...(name === "browser"
        ? { engines: [{ version: "154.0.8037.95", checks }] }
        : { browser: { version: "154.0.8037.95" }, checks }),
    };
    verifyArtifact(name, valid, revision, digest);
    for (const malformed of [
      undefined,
      null,
      { length: minimum },
      [],
      checks.slice(1),
      Array(minimum),
      Array(minimum).fill(null),
      Array(minimum).fill(checks[0]),
      checks.map((c, i) => (i === 0 ? { ...c, result: "fail" } : c)),
      checks.map((c, i) => (i === 0 ? { result: "pass" } : c)),
    ]) {
      const evidence = structuredClone(valid);
      if (name === "browser") evidence.engines[0].checks = malformed;
      else evidence.checks = malformed;
      assert.throws(() => verifyArtifact(name, evidence, revision, digest));
    }
    if (name === "browser")
      for (const engines of [
        undefined,
        null,
        { length: 1, 0: valid.engines[0] },
        [null],
        [valid.engines[0], valid.engines[0]],
      ])
        assert.throws(() =>
          verifyArtifact(name, { ...valid, engines }, revision, digest),
        );
  }
});
