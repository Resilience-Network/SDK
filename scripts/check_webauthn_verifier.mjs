import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
const root = fileURLToPath(new URL("../", import.meta.url)),
  run = (command, args) =>
    execFileSync(command, args, {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 2 * 1024 * 1024,
      timeout: 45000,
    }),
  inventory = JSON.parse(
    await readFile(
      new URL("../tests/webauthn/rp-contract-cases.json", import.meta.url),
      "utf8",
    ),
  ),
  metadata = JSON.parse(
    await readFile(
      new URL("../node_modules/@simplewebauthn/server/package.json", import.meta.url),
      "utf8",
    ),
  ),
  lock = JSON.parse(
    await readFile(new URL("../package-lock.json", import.meta.url), "utf8"),
  );
assert.equal(metadata.version, "14.0.3");
assert.equal(inventory.cases.length, 67);
assert.equal(new Set(inventory.cases.map((value) => value.id)).size, 67);
const output = run(process.execPath, [
  "--test",
  "--test-reporter=tap",
  "tests/webauthn-verifier.test.mjs",
]);
for (const item of inventory.cases)
  assert(output.includes("# Subtest: RP normative: " + item.id));
assert.match(output, /# fail 0\b/);
assert.match(output, /# skipped 0\b/);
assert.match(output, /# todo 0\b/);
const tests = Number(/# tests (\d+)/.exec(output)?.[1]);
assert(tests >= 67);
const files = [
    "examples/webauthn/reference-rp.mjs",
    "tests/webauthn/signed-fixtures.mjs",
    "tests/webauthn-verifier.test.mjs",
    "tests/webauthn/rp-contract-cases.json",
    "node_modules/@simplewebauthn/server/esm/authentication/verifyAuthenticationResponse.js",
    "node_modules/@simplewebauthn/server/esm/registration/verifyRegistrationResponse.js",
  ],
  hashes = {};
for (const file of files)
  hashes[file] = createHash("sha256")
    .update(await readFile(resolve(root, file)))
    .digest("hex");
const report = {
  version: 1,
  kind: "actual-reference-rp-conformance",
  sdkRevision: run("git", ["rev-parse", "HEAD"]).trim(),
  trackedClean:
    run("git", ["status", "--porcelain", "--untracked-files=no"]).trim() === "",
  node: process.version,
  openssl: process.versions.openssl,
  verifier: {
    package: metadata.name,
    version: metadata.version,
    integrity: lock.packages["node_modules/@simplewebauthn/server"].integrity,
  },
  store: "single-process-in-memory-conformance-only",
  normativeCases: inventory.cases.map((item) => ({
    id: item.id,
    expected: item.expected,
    result: "pass",
  })),
  tests,
  failures: 0,
  skipped: 0,
  todo: 0,
  sourceSha256: hashes,
  limitations: [
    "No durable restart or multi-worker store qualification",
    "No browser engine or physical authenticator qualification",
    "No production RP deployment/session service or native WebAuthn authority",
    "No independent security sign-off",
  ],
};
const directory = resolve(root, "artifacts/webauthn-verifier");
await mkdir(directory, { recursive: true });
const path = resolve(directory, "latest.json");
await writeFile(path, JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
console.log(
  `Reference RP conformance PASS: ${inventory.cases.length} normative cases; ${tests} tests, zero skips/todos; ${metadata.name}@${metadata.version}; Node ${process.version}.`,
);
console.log(`Sanitized evidence: ${path}`);
