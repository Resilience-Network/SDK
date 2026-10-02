import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
assert(
  process.env.RSC_CHAIN_DIR,
  "Set RSC_CHAIN_DIR to the immutable pinned Chain checkout.",
);
const chain = resolve(process.env.RSC_CHAIN_DIR);
const run = (command, args, options = {}) =>
  execFileSync(command, args, { cwd: chain, encoding: "utf8", ...options });
const pin = JSON.parse(await readFile(join(root, "protocol-source.json"), "utf8"));
assert.equal(run("git", ["rev-parse", "HEAD"]).trim(), pin.revision);
assert.equal(run("git", ["status", "--porcelain", "--untracked-files=all"]).trim(), "");
assert.equal(run("go", ["env", "CGO_ENABLED"]).trim(), "1");
run("make", ["build-crypto"], { stdio: "inherit" });
const temporary = await mkdtemp(join(tmpdir(), "resilience-sdk-rpc-"));
const source = await readFile(join(root, "tests/go-rpc-reference/contracts_test.go"));
const installed = join(
  chain,
  "internal/rpc",
  `sdk_contracts_${randomUUID().replaceAll("-", "")}_test.go`,
);
let owned = false;
try {
  await writeFile(installed, source, { flag: "wx" });
  owned = true;
  const output = join(temporary, "rpc.json");
  run(
    "go",
    ["test", "./internal/rpc", "-run", "^TestSDKPinnedRPCContracts$", "-count=1"],
    { env: { ...process.env, RSC_RPC_FIXTURE_OUTPUT: output }, stdio: "inherit" },
  );
  const fixtures = JSON.parse(await readFile(output, "utf8"));
  const reference = join(root, "tests/fixtures/rpc-contracts.json");
  if (process.argv.includes("--write")) {
    await writeFile(
      reference,
      `${JSON.stringify({ revision: pin.revision, fixtures }, null, 2)}\n`,
    );
    console.log(
      `Wrote ${fixtures.length} native production-handler fixtures at ${pin.revision}.`,
    );
  } else {
    assert.deepEqual(
      JSON.parse(await readFile(reference, "utf8")),
      { revision: pin.revision, fixtures },
      "Native RPC fixtures drifted; inspect semantics before regeneration.",
    );
    console.log(
      `Native production-handler contract fixtures match: ${fixtures.length}; pin ${pin.revision}.`,
    );
  }
} finally {
  if (owned) {
    assert.deepEqual(
      await readFile(installed),
      source,
      "Owned test file was changed externally; preserve it for inspection.",
    );
    await rm(installed);
  }
  await rm(temporary, { recursive: true, force: true });
}
// The exclusively owned test is transient; check source cleanliness after teardown.
assert.equal(run("git", ["rev-parse", "HEAD"]).trim(), pin.revision);
assert.equal(run("git", ["status", "--porcelain", "--untracked-files=all"]).trim(), "");
console.log("Pinned Chain checkout remains clean after owned fixture-test teardown.");
