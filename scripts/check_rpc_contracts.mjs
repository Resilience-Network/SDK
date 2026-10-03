import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
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
const signingGolden = JSON.parse(
  await readFile(join(root, "tests/display/golden/signing-binding.json"), "utf8"),
);
assert.equal(signingGolden.validatedAtRevision, pin.revision);
assert.equal(
  createHash("sha256")
    .update(await readFile(join(chain, "reference/sessionauth/model.py")))
    .digest("hex"),
  signingGolden.modelSha256,
  "Independent signing-review model changed; inspect goldens before repinning.",
);
assert.equal(
  createHash("sha256")
    .update(await readFile(join(chain, pin.vectorPaths[0])))
    .digest("hex"),
  pin.vectorSha256,
);
const temporary = await mkdtemp(join(tmpdir(), "resilience-sdk-rpc-"));
const source = await readFile(join(root, "tests/go-rpc-reference/contracts_test.go"));
const receiptSource = await readFile(
  join(root, "tests/go-rpc-reference/receipts_test.go"),
);
const receiptInstalled = join(
  chain,
  "internal/rpc",
  `sdk_receipts_${randomUUID().replaceAll("-", "")}_test.go`,
);
let receiptOwned = false;
const installed = join(
  chain,
  "internal/rpc",
  `sdk_contracts_${randomUUID().replaceAll("-", "")}_test.go`,
);
let owned = false;
try {
  await writeFile(installed, source, { flag: "wx" });
  owned = true;
  await writeFile(receiptInstalled, receiptSource, { flag: "wx" });
  receiptOwned = true;
  const output = join(temporary, "rpc.json");
  const receiptOutput = join(temporary, "receipts.json");
  const envelopeOutput = join(temporary, "envelopes.json");
  run(
    "go",
    ["test", "./internal/rpc", "-run", "^TestSDKPinnedRPCContracts$", "-count=1"],
    {
      env: {
        ...process.env,
        RSC_RPC_FIXTURE_OUTPUT: output,
        RSC_RPC_ENVELOPE_OUTPUT: envelopeOutput,
        RSC_RPC_RECEIPT_OUTPUT: receiptOutput,
      },
      stdio: "inherit",
    },
  );
  const fixtures = JSON.parse(await readFile(output, "utf8"));
  const reference = join(root, "tests/fixtures/rpc-contracts.json");
  const envelopes = JSON.parse(await readFile(envelopeOutput, "utf8"));
  const envelopeReference = join(root, "tests/fixtures/rpc-envelopes.json");
  const envelopeRecord = {
    revision: pin.revision,
    provenance:
      "Actual production Handler/API; owned in-memory state. Falsy test probes are explicitly labelled, not public RPC methods. No running-network finality claim.",
    envelopes,
  };
  const receipts = JSON.parse(await readFile(receiptOutput, "utf8"));
  const receiptReference = join(root, "tests/fixtures/rpc-receipts.json");
  const receiptRecord = {
    revision: pin.revision,
    provenance:
      "Native production Handler/API with owned constructed receipt/state fixtures. Canonical native counter/event commitments; projection-only, not funded execution. SessionCancel has a structural test signature. No independent finality claim.",
    fixtures: receipts,
  };
  if (process.argv.includes("--write")) {
    await writeFile(
      reference,
      `${JSON.stringify({ revision: pin.revision, fixtures }, null, 2)}\n`,
    );
    await writeFile(receiptReference, `${JSON.stringify(receiptRecord, null, 2)}\n`);
    await writeFile(envelopeReference, `${JSON.stringify(envelopeRecord, null, 2)}\n`);
    console.log(
      `Wrote ${fixtures.length} native typed fixtures and ${envelopes.length} native envelope and ${receipts.length} receipt fixtures at ${pin.revision}.`,
    );
  } else {
    assert.deepEqual(
      JSON.parse(await readFile(receiptReference, "utf8")),
      receiptRecord,
      "Native receipt fixtures drifted; inspect semantics before regeneration.",
    );
    assert.deepEqual(
      JSON.parse(await readFile(reference, "utf8")),
      { revision: pin.revision, fixtures },
      "Native RPC fixtures drifted; inspect semantics before regeneration.",
    );
    assert.deepEqual(
      JSON.parse(await readFile(envelopeReference, "utf8")),
      envelopeRecord,
      "Native envelope fixtures drifted; inspect semantics before regeneration.",
    );
    console.log(
      `Native production-handler fixtures match: ${fixtures.length} typed, ${envelopes.length} envelopes, ${receipts.length} receipts; pin ${pin.revision}.`,
    );
  }
} finally {
  if (receiptOwned) {
    assert.deepEqual(
      await readFile(receiptInstalled),
      receiptSource,
      "Owned receipt test changed externally; preserve for inspection.",
    );
    await rm(receiptInstalled);
  }
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
