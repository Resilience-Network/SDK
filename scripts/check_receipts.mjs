import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as sdk from "../dist/index.js";
const root = fileURLToPath(new URL("../", import.meta.url));
assert(
  process.env.RSC_CHAIN_DIR,
  "Set RSC_CHAIN_DIR to immutable clean pinned native Chain checkout.",
);
const chain = resolve(process.env.RSC_CHAIN_DIR),
  pin = JSON.parse(await readFile(join(root, "protocol-source.json"), "utf8"));
const run = (command, args, options = {}) =>
  execFileSync(command, args, { cwd: chain, encoding: "utf8", ...options });
assert.equal(run("git", ["rev-parse", "HEAD"]).trim(), pin.revision);
assert.equal(run("git", ["status", "--porcelain", "--untracked-files=all"]).trim(), "");
assert.equal(run("go", ["env", "CGO_ENABLED"]).trim(), "1");
run("make", ["build-crypto"], { stdio: "inherit" });
const temporary = await mkdtemp(join(tmpdir(), "resilience-sdk-receipts-"));
const source = await readFile(
  join(root, "tests/go-receipt-reference/commitments_test.go"),
);
const installed = join(
  chain,
  "pkg/sessionauth",
  `sdk_receipts_${randomUUID().replaceAll("-", "")}_test.go`,
);
let owned = false;
try {
  await writeFile(installed, source, { flag: "wx" });
  owned = true;
  const output = join(temporary, "output.json"),
    input = join(temporary, "input.json");
  const native = (inputPath = "") =>
    run(
      "go",
      ["test", "./pkg/sessionauth", "-run", "^TestSDKReceiptCommitments$", "-count=1"],
      {
        env: {
          ...process.env,
          RSC_RECEIPT_OUTPUT: output,
          RSC_RECEIPT_INPUT: inputPath,
        },
        stdio: "inherit",
      },
    );
  native();
  const fixtures = JSON.parse(await readFile(output, "utf8"));
  const record = {
    revision: pin.revision,
    provenance:
      "Independent native counter/event encoders and production internal decision seal/shape validation. Decision test decoder is a commitment oracle, not a public Chain decoder or policy evaluator.",
    fixtures,
  };
  const reference = join(root, "tests/fixtures/receipt-commitments.json");
  if (process.argv.includes("--write"))
    await writeFile(reference, `${JSON.stringify(record, null, 2)}\n`);
  else
    assert.deepEqual(
      JSON.parse(await readFile(reference, "utf8")),
      record,
      "Native commitment fixtures drifted; investigate semantics.",
    );
  const cases = [...fixtures];
  let seed = 0x16ce1a;
  const random = () => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return seed >>> 0;
  };
  for (const fixture of fixtures) {
    const bytes = sdk.hexToBytes(fixture.hex);
    // Every truncated length, not just a convenient selected prefix.
    for (let length = 0; length < bytes.length; length++)
      cases.push({ ...fixture, hex: sdk.bytesToHex(bytes.slice(0, length)) });
    cases.push({ ...fixture, hex: `${fixture.hex}00` });
    for (let count = 0; count < 48; count++) {
      const mutation = bytes.slice();
      mutation[random() % bytes.length] ^= 1 << (random() % 8);
      cases.push({ ...fixture, hex: sdk.bytesToHex(mutation) });
    }
  }
  await writeFile(input, JSON.stringify(cases));
  native(input);
  const results = JSON.parse(await readFile(output, "utf8"));
  assert.equal(results.length, cases.length);
  const codecs = {
    counter: sdk.receiptCounterDeltaCodec,
    event: sdk.authorizationEventCodec,
    decision: sdk.sessionDecisionCommitmentCodec,
  };
  const hashes = {
    counter: sdk.receiptCounterDeltaHash,
    event: (v) => sdk.keccak256(sdk.authorizationEventCodec.encode(v)),
    decision: sdk.sessionDecisionCommitmentHash,
  };
  let accepted = 0,
    rejected = 0;
  for (const [at, item] of cases.entries()) {
    const expected = results[at];
    let value;
    try {
      value = codecs[item.kind].decode(sdk.hexToBytes(item.hex));
    } catch (failure) {
      assert(failure instanceof sdk.CodecError);
      assert.equal(
        expected.accepted,
        false,
        `SDK rejected native-accepted ${item.kind}/${item.name}/${at}`,
      );
      rejected++;
      continue;
    }
    assert.equal(
      expected.accepted,
      true,
      `SDK accepted native-rejected ${item.kind}/${item.name}/${at}`,
    );
    assert.equal(sdk.bytesToHex(codecs[item.kind].encode(value)), expected.canonical);
    assert.equal(sdk.bytesToHex(hashes[item.kind](value)), expected.hash);
    accepted++;
  }
  console.log(
    `Native receipt commitment PASS: ${fixtures.length} independent fixtures, ${cases.length} cases (${accepted} accepted, ${rejected} rejected), every truncation +48 seeded mutations; seed 0x16ce1a; Chain ${pin.revision}.`,
  );
} finally {
  if (owned) {
    assert.deepEqual(
      await readFile(installed),
      source,
      "Owned test changed externally; preserve for inspection.",
    );
    await rm(installed);
  }
  await rm(temporary, { recursive: true, force: true });
}
assert.equal(run("git", ["rev-parse", "HEAD"]).trim(), pin.revision);
assert.equal(run("git", ["status", "--porcelain", "--untracked-files=all"]).trim(), "");
