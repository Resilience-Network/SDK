import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  bytes,
  context,
  fixtureCodecs,
  hex,
  samples,
  sdk,
  seeded,
  vectors,
} from "../tests/helpers.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const chain = process.env.RSC_CHAIN_DIR;
assert(
  chain,
  "Set RSC_CHAIN_DIR to a clean checkout at protocol-source.json revision.",
);
const pin = JSON.parse(
  await readFile(new URL("../protocol-source.json", import.meta.url), "utf8"),
);
const run = (command, args, options = {}) =>
  execFileSync(command, args, { cwd: resolve(chain), encoding: "utf8", ...options });
assert.equal(
  run("git", ["rev-parse", "HEAD"]).trim(),
  pin.revision,
  "Pinned Chain revision mismatch",
);
assert.equal(
  run("git", ["status", "--porcelain", "--untracked-files=no"]).trim(),
  "",
  "Chain tracked source must be clean",
);
assert.equal(
  run("go", ["env", "CGO_ENABLED"]).trim(),
  "1",
  "Native conformance requires CGO_ENABLED=1",
);
run("make", ["build-crypto"], { stdio: "inherit" });
const temporary = await mkdtemp(join(tmpdir(), "resilience-sdk-oracle-"));

try {
  const binary = join(temporary, "go-reference");
  run("go", ["build", "-o", binary, join(root, "tests/go-reference/main.go")], {
    stdio: "inherit",
  });
  const sourceFixtures = JSON.parse(run(binary, ["fixtures"]));
  const cases = samples();
  const extraRequest = {
    kind: "hashes",
    hex: vectors.policy.policyHash,
    chainId: context.chainId.toString(),
    genesis: hex(context.genesisHash),
    owner: vectors.keys.owner,
  };
  const [extras] = JSON.parse(
    run(binary, [], { input: JSON.stringify([extraRequest]) }),
  );
  assert.equal(extras.accepted, true);
  const id = bytes(vectors.policy.policyHash),
    owner = bytes(vectors.keys.owner);
  const extraHashes = {
    meta: sdk.authorizationMetaKey(),
    recovery: sdk.authorizationRecoveryKey(),
    grantKey: sdk.authorizationGrantKey(id),
    activeKey: sdk.authorizationActiveKey(1n, id),
    leaf: sdk.recipientLeafHash(context, 0, owner),
    empty: sdk.recipientEmptyLeafHash(context, 0, 0xffffffff),
    node: sdk.recipientNodeHash(context, 0, id, id),
    validator: sdk.validatorConsensusKeyHash(id),
  };
  for (const [key, value] of Object.entries(extraHashes))
    assert.equal(hex(value), extras.hashes[key], `Go hash helper: ${key}`);
  for (const [kind, expected] of Object.entries(sourceFixtures)) {
    const candidates = cases.filter(
      (item) => item.kind === (kind.startsWith("rotate") ? "rotate" : kind),
    );
    assert(
      candidates.some((item) => item.hex === expected),
      `Go-generated field fixture mismatch: ${kind}`,
    );
  }
  const random = seeded();
  for (const item of [...cases]) {
    const source = bytes(item.hex);
    for (const length of [0, 1, source.length - 1])
      cases.push({
        ...item,
        hex: hex(source.slice(0, length)),
        name: `${item.name} truncated ${length}`,
      });
    cases.push({ ...item, hex: `${item.hex}00`, name: `${item.name} trailing` });
    for (let i = 0; i < 32; i++) {
      const data = source.slice();
      data[random() % data.length] ^= 1 << (random() % 8);
      cases.push({ ...item, hex: hex(data), name: `${item.name} mutation ${i}` });
    }
  }
  // Go supports CLAIM_REWARDS (0x06); the initial SDK scope deliberately does not.
  const outsideScope = bytes(cases.find((item) => item.name === "empty action 7").hex);
  outsideScope[30] = 6;
  cases.push({
    kind: "intent",
    name: "explicit out-of-scope CLAIM_REWARDS",
    hex: hex(outsideScope),
  });
  const requests = cases.map((item) => ({
    ...item,
    chainId: context.chainId.toString(),
    genesis: hex(context.genesisHash),
    owner: vectors.keys.owner,
  }));
  const results = JSON.parse(
    run(binary, [], { input: JSON.stringify(requests), maxBuffer: 32 * 1024 * 1024 }),
  );
  assert.equal(results.length, requests.length);
  let accepted = 0,
    rejected = 0,
    unsupported = 0;
  for (let index = 0; index < cases.length; index++) {
    const item = cases[index],
      oracle = results[index];
    let value;
    try {
      value = fixtureCodecs[item.kind].decode(bytes(item.hex));
    } catch (error) {
      assert(error instanceof sdk.CodecError);
      const actionOutsideScope =
        ["intent", "transaction"].includes(item.kind) &&
        !Object.values(sdk.Action).includes(bytes(item.hex)[30]);
      if (oracle.accepted && actionOutsideScope) {
        assert.equal(error.code, "UNSUPPORTED_FEATURE");
        unsupported++;
        continue;
      }
      assert.equal(
        oracle.accepted,
        false,
        `SDK rejected Go-accepted ${item.kind}/${item.name}: ${error.message}`,
      );
      rejected++;
      continue;
    }
    assert.equal(
      oracle.accepted,
      true,
      `SDK accepted Go-rejected ${item.kind}/${item.name}: ${oracle.error}`,
    );
    assert.equal(hex(fixtureCodecs[item.kind].encode(value)), oracle.canonical);
    accepted++;
    const hashes = oracle.hashes ?? {};
    if (hashes.intentHashError) assert.throws(() => sdk.intentHash(context, value));
    if (hashes.transactionIdError)
      assert.throws(() => sdk.transactionId(context, value.intent, value.envelope));
    if (hashes.intentHash)
      assert.equal(hex(sdk.intentHash(context, value)), hashes.intentHash);
    if (hashes.policyHash) assert.equal(hex(sdk.policyHash(value)), hashes.policyHash);
    if (hashes.rootConfigHash) {
      assert.equal(hex(sdk.rootConfigHash(value)), hashes.rootConfigHash);
      value.keys.forEach((key, i) =>
        assert.equal(hex(sdk.rootKeyId(key)), hashes[`rootKeyId${i}`]),
      );
    }
    if (hashes.fingerprint) {
      assert.equal(
        hex(sdk.sessionKeyFingerprint(value.grant.keyScheme, value.grant.publicKey)),
        hashes.fingerprint,
      );
      assert.equal(
        hex(
          sdk.grantId(
            context,
            bytes(vectors.keys.owner),
            1n,
            0n,
            value.grant.keyScheme,
            value.grant.publicKey,
          ),
        ),
        hashes.grantId,
      );
    }
    if (hashes.transactionId) {
      const { intent: i, envelope: e } = value;
      assert.equal(hex(sdk.transactionId(context, i, e)), hashes.transactionId);
      const digest =
        e.mode === 0
          ? sdk.directDigest(context, i, e.nonce)
          : e.mode === 1
            ? sdk.rootDigest(context, i, e.credentialId, e.authEpoch, e.nonce)
            : sdk.sessionDigest(context, i, {
                grantId: e.credentialId,
                authEpoch: e.authEpoch,
                policyHash: e.policyHash,
                nonce: e.nonce,
              });
      assert.equal(hex(digest), hashes.digest);
      if (hashes.sponsorDigest)
        assert.equal(
          hex(sdk.sponsorDigest(context, i, i.sponsor, e.sponsorNonce)),
          hashes.sponsorDigest,
        );
    }
  }
  assert(unsupported >= 1, "The known-valid out-of-scope action must fail explicitly");
  console.log(
    `Pinned Go differential PASS: ${cases.length} cases (${accepted} accepted, ${rejected} rejected, ${unsupported} explicit out-of-scope action rejections); ${Object.keys(sourceFixtures).length} independently Go-generated onboarding layouts; 8 state/recipient/validator hash helpers.`,
  );
} finally {
  await rm(temporary, { recursive: true, force: true });
}
