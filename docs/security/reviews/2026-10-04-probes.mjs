// Historical reproductions, not a qualification suite. All data are public fixtures.
// Build first. Refuse changed reviewed sources; future fixes need new regressions.
import assert from "node:assert/strict";
import { spawn as actualSpawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import * as sdk from "../../../dist/index.js";
import { verifyArtifact } from "../../../scripts/qualification/profile.mjs";
import { OwnedProcesses } from "../../../scripts/localnet/harness.mjs";

const root = fileURLToPath(new URL("../../../", import.meta.url));
assert.equal(process.platform, "darwin", "Use the reviewed macOS process profile");
assert.equal(process.arch, "arm64", "Use the reviewed arm64 process profile");
assert.equal(process.version, "v24.21.0", "Use the reviewed Node runtime");
const hashes = {
  "src/rpc/http.ts": "71ce0b27105dbd7e7f356a588670c7f52da1927b551a2c7a6fae11731ffdfb37",
  "src/rpc/methods.ts":
    "93fab362cdf22f44a86377d02e9fb5a6fe7582ff4fcd03df2a208f09852569c5",
  "scripts/qualification/profile.mjs":
    "abc7369284b73a2acccac7eee64dbfefe68b8e91580d2631e52b70e03706874a",
  "scripts/qualification/run.mjs":
    "12daefa80960fd7862716cdfd7669aaff91a3211c80df37760f8acdb3960ee3d",
  "scripts/localnet/harness.mjs":
    "fa68fc802aa141b846d156274c9dfdb1a45ce36fa76d3b9acef76c58b5100975",
};
for (const [path, expected] of Object.entries(hashes))
  assert.equal(
    createHash("sha256")
      .update(await readFile(join(root, path)))
      .digest("hex"),
    expected,
    "Historical baseline changed: " + path,
  );
const results = [];
const record = (value) => results.push(value);
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function bounded(promise, ms = 3000) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(Error("Review probe deadline")), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

// R2: actual public client; the original object reaches the caller before fetch.
const original = new sdk.RpcClientError("NETWORK_ERROR");
original.message = "REVIEW_PUBLIC_SENTINEL";
original.cause = "REVIEW_PUBLIC_SENTINEL";
let fetches = 0;
const http = new sdk.HttpRpcClient({
  url: "http://127.0.0.1:1",
  maxRetries: 0,
  fetch: async () => {
    fetches++;
    throw Error("Review fetch must not run");
  },
});
await assert.rejects(
  http.request(
    "rsc_chainId",
    new Proxy(
      {},
      {
        getPrototypeOf: () => {
          throw original;
        },
      },
    ),
  ),
  (error) => error === original && error.cause === original.cause,
);
assert.equal(fetches, 0);
record({ issue: 84, originalErrorForwarded: true, fetches });

// R5: JSON-compatible missing/string counts accepted by the actual predicate.
const revision = "a".repeat(40);
for (const value of [undefined, "76"]) {
  verifyArtifact(
    "rp",
    {
      revision,
      trackedClean: true,
      failures: 0,
      skipped: 0,
      todo: 0,
      ...(value === undefined ? {} : { tests: value }),
    },
    revision,
    "b".repeat(64),
  );
  record({ issue: 85, acceptedCount: value ?? "missing" });
}

// R1: actual typed client and valid native JSON fixture, across two read-only polls.
const fixture = JSON.parse(
  await readFile(join(root, "tests/fixtures/rpc-reconciliation.json")),
).fixtures[0];
for (const increase of [5n, 0n]) {
  let polls = 0;
  const firstHeight = BigInt(fixture.identity.result.state.height) + increase;
  const firstState = {
    finality: "finalized",
    height: "0x" + firstHeight.toString(16),
    blockHash: "0x" + "aa".repeat(32),
    stateRoot: "0x" + "bb".repeat(32),
  };
  const fetch = async (_url, init) => {
    const requests = JSON.parse(init.body);
    assert(Array.isArray(requests), "Reconciliation must never send");
    assert(!requests.some((r) => r.method.includes("sendRawTransaction")));
    if (requests.some((r) => r.method === "rsc_getTransactionReceipt")) polls++;
    const responses = requests.map((request) => {
      const key = {
        rsc_getAuthorizationFinalityStatus: "identity",
        rsc_getTransactionReceipt: "receipt",
        rsc_getTransactionByHash: "transaction",
        rsc_getRootAuthority: "root",
        rsc_getSessionGrant: "grant",
        rsc_getBlockByNumber: "block",
      }[request.method];
      const native = key
        ? fixture[key]
        : request.params[0] === fixture.transaction.result.from
          ? fixture.accountNonce
          : fixture.sponsorNonce;
      assert(native);
      const response = structuredClone(native);
      response.id = request.id;
      if (polls === 1) {
        if (
          ["rsc_getTransactionReceipt", "rsc_getTransactionByHash"].includes(
            request.method,
          )
        )
          response.result = null;
        if (response.result?.state) response.result.state = structuredClone(firstState);
      }
      return response;
    });
    return new Response(JSON.stringify(responses));
  };
  const client = new sdk.ChainRpcClient({
    url: "https://review.example.invalid",
    expected: {
      chainId: 1337n,
      genesisHash: sdk.hexToBytes(fixture.identity.result.genesisHash),
      authorizationCapability: sdk.AUTHORIZATION_CAPABILITY,
    },
    fetch,
    maxRetries: 0,
  });
  const result = await client.reconcileTransaction(sdk.hexToBytes(fixture.canonical), {
    maxPolls: 2,
    pollIntervalMs: 1,
    timeoutMs: 1000,
  });
  assert.equal(result.status, "reported-finalized-success");
  assert.equal(result.polls, 2);
  assert(firstHeight >= result.identity.state.height);
  assert.notEqual(
    firstState.blockHash,
    sdk.bytesToHex(result.identity.state.blockHash),
  );
  record({
    issue: 88,
    scenario: increase === 0n ? "equal-height contradiction" : "height regression",
    previousHeight: firstHeight.toString(),
    terminalHeight: result.identity.state.height.toString(),
    status: result.status,
    sends: 0,
  });
}

// R3: verbatim reviewed controller; only this fixture's group can be killed.
const source = await readFile(join(root, "scripts/qualification/run.mjs"), "utf8");
const termination = source.slice(
  source.indexOf("const terminate = () => {"),
  source.indexOf("const abort = () => {"),
);
const promise = source.slice(
  source.indexOf("  const result = await new Promise((resolve, reject) => {"),
  source.indexOf("  child = undefined;"),
);
assert(termination.includes('process.kill(-child.pid, "SIGTERM")'));
assert(promise.includes("const timer = setTimeout(stop, stage.timeout)"));
const directory = await mkdtemp(join(tmpdir(), "sdk-review-83-owned-"));
let handle;
const spawn = (...args) => (handle = actualSpawn(...args));
const exercise = new Function(
  "spawn",
  "args",
  "root",
  "stage",
  `return (async()=>{let child;${termination}\n${promise}\nreturn result;})()`,
);
let pending;
try {
  const path = join(directory, "ignores-term.mjs");
  await writeFile(
    path,
    "process.on('SIGTERM',()=>{});console.log('ready');setInterval(()=>{},1000);\n",
    { mode: 0o600 },
  );
  let settled = false;
  const start = Date.now();
  pending = exercise(spawn, [path], directory, { timeout: 200 }).then((result) => {
    settled = true;
    return result;
  });
  await wait(750);
  assert.equal(settled, false);
  assert.equal(handle.exitCode, null);
  assert.equal(handle.signalCode, null);
  record({
    issue: 86,
    timeoutMs: 200,
    elapsedMs: Date.now() - start,
    settled,
    childStillRunning: true,
  });
} finally {
  if (handle && handle.exitCode === null && handle.signalCode === null)
    process.kill(-handle.pid, "SIGKILL");
  if (pending) {
    const result = await bounded(pending);
    assert.equal(result.signal, "SIGKILL");
    assert.equal(result.failed, true);
    assert.match(result.output.toString(), /ready/);
    record({ issue: 86, probeOwnedChildClosed: true });
  }
  await rm(directory, { recursive: true });
}

// R4: use the actual supervisor with an exited parent and inherited-pipe child.
const owned = new OwnedProcesses();
const leader = `const {spawn}=require('node:child_process');const child=spawn(process.execPath,['-e',"process.on('SIGTERM',()=>{});console.log(process.pid);setInterval(()=>{},1000)"],{stdio:['ignore',process.stdout,'ignore']});child.unref();`;
const entry = owned.start(process.execPath, ["-e", leader], {
  stdio: ["ignore", "pipe", "ignore"],
});
try {
  await bounded(new Promise((resolve) => entry.child.stdout.once("data", resolve)));
  if (entry.child.exitCode === null)
    await bounded(new Promise((resolve) => entry.child.once("exit", resolve)));
  assert.equal(entry.child.exitCode, 0);
  assert.equal(entry.exited, true);
  assert.equal(entry.closed, false);
  const start = Date.now();
  await assert.rejects(owned.stop(20), /Owned child did not close after kill/);
  assert.equal(entry.closed, false);
  record({
    issue: 87,
    leaderExited: true,
    stopRejected: true,
    elapsedMs: Date.now() - start,
    descendantPipeStillOpen: true,
  });
} finally {
  if (!entry.closed) process.kill(-entry.child.pid, "SIGKILL");
  await bounded(entry.done);
  record({ issue: 87, probeOwnedGroupClosed: true });
}
console.log(
  JSON.stringify(
    {
      kind: "historical-known-defect-reproductions",
      baseline: "fac5ba1843be7ed51562f4387c34e82677c4216d",
      qualificationPassed: false,
      results,
    },
    null,
    2,
  ),
);
