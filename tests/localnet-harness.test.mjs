import assert from "node:assert/strict";
import { mkdtemp, realpath, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  OwnedProcesses,
  leaseLoopbackPorts,
  removeOwnedRuntime,
  withNativeLocalnet,
} from "../scripts/localnet/harness.mjs";

test(
  "process supervisor stops only its owned child handle, including a stuck SIGTERM handler",
  { timeout: 10000 },
  async () => {
    const own = new OwnedProcesses(),
      other = new OwnedProcesses();
    const unrelated = other.start(
      process.execPath,
      ["-e", "setInterval(()=>{},1000)"],
      { stdio: "ignore" },
    );
    const child = own.start(
      process.execPath,
      [
        "-e",
        "process.on('SIGTERM',()=>{});console.log('ready');setInterval(()=>{},1000)",
      ],
      { stdio: ["ignore", "pipe", "ignore"] },
    );
    try {
      await new Promise((r) => child.child.stdout.once("data", r));
      assert.equal(own.pids.length, 1);
      await own.stop(20);
      assert.equal(child.closed, true);
      assert.equal(unrelated.closed, false);
      await own.stop(20);
    } finally {
      await other.stop(1000);
    }
  },
);
test("loopback port leasing is exclusive and release is idempotent", async () => {
  const lease = await leaseLoopbackPorts(3);
  assert.equal(new Set(lease.ports).size, 3);
  for (const port of lease.ports) {
    const probe = createServer();
    await assert.rejects(
      new Promise((yes, no) => {
        probe.once("error", no);
        probe.listen(port, "127.0.0.1", yes);
      }),
      (e) => e.code === "EADDRINUSE",
    );
  }
  await lease.release();
  await lease.release();
  const probe = createServer();
  await new Promise((r) => probe.listen(lease.ports[0], "127.0.0.1", r));
  await new Promise((r) => probe.close(r));
});
test("cleanup validates canonical ownership marker and refuses symlinks/tampering; external sentinel stays intact", async () => {
  const root = await realpath(tmpdir()),
    runtime = await mkdtemp(join(root, "resilience-sdk-native-test-")),
    external = await mkdtemp(join(root, "resilience-sdk-sentinel-")),
    alias = join(external, "alias");
  const sentinel = join(external, "keep.json");
  await writeFile(sentinel, '{"existingSafetyState":"retain"}');
  try {
    await writeFile(
      join(runtime, "ownership.json"),
      JSON.stringify({ id: "mine", path: await realpath(runtime), disposable: true }),
    );
    await assert.rejects(removeOwnedRuntime(runtime, "another"));
    assert.equal(await readFile(sentinel, "utf8"), '{"existingSafetyState":"retain"}');
    await symlink(runtime, alias);
    await assert.rejects(removeOwnedRuntime(alias, "mine"));
    await removeOwnedRuntime(runtime, "mine");
    await assert.rejects(
      readFile(join(runtime, "ownership.json")),
      (e) => e.code === "ENOENT",
    );
    assert.equal(await readFile(sentinel, "utf8"), '{"existingSafetyState":"retain"}');
  } finally {
    await rm(runtime, { recursive: true, force: true });
    await rm(external, { recursive: true, force: true });
  }
});
test("invalid native harness options fail before creating/starting a network", async () => {
  for (const options of [
    { chainDir: "/invalid", validators: 2 },
    { chainDir: "/invalid", readyTimeoutMs: 0 },
    { chainDir: "/invalid", workTimeoutMs: 0 },
    { chainDir: "/invalid", failureStage: "unowned-delete" },
    { chainDir: "/invalid", overflowRecipient: "true" },
  ])
    await assert.rejects(
      withNativeLocalnet(options, () => {
        throw Error("must not run");
      }),
    );
});

test(
  "owned process group escalation stops a nested child that ignores SIGTERM",
  { timeout: 10000 },
  async () => {
    const processes = new OwnedProcesses();
    const script = `const {spawn}=require('node:child_process');process.on('SIGTERM',()=>{});const child=spawn(process.execPath,['-e',"process.on('SIGTERM',()=>{});console.log(process.pid);setInterval(()=>{},1000)"],{stdio:['ignore','pipe','ignore']});child.stdout.on('data',data=>process.stdout.write(data));setInterval(()=>{},1000);`;
    const entry = processes.start(process.execPath, ["-e", script], {
      stdio: ["ignore", "pipe", "ignore"],
    });
    const nestedPid = Number(
      await new Promise((r) => entry.child.stdout.once("data", r)),
    );
    assert(Number.isSafeInteger(nestedPid) && nestedPid > 0);
    await processes.stop(20);
    // The killed nested child can briefly be a zombie awaiting the OS reaper;
    // parent pipe closure confirms every inherited writer closed, so it cannot run.
    assert.equal(entry.closed, true);
    assert.equal(entry.child.stdout.readableEnded, true);
  },
);
