import assert from "node:assert/strict";
import { mkdtemp, realpath, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { spawn } from "node:child_process";
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

test(
  "owned cleanup closes inherited descendants after their command leader exits",
  { timeout: 10000 },
  async () => {
    const processes = new OwnedProcesses(),
      other = new OwnedProcesses();
    const unrelated = other.start(
      process.execPath,
      ["-e", "setInterval(()=>{},1000)"],
      { stdio: "ignore" },
    );
    const script = `const {spawn}=require('node:child_process');const child=spawn(process.execPath,['-e',"process.on('SIGTERM',()=>{});console.log('descendant-ready');setInterval(()=>{},1000)"],{stdio:['ignore','inherit','ignore']});child.unref();process.exit(0);`;
    const entry = processes.start(process.execPath, ["-e", script], {
      stdio: ["ignore", "pipe", "ignore"],
    });
    try {
      await new Promise((resolve) => entry.child.stdout.once("data", resolve));
      const deadline = Date.now() + 2000;
      while (!entry.exited && Date.now() < deadline) await delay(5);
      assert.equal(entry.exited, true);
      assert.equal(entry.closed, false);
      await processes.stop(20);
      assert.equal(entry.closed, true);
      assert.equal(entry.child.stdout.readableEnded, true);
      assert.equal(unrelated.closed, false);
      await processes.stop(20);
    } finally {
      // The pre-fix fixture leaves this known inherited group alive. Close only
      // that freshly spawned public fixture; never infer ownership from old files.
      if (!entry.closed) {
        try {
          process.kill(-entry.child.pid, "SIGKILL");
        } catch (e) {
          if (e.code !== "ESRCH") throw e;
        }
        await new Promise((resolve) => entry.child.once("close", resolve));
      }
      await other.stop(20);
    }
  },
);

test(
  "group lease preserves command exit and spawn-failure results until cleanup",
  { timeout: 10000 },
  async () => {
    for (const missing of [false, true]) {
      const processes = new OwnedProcesses();
      const entry = processes.start(
        missing ? "/sdk-fixture/nonexistent-command" : process.execPath,
        missing ? [] : ["-e", "process.exit(3)"],
        { stdio: "ignore" },
      );
      try {
        const result = await entry.done;
        assert.equal(result.code, missing ? null : 3);
        assert.equal(Boolean(entry.error), missing);
        assert.equal(entry.exited, true);
        assert.equal(entry.closed, false);
      } finally {
        await processes.stop(20);
      }
      assert.equal(entry.closed, true);
    }
  },
);

test(
  "owner IPC disconnect closes its detached owned group",
  { timeout: 10000 },
  async () => {
    const url = new URL("../scripts/localnet/processes.mjs", import.meta.url).href;
    const script = `import {OwnedProcesses} from ${JSON.stringify(url)};
    const entry=new OwnedProcesses().start(process.execPath,['-e',"process.on('SIGTERM',()=>{});console.log('OWNED_READY');setInterval(()=>{},1000)"],{stdio:['ignore','inherit','inherit']});
    console.log('LEASE='+entry.child.pid);setTimeout(()=>process.exit(0),500);`;
    const owner = spawn(process.execPath, ["--input-type=module", "-e", script], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    owner.stdout.on("data", (data) => (output += data));
    owner.stderr.resume();
    const closed = new Promise((resolve) =>
      owner.once("close", (code) => resolve(code)),
    );
    let timer;
    try {
      const code = await Promise.race([
        closed,
        new Promise((_, reject) => {
          timer = setTimeout(
            () => reject(Error("Owner-disconnect containment deadline")),
            8000,
          );
        }),
      ]);
      assert.equal(code, 0);
      assert(output.includes("OWNED_READY"));
      assert.equal(owner.stdout.readableEnded, true);
    } finally {
      clearTimeout(timer);
      if (!owner.stdout.readableEnded) {
        const pid = Number(/LEASE=(\d+)/.exec(output)?.[1]);
        if (Number.isSafeInteger(pid) && pid > 0)
          try {
            process.kill(-pid, "SIGKILL");
          } catch (e) {
            if (e.code !== "ESRCH") throw e;
          }
        if (owner.exitCode === null) owner.kill("SIGKILL");
        await closed;
      }
    }
  },
);
