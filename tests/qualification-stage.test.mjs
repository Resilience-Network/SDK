import assert from "node:assert/strict";
import test from "node:test";
import { runStage } from "../scripts/qualification/stage.mjs";
async function within(promise, ms) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(Error("Fixture completion deadline")), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
test(
  "stage timeout settles even when its actual child ignores SIGTERM",
  { timeout: 10000 },
  async () => {
    let child;
    const pending = runStage({
      command: process.execPath,
      args: [
        "-e",
        "process.on('SIGTERM',()=>{});console.log('READY');setInterval(()=>{},1000)",
      ],
      timeoutMs: 800,
      graceMs: 20,
      killWaitMs: 2000,
      onStart: (value) => {
        child = value;
      },
    });
    try {
      const result = await within(pending, 2000);
      assert.equal(result.failed, true);
      assert.equal(result.reason, "timeout");
      assert.equal(result.cleanupClosed, true);
      assert(result.output.includes(Buffer.from("READY")));
    } finally {
      if (child && child.exitCode === null && child.signalCode === null) {
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch (error) {
          if (error.code !== "ESRCH") throw error;
        }
      }
      await pending;
    }
  },
);

const fixture = (args, options = {}) =>
  runStage({
    command: process.execPath,
    args,
    timeoutMs: 2000,
    graceMs: 20,
    killWaitMs: 2000,
    ...options,
  });
test(
  "stage output overflow retains a bounded prefix and closes an uncooperative writer",
  { timeout: 10000 },
  async () => {
    const result = await within(
      fixture(
        [
          "-e",
          "process.on('SIGTERM',()=>{});console.log('x'.repeat(4096));setInterval(()=>{},1000)",
        ],
        { maxOutputBytes: 1024 },
      ),
      5000,
    );
    assert.equal(result.failed, true);
    assert.equal(result.reason, "output-limit");
    assert.equal(result.cleanupClosed, true);
    assert.equal(result.output.length, 1024);
    assert(result.outputBytes > 1024);
  },
);
test(
  "stage abort closes an uncooperative child and pre-abort dispatches nothing",
  { timeout: 10000 },
  async () => {
    const controller = new AbortController();
    const result = await within(
      fixture(
        [
          "-e",
          "process.on('SIGTERM',()=>{});console.log('READY');setInterval(()=>{},1000)",
        ],
        {
          signal: controller.signal,
          onStart: (child) => child.stdout.once("data", () => controller.abort()),
        },
      ),
      5000,
    );
    assert.equal(result.reason, "interrupted");
    assert.equal(result.failed, true);
    assert.equal(result.cleanupClosed, true);
    let started = false;
    const before = await fixture(["-e", "throw Error('must not start')"], {
      signal: controller.signal,
      onStart: () => {
        started = true;
      },
    });
    assert.equal(started, false);
    assert.equal(before.reason, "interrupted");
    assert.equal(before.cleanupClosed, true);
  },
);
test(
  "stage command success, nonzero exit and spawn failure remain distinct",
  { timeout: 10000 },
  async () => {
    const success = await fixture(["-e", "console.log('OK')"]);
    assert.equal(success.code, 0);
    assert.equal(success.failed, false);
    assert.equal(success.cleanupClosed, true);
    const failure = await fixture(["-e", "process.exit(3)"]);
    assert.equal(failure.code, 3);
    assert.equal(failure.reason, "command-failed");
    assert.equal(failure.cleanupClosed, true);
    const missing = await fixture([], { command: "/sdk-fixture/nonexistent-command" });
    assert.equal(missing.code, null);
    assert.equal(missing.failed, true);
    assert.equal(missing.reason, "spawn-or-containment-error");
    assert.equal(missing.cleanupClosed, true);
  },
);
test(
  "stage closes inherited writers after the command leader exits",
  { timeout: 10000 },
  async () => {
    const script = `const {spawn}=require('node:child_process');const child=spawn(process.execPath,['-e',"process.on('SIGTERM',()=>{});console.log('READY');setInterval(()=>{},1000)"],{stdio:['ignore','inherit','ignore']});child.unref();process.exit(0);`;
    const result = await within(fixture(["-e", script]), 5000);
    assert.equal(result.code, 0);
    assert.equal(result.failed, false);
    assert.equal(result.cleanupClosed, true);
  },
);
test(
  "stage forced termination waits for detached owned groups even with ignored stdout",
  { timeout: 12000 },
  async () => {
    const url = new URL("../scripts/localnet/processes.mjs", import.meta.url).href;
    const script = `import {OwnedProcesses} from ${JSON.stringify(url)};
    process.on('SIGTERM',()=>{});
    const entry=new OwnedProcesses().start(process.execPath,['-e',"process.on('SIGTERM',()=>{});setInterval(()=>{},1000)"],{stdio:'ignore'});
    entry.child.on('message',m=>{if(m.type==='spawn') console.log('NESTED_STARTED');});
    setInterval(()=>{},1000);`;
    const started = Date.now();
    const result = await within(
      fixture(["--input-type=module", "-e", script], {
        timeoutMs: 800,
        killWaitMs: 7000,
      }),
      10000,
    );
    assert.equal(result.reason, "timeout");
    assert.equal(result.cleanupClosed, true);
    assert(result.output.includes(Buffer.from("NESTED_STARTED")));
    assert(
      Date.now() - started >= 4500,
      "must await orphan group's actual descriptor closure",
    );
  },
);
test(
  "stage finalizes a failed result when an untracked detached session retains a pipe",
  { timeout: 10000 },
  async () => {
    // Explicitly created public adversarial fixture. Its fresh recorded group is
    // cleaned here; the controller must never guess ownership of such an escape.
    const script = `const {spawn}=require('node:child_process');const child=spawn(process.execPath,['-e',"process.on('SIGTERM',()=>{});setInterval(()=>{},1000)"],{detached:true,stdio:['ignore','inherit','ignore']});console.log('ESCAPED='+child.pid);child.unref();process.exit(0);`;
    const result = await within(fixture(["-e", script], { killWaitMs: 50 }), 5000);
    const pid = Number(/ESCAPED=(\d+)/.exec(result.output.toString())?.[1]);
    assert(Number.isSafeInteger(pid) && pid > 0);
    try {
      assert.equal(result.code, 0);
      assert.equal(result.failed, true);
      assert.equal(result.reason, "cleanup-failed");
      assert.equal(result.cleanupClosed, false);
    } finally {
      try {
        process.kill(-pid, "SIGKILL");
      } catch (error) {
        if (error.code !== "ESRCH") throw error;
      }
    }
  },
);
test("invalid stage budgets are rejected before spawning", async () => {
  for (const options of [
    { timeoutMs: 0 },
    { graceMs: 0 },
    { killWaitMs: 10001 },
    { maxOutputBytes: NaN },
    { maxOutputBytes: 8388609 },
  ]) {
    let started = false;
    await assert.rejects(
      fixture([], {
        ...options,
        onStart: () => {
          started = true;
        },
      }),
    );
    assert.equal(started, false);
  }
});
