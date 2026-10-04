import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
const supervisor = fileURLToPath(new URL("./group-supervisor.mjs", import.meta.url));

/** A live spawned supervisor leases each POSIX group until bounded teardown. */
export class OwnedProcesses {
  #children = [];
  get allClosed() {
    return this.#children.every((e) => e.closed && !e.containmentLost);
  }
  get pids() {
    return this.#children.map((entry) => entry.child.pid).filter(Boolean);
  }
  start(command, args, options = {}) {
    const posix = process.platform !== "win32";
    const stdio = options.stdio ?? "pipe";
    const child = spawn(
      posix ? process.execPath : command,
      posix ? [supervisor, command, ...args] : args,
      {
        ...options,
        shell: false,
        detached: posix,
        stdio: posix
          ? [...(Array.isArray(stdio) ? stdio : [stdio, stdio, stdio]), "ipc"]
          : stdio,
      },
    );
    const entry = {
      child,
      closed: false,
      exited: false,
      leaseExited: false,
      stopping: false,
      containmentLost: false,
      targetPid: posix ? null : child.pid,
      error: null,
    };
    let commandDone;
    entry.done = new Promise((resolve) => {
      commandDone = resolve;
    });
    entry.closedPromise = new Promise((resolve) => {
      child.once("error", () => {
        entry.error = Error("Owned process failed to spawn");
        commandDone({ code: null, signal: null });
      });
      child.once("close", (code, signal) => {
        entry.closed = true;
        commandDone({ code, signal });
        resolve();
      });
    });
    child.once("exit", () => {
      entry.leaseExited = true;
      if (!posix) entry.exited = true;
      if (posix && !entry.stopping) {
        entry.containmentLost = true;
        entry.error = Error("Owned group supervisor exited unexpectedly");
      }
    });
    if (posix)
      child.on("message", (message) => {
        if (message.type === "spawn") entry.targetPid = message.pid;
        else if (message.type === "exit") entry.exited = true;
        else if (message.type === "close")
          commandDone({ code: message.code, signal: message.signal });
        else if (message.type === "spawn-error") {
          entry.error = Error("Owned command failed to spawn");
          entry.exited = true;
          commandDone({ code: null, signal: null });
        }
      });
    this.#children.push(entry);
    return entry;
  }
  // Target exit does not end the group lease. Never signal an exited lease PID.
  async stop(graceMs = 5000, killWaitMs = 2000) {
    assert(Number.isSafeInteger(graceMs) && graceMs >= 1 && graceMs <= 10000);
    assert(Number.isSafeInteger(killWaitMs) && killWaitMs >= 1 && killWaitMs <= 10000);
    const terminate = (entry, signal) => {
      if (entry.closed || entry.leaseExited || !entry.child.pid) return;
      entry.stopping = true;
      try {
        if (process.platform === "win32") entry.child.kill(signal);
        else process.kill(-entry.child.pid, signal);
      } catch (error) {
        if (error.code !== "ESRCH") throw error;
      }
    };
    const closed = () => Promise.all(this.#children.map((e) => e.closedPromise));
    const bounded = async (ms) => {
      let timer;
      try {
        return await Promise.race([
          closed().then(() => true),
          new Promise((resolve) => {
            timer = setTimeout(() => resolve(false), ms);
          }),
        ]);
      } finally {
        clearTimeout(timer);
      }
    };
    for (const entry of this.#children) terminate(entry, "SIGTERM");
    if (!(await bounded(graceMs))) {
      for (const entry of this.#children) terminate(entry, "SIGKILL");
      assert(await bounded(killWaitMs), "Owned child did not close after kill");
    }
    assert(this.allClosed, "Owned process containment lost");
  }
}
