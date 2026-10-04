// Bounded actual stage controller; no SDK build/dependency imports during install.
import assert from "node:assert/strict";
import { OwnedProcesses } from "../localnet/processes.mjs";

export async function runStage({
  command,
  args,
  cwd,
  env,
  timeoutMs,
  signal,
  onStart,
  graceMs = 10000,
  killWaitMs = 7000,
  maxOutputBytes = 8 * 1024 * 1024,
}) {
  for (const [value, maximum] of [
    [timeoutMs, 3600000],
    [graceMs, 10000],
    [killWaitMs, 10000],
    [maxOutputBytes, 8 * 1024 * 1024],
  ])
    assert(Number.isSafeInteger(value) && value >= 1 && value <= maximum);
  const processes = new OwnedProcesses(),
    chunks = [];
  let entry,
    timer,
    reason = null,
    outputBytes = 0,
    retained = 0,
    outcome;
  let finish;
  const fault = new Promise((resolve) => {
    finish = resolve;
  });
  const fail = (why) => {
    reason ??= why;
    finish();
  };
  const abort = () => fail("interrupted");
  const receive = (chunk) => {
    outputBytes += chunk.length;
    const keep = Math.min(chunk.length, maxOutputBytes - retained);
    if (keep > 0) {
      chunks.push(Buffer.from(chunk.subarray(0, keep)));
      retained += keep;
    }
    if (outputBytes > maxOutputBytes) fail("output-limit");
  };
  let cleanupClosed = false;
  try {
    if (signal?.aborted) fail("interrupted");
    else {
      entry = processes.start(command, args, {
        cwd,
        env,
        stdio: ["ignore", "pipe", "pipe"],
        containment: true,
      });
      entry.child.stdout.on("data", receive);
      entry.child.stderr.on("data", receive);
      // EOF includes every tracked detached group's inherited writer, even when
      // its command ignores/drops stdout. No group is rediscovered from a PID file.
      entry.child.stdio[4]?.resume();
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) abort();
      timer = setTimeout(() => fail("timeout"), timeoutMs);
      onStart?.(entry.child);
      await Promise.race([
        entry.done.then((value) => {
          outcome = value;
        }),
        fault,
      ]);
      if (entry.error) fail("spawn-or-containment-error");
      else if (outcome && outcome.code !== 0) fail("command-failed");
    }
  } catch {
    fail("controller-error");
  } finally {
    clearTimeout(timer);
    try {
      await processes.stop(graceMs, killWaitMs);
      cleanupClosed = processes.allClosed;
    } catch {
      fail("cleanup-failed");
      if (entry) {
        // A bounded failed manifest must still be writable if an untracked
        // session escape retains a pipe. Detachment never qualifies as closure.
        entry.containmentLost = true;
        for (const stream of entry.child.stdio) stream?.destroy?.();
        if (entry.child.connected) entry.child.disconnect();
        entry.child.unref();
      }
    }
    signal?.removeEventListener("abort", abort);
  }
  return {
    code: outcome?.code ?? null,
    signal: outcome?.signal ?? null,
    failed: reason !== null || !cleanupClosed,
    reason,
    cleanupClosed,
    outputBytes,
    output: Buffer.concat(chunks, retained),
  };
}
