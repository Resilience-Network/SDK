// POSIX-only owned group lease. Command arguments/environment are not logged.
import { spawn } from "node:child_process";
import { containmentIdentity } from "./processes.mjs";
if (process.platform === "win32" || !process.send) throw Error("Owned IPC required");
const [command, ...args] = process.argv.slice(2);
const containment = process.env.RSC_OWNED_CONTAINMENT && containmentIdentity();
if (containment) process.env.RSC_OWNED_CONTAINMENT = containment;
else delete process.env.RSC_OWNED_CONTAINMENT;
const send = (message) => {
  if (process.connected) process.send(message, () => {});
};
// Remain alive even after the target/its descriptors close. The owner performs
// group teardown while this lease prevents group-ID reuse.
setInterval(() => {}, 1000);
let stopping = false;
const arm = () => {
  if (stopping) return;
  stopping = true;
  setTimeout(() => process.kill(-process.pid, "SIGKILL"), 5000);
};
// With a connected owner, only the owner escalates. Competing kill timers can
// race process exit/reaping. Keep the anchor live through graceful termination.
process.on("SIGTERM", () => {});
const orphan = () => {
  arm();
  process.kill(-process.pid, "SIGTERM");
};
process.on("SIGINT", () => {});
process.on("disconnect", orphan);
const child = spawn(command, args, {
  stdio: ["inherit", "inherit", "inherit", "ignore", ...(containment ? [4] : [])],
  shell: false,
});
child.once("spawn", () => send({ type: "spawn", pid: child.pid }));
child.once("error", () => send({ type: "spawn-error" }));
child.once("exit", (code, signal) => send({ type: "exit", code, signal }));
child.once("close", (code, signal) => send({ type: "close", code, signal }));
