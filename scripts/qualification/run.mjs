// Serial owned candidate checks. No checkout mutation, publication or hosted dispatch.
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { platform, arch } from "node:os";
import {
  profile,
  stages,
  verifyOutput,
  verifyArtifact,
  verifyNativeChecks,
  entryScripts,
} from "./profile.mjs";
import { verifyCapturedLogs } from "../localnet/verify-logs.mjs";
const root = fileURLToPath(new URL("../../", import.meta.url));
const hash = (data) => createHash("sha256").update(data).digest("hex");
const command = (name, args, cwd = root) =>
  execFileSync(name, args, {
    cwd,
    encoding: "utf8",
    timeout: 30000,
    maxBuffer: 2 * 1024 * 1024,
  }).trim();
const clean = (cwd) =>
  assert.equal(
    command("git", ["status", "--porcelain", "--untracked-files=all"], cwd),
    "",
    "Checkout must be clean",
  );
const pin = JSON.parse(await readFile(join(root, "protocol-source.json")));
const chain = process.env.RSC_CHAIN_DIR;
assert(chain, "RSC_CHAIN_DIR is an explicit owner-provided private pinned checkout");
assert(process.env.npm_execpath, "Run through npm");
const revision = command("git", ["rev-parse", "HEAD"]);
assert.match(
  process.env.RSC_CANDIDATE_REVISION ?? "",
  /^[a-f0-9]{40}$/,
  "Explicit full candidate revision required",
);
assert.equal(
  revision,
  process.env.RSC_CANDIDATE_REVISION,
  "Candidate revision mismatch",
);
clean(root);
clean(chain);
assert.equal(
  command("git", ["rev-parse", "HEAD"], chain),
  pin.revision,
  "Native source mismatch",
);
assert.equal(
  hash(await readFile(join(chain, pin.vectorPaths[0]))),
  pin.vectorSha256,
  "Native vectors mismatch",
);
assert(
  process.argv.slice(2).every((arg) => arg === "--preflight"),
  "Unknown qualification argument",
);
assert.equal(command("python3", ["--version"]), profile.python);
assert.equal(process.version, profile.node);
assert.equal(platform(), profile.platform);
assert.equal(arch(), profile.arch);
assert.equal(
  command(process.execPath, [process.env.npm_execpath, "--version"]),
  profile.npm,
);
assert.equal(command("go", ["version"], chain), profile.go);
assert.equal(command("go", ["env", "CGO_ENABLED"], chain), "1");
assert.equal(command("rustc", ["--version"], chain), profile.rust);
assert.equal(
  process.env.RSC_BROWSER_ENGINES,
  "chromium",
  "Explicit selected local engine profile required",
);
assert.equal(
  process.env.RSC_BROWSER_CHROMIUM_CHANNEL,
  "chrome",
  "Explicit installed Chrome required",
);
if (process.argv.includes("--preflight")) {
  console.log("Candidate preflight PASS; no suites executed.");
  process.exit(0);
}
const id = randomUUID(),
  directory = join(root, "artifacts/qualification", id);
await mkdir(directory, { recursive: true, mode: 0o700 });
const report = {
  schema: 1,
  kind: "local-candidate-qualification",
  id,
  revision,
  chainRevision: pin.revision,
  profile,
  startedAt: new Date().toISOString(),
  result: "running",
  stages: [],
  sourceSha256: {},
  externalGatesPassed: false,
};
for (const file of [
  "package.json",
  "package-lock.json",
  "protocol-source.json",
  "qualification/api-v1.json",
  "scripts/qualification/run.mjs",
  "scripts/qualification/profile.mjs",
])
  report.sourceSha256[file] = hash(await readFile(join(root, file)));
let child,
  interrupted = false;
const terminate = () => {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  try {
    process.kill(-child.pid, "SIGTERM");
  } catch (error) {
    if (error.code !== "ESRCH") throw error;
  }
};
const abort = () => {
  interrupted = true;
  terminate();
};
process.once("SIGINT", abort);
process.once("SIGTERM", abort);
const nativeRoot = join(root, "test-results/localnet");
const listNative = async () => {
  try {
    return new Set(await readdir(nativeRoot));
  } catch (error) {
    if (error.code === "ENOENT") return new Set();
    throw error;
  }
};
async function execute(stage) {
  const previous = await listNative(),
    start = Date.now();
  const args = entryScripts[stage.id]
    ? [entryScripts[stage.id]]
    : [process.env.npm_execpath, ...(stage.args ?? ["run", stage.script])];
  report.activeStage = stage.id;
  console.log("Starting candidate stage: " + stage.id);
  const result = await new Promise((resolve, reject) => {
    child = spawn(process.execPath, args, {
      cwd: root,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
      detached: true,
    });
    const chunks = [];
    let size = 0,
      failed = false;
    const stop = () => {
      failed = true;
      terminate();
    };
    const timer = setTimeout(stop, stage.timeout);
    const receive = (chunk) => {
      size += chunk.length;
      if (size > 8 * 1024 * 1024) stop();
      else chunks.push(chunk);
    };
    child.stdout.on("data", receive);
    child.stderr.on("data", receive);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, failed, output: Buffer.concat(chunks) });
    });
  });
  child = undefined;
  const log = stage.id + ".log";
  await writeFile(join(directory, log), result.output, { mode: 0o600, flag: "wx" });
  assert(
    !interrupted && !result.failed && result.code === 0,
    `Candidate stage failed: ${stage.id}; restricted log retained`,
  );
  const count = verifyOutput(stage, result.output.toString("utf8"));
  const native = [];
  if (stage.nativeRuns) {
    const added = [...(await listNative())].filter((value) => !previous.has(value));
    assert.equal(
      added.length,
      stage.nativeRuns,
      "Required native owned runs missing or concurrent run detected",
    );
    for (const ownershipId of added) {
      const path = join(nativeRoot, ownershipId, "evidence.json");
      const bytes = await readFile(path),
        e = JSON.parse(bytes);
      assert.equal(e.sdkRevision, revision);
      assert.equal(e.sdkWorkingTree, "");
      assert.equal(e.chainRevision, pin.revision);
      assert.equal(e.cgo, "1");
      assert.equal(e.goVersion, profile.go);
      assert.equal(e.rustVersion, profile.rust);
      assert.equal(e.teardown.allOwnedChildrenClosed, true);
      verifyNativeChecks(e.checks, stage.negative ? 0 : (stage.minimumChecks ?? 1));
      if (stage.negative) {
        assert(["failed", "interrupted"].includes(e.status));
        assert.equal(e.runtimeRetained, true);
      } else {
        assert.equal(e.status, "passed");
        assert.equal(e.runtimeRetained, false);
      }
      const failedFiles = e.logCapture.logs
        .filter((l) => l.status === "failed")
        .map((l) => l.file);
      assert(stage.negative || failedFiles.length === 0);
      assert(failedFiles.length <= 1 && failedFiles.every((f) => f === "node-1.log"));
      const secrets = [];
      if (stage.negative) {
        for (const name of await readdir(join(e.runtime, "keys")).catch((error) => {
          if (error.code === "ENOENT") return [];
          throw error;
        }))
          secrets.push(
            JSON.parse(await readFile(join(e.runtime, "keys", name))).privateKey,
          );
      }
      await verifyCapturedLogs(e, { secrets, failedFiles });
      native.push({
        ownershipId,
        status: e.status,
        checks: e.checks.length,
        logs: e.logCapture.logs.length,
        evidenceSha256: hash(bytes),
        runtimeRetained: e.runtimeRetained,
        ownedChildrenClosed: true,
        retainedLogHashesVerified: true,
      });
    }
  }
  clean(root);
  clean(chain);
  assert.equal(command("git", ["rev-parse", "HEAD"], chain), pin.revision);
  assert.equal(command("git", ["rev-parse", "HEAD"]), revision);
  const record = {
    id: stage.id,
    command: ["node", ...args],
    status: "pass",
    count,
    native,
    durationMilliseconds: Date.now() - start,
    outputSha256: hash(result.output),
    outputBytes: result.output.length,
  };
  report.stages.push(record);
  await writeFile(
    join(directory, "manifest.json"),
    JSON.stringify(report, null, 2) + "\n",
    { mode: 0o600 },
  );
  console.log(
    `Candidate stage PASS: ${stage.id}; ${count ?? native.length} evidence count`,
  );
}
try {
  for (const stage of stages) {
    assert(!interrupted);
    await execute(stage);
  }
  // Artifact predicates independently reject stale, dirty or partial child evidence.
  const summaries = [];
  for (const [name, relative] of [
    ["api", "api-qualification"],
    ["rp", "webauthn-verifier"],
    ["browser", "browser"],
    ["installed", "installed-session"],
    ["combined", "passkey-session"],
  ]) {
    const bytes = await readFile(join(root, "artifacts", relative, "latest.json")),
      e = JSON.parse(bytes);
    if (name === "api") report.archiveSha256 = e.archiveSha256;
    verifyArtifact(name, e, revision, report.archiveSha256);
    summaries.push({ name, sha256: hash(bytes) });
  }
  report.activeStage = null;
  report.artifacts = summaries;
  report.result = "pass";
} catch (error) {
  report.result = interrupted ? "interrupted" : "failed";
  report.failure = "Required candidate stage or evidence rejected";
  process.exitCode = 1;
  console.error(report.failure);
} finally {
  report.finishedAt = new Date().toISOString();
  process.removeListener("SIGINT", abort);
  process.removeListener("SIGTERM", abort);
  await writeFile(
    join(directory, "manifest.json"),
    JSON.stringify(report, null, 2) + "\n",
    { mode: 0o600 },
  );
  await writeFile(
    join(root, "artifacts/qualification/latest.json"),
    JSON.stringify(report, null, 2) + "\n",
    { mode: 0o600 },
  );
  console.log(
    `Candidate ${report.result}: ${report.stages.length}/${stages.length} stages; manifest ${join(directory, "manifest.json")}`,
  );
}
