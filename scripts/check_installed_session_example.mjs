// Actual native lifecycle executed with an installed npm tarball, not repo dist.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, writeFile, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, randomUUID } from "node:crypto";
const root = fileURLToPath(new URL("../", import.meta.url)),
  directory = await mkdtemp(join(tmpdir(), "rsc-sdk-installed-native-")),
  ownership = randomUUID(),
  npmCli = process.env.npm_execpath,
  report = {
    version: 1,
    kind: "installed-tarball-native-session-example",
    sdkRevision: execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: root,
      encoding: "utf8",
    }).trim(),
    trackedClean:
      execFileSync("git", ["status", "--porcelain", "--untracked-files=no"], {
        cwd: root,
        encoding: "utf8",
      }).trim() === "",
    node: process.version,
  };
assert(npmCli, "Run through npm run example:session-installed");
await writeFile(join(directory, ".owned-installed-example"), ownership, {
  flag: "wx",
  mode: 0o600,
});
let successful = false;
try {
  const npm = (args, options = {}) =>
    execFileSync(process.execPath, [npmCli, ...args], {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 2 * 1024 * 1024,
      timeout: 90000,
      ...options,
    });
  const [packed] = JSON.parse(
      npm(["pack", "--ignore-scripts", "--json", "--pack-destination", directory]),
    ),
    archive = join(directory, packed.filename);
  report.archiveSha256 = createHash("sha256")
    .update(await readFile(archive))
    .digest("hex");
  const consumer = join(directory, "consumer");
  await mkdir(consumer);
  await writeFile(join(consumer, "package.json"), '{"private":true,"type":"module"}\n');
  npm(
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--omit=dev",
      "--package-lock=false",
      archive,
    ],
    { cwd: consumer },
  );
  const source = await readFile(
    new URL("../examples/session-localnet.mjs", import.meta.url),
    "utf8",
  );
  let copied = source;
  for (const [from, to] of [
    [
      '"../scripts/localnet/harness.mjs"',
      JSON.stringify(new URL("./localnet/harness.mjs", import.meta.url).href),
    ],
    [
      '"../scripts/localnet/verify-logs.mjs"',
      JSON.stringify(new URL("./localnet/verify-logs.mjs", import.meta.url).href),
    ],
  ]) {
    assert.equal(copied.split(from).length, 2);
    copied = copied.replace(from, to);
  }
  assert(copied.includes('import * as sdk from "@resilience-network/sdk";'));
  assert(!copied.includes('"../dist/'));
  report.originalExampleSha256 = createHash("sha256").update(source).digest("hex");
  report.copiedExampleSha256 = createHash("sha256").update(copied).digest("hex");
  const examplePath = join(consumer, "session-localnet.mjs");
  await writeFile(examplePath, copied);
  // Only two harness import URLs differ. Every SDK/signer import resolves in consumer.
  const runner = join(consumer, "run.mjs");
  await writeFile(
    runner,
    `import assert from "node:assert/strict";
import {writeFile} from "node:fs/promises";
import {withNativeLocalnet} from ${JSON.stringify(new URL("./localnet/harness.mjs", import.meta.url).href)};
import {runSessionExample} from "./session-localnet.mjs";
const controller=new AbortController(), abort=()=>controller.abort();
process.once("SIGINT",abort);process.once("SIGTERM",abort);
try {
 const result=await withNativeLocalnet({signal:controller.signal},runSessionExample);
 await result.verify();assert.equal(result.evidence.runtimeRetained,false);assert(result.evidence.teardown.allOwnedChildrenClosed);
 await writeFile(${JSON.stringify(join(consumer, "result.json"))},JSON.stringify({ownershipId:result.evidence.ownershipId,chainRevision:result.evidence.chainRevision,cgo:result.evidence.cgo,go:result.evidence.goVersion,rust:result.evidence.rustVersion,checks:result.evidence.checks.length,logs:result.evidence.logCapture.logs.length,runtimeRetained:false,ownedChildrenClosed:true,redactionVerified:true}),{mode:0o600});
}finally{process.removeListener("SIGINT",abort);process.removeListener("SIGTERM",abort);}
`,
  );
  // Async child preserves ownership/cancellation/teardown through its native harness.
  const { spawn } = await import("node:child_process");
  const child = spawn(process.execPath, [runner], {
      cwd: consumer,
      env: process.env,
      stdio: "inherit",
      shell: false,
    }),
    forward = () => child.kill("SIGTERM");
  process.once("SIGINT", forward);
  process.once("SIGTERM", forward);
  let timer;
  try {
    const exit = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolve({ code, signal }));
      timer = setTimeout(() => child.kill("SIGTERM"), 720000);
    });
    assert.equal(exit.code, 0, "Installed native example failed");
    assert.equal(exit.signal, null);
  } finally {
    clearTimeout(timer);
    process.removeListener("SIGINT", forward);
    process.removeListener("SIGTERM", forward);
  }
  report.native = JSON.parse(await readFile(join(consumer, "result.json"), "utf8"));
  report.result = "pass";
  successful = true;
} catch (error) {
  report.result = "failed";
  throw error;
} finally {
  if (successful) {
    assert.equal(
      await readFile(join(directory, ".owned-installed-example"), "utf8"),
      ownership,
    );
    await rm(directory, { recursive: true });
  }
  report.ownedConsumerRemoved = successful;
  const artifact = fileURLToPath(
    new URL("../artifacts/installed-session/", import.meta.url),
  );
  await mkdir(artifact, { recursive: true });
  await writeFile(artifact + "latest.json", JSON.stringify(report, null, 2) + "\n", {
    mode: 0o600,
  });
}
console.log(
  "Installed tarball native example PASS: funded DIRECT activation, both raw session schemes and finalized ROOT revocation; no repository SDK import.",
);
