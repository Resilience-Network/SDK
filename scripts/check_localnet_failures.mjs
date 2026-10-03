import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { withNativeLocalnet } from "./localnet/harness.mjs";
// Real native failure/interrupt qualification, separately from supervisor unit tests.
const sentinelDir = await mkdtemp(join(tmpdir(), "sdk-native-external-sentinel-")),
  sentinel = join(sentinelDir, "signing-record.json");
const original = '{"existing":"do-not-touch","signingWatermark":999}';
await writeFile(sentinel, original);
const artifactRoot = fileURLToPath(
  new URL("../test-results/localnet/", import.meta.url),
);
const checkEvidence = async (previous, expected) => {
  const created = (await readdir(artifactRoot)).filter((id) => !previous.has(id));
  assert.equal(created.length, 1);
  const evidence = JSON.parse(
    await readFile(join(artifactRoot, created[0], "evidence.json"), "utf8"),
  );
  assert.equal(evidence.status, expected);
  assert.equal(evidence.runtimeRetained, true);
  assert.equal(evidence.teardown.allOwnedChildrenClosed, true);
  const marker = JSON.parse(
    await readFile(join(evidence.runtime, "ownership.json"), "utf8"),
  );
  assert.equal(marker.id, evidence.ownershipId);
  assert.equal(await readFile(sentinel, "utf8"), original);
};
try {
  for (const stage of ["before-start", "after-ready"]) {
    const previous = new Set(await readdir(artifactRoot));
    await assert.rejects(
      withNativeLocalnet({ failureStage: stage }, () => {
        throw Error("must not run");
      }),
    );
    await checkEvidence(previous, "failed");
  }
  const previous = new Set(await readdir(artifactRoot));
  await assert.rejects(
    withNativeLocalnet({ readyTimeoutMs: 1 }, () => {
      throw Error("must not run");
    }),
  );
  await checkEvidence(previous, "failed");
  const beforeHungCallback = new Set(await readdir(artifactRoot));
  await assert.rejects(
    withNativeLocalnet({ workTimeoutMs: 5 }, () => new Promise(() => {})),
  );
  await checkEvidence(beforeHungCallback, "failed");
  for (const signal of ["SIGINT", "SIGTERM"]) {
    const prior = new Set(await readdir(artifactRoot)),
      controller = new AbortController(),
      abort = () => controller.abort();
    process.once(signal, abort);
    try {
      await assert.rejects(
        withNativeLocalnet({ signal: controller.signal }, async () => {
          const aborted = new Promise((resolve) =>
            controller.signal.addEventListener("abort", resolve, { once: true }),
          );
          process.kill(process.pid, signal);
          await aborted;
        }),
      );
      await checkEvidence(prior, "interrupted");
    } finally {
      process.removeListener(signal, abort);
    }
  }
  console.log(
    "Native setup/ready-node/readiness/hung-callback failures and actual SIGINT/SIGTERM retain owned restricted runtime, close owned nodes and preserve external safety sentinel.",
  );
} finally {
  await rm(sentinelDir, { recursive: true });
}
