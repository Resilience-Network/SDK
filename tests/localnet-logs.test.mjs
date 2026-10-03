import assert from "node:assert/strict";
import {
  mkdtemp,
  mkdir,
  readFile,
  rm,
  stat,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { captureOwnedLogs, MAX_NATIVE_LOG_BYTES } from "../scripts/localnet/logs.mjs";
async function fixture(work) {
  const root = await mkdtemp(join(tmpdir(), "sdk-log-unit-")),
    runtime = join(root, "runtime"),
    artifacts = join(root, "artifacts");
  await mkdir(runtime);
  await mkdir(artifacts);
  try {
    await work({ root, runtime, artifacts });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
test("owned log manifest records exact redacted UTF-8 sizes and independent hashes, including empty logs", async () =>
  fixture(async ({ runtime, artifacts }) => {
    const secret = "unit-private-key-secret-0123456789",
      text = `public α\n${secret}\n${secret}\n`;
    await writeFile(join(runtime, "command-1.log"), text);
    await writeFile(join(runtime, "node-1.log"), "");
    const result = await captureOwnedLogs(
      runtime,
      artifacts,
      ["command-1.log", "node-1.log"],
      [secret, secret.slice(0, 20)],
    );
    assert.equal(result.status, "passed");
    assert.equal(result.logs.length, 2);
    for (const entry of result.logs) {
      const data = await readFile(join(artifacts, entry.file));
      assert.equal(entry.status, "captured");
      assert.equal(entry.sizeBytes, data.length);
      assert.equal(entry.sha256, createHash("sha256").update(data).digest("hex"));
      assert(!data.toString().includes(secret));
      assert.equal((await stat(join(artifacts, entry.file))).mode & 0o777, 0o600);
    }
    assert.equal(await readFile(join(runtime, "command-1.log"), "utf8"), text);
    assert.equal(
      await readFile(join(artifacts, "command-1.log"), "utf8"),
      "public α\n[REDACTED_TEST_SECRET]\n[REDACTED_TEST_SECRET]\n",
    );
  }));
test("missing log capture fails explicitly without suppressing other log evidence", async () =>
  fixture(async ({ runtime, artifacts }) => {
    await writeFile(join(runtime, "node-1.log"), "public");
    const r = await captureOwnedLogs(
      runtime,
      artifacts,
      ["command-1.log", "node-1.log"],
      [],
    );
    assert.equal(r.status, "failed");
    assert.deepEqual(r.logs[0], {
      file: "command-1.log",
      status: "failed",
      code: "ENOENT",
    });
    assert.equal(r.logs[1].status, "captured");
  }));
test("capture refuses source/destination symlinks, nonregular logs and artifact replacement", async () =>
  fixture(async ({ root, runtime, artifacts }) => {
    const sentinel = join(root, "external-secret"),
      secret = "external-secret-must-not-copy";
    await writeFile(sentinel, secret);
    await symlink(sentinel, join(runtime, "command-1.log"));
    await mkdir(join(runtime, "command-2.log"));
    await writeFile(join(runtime, "node-1.log"), "owned");
    await symlink(sentinel, join(artifacts, "node-1.log"));
    await writeFile(join(runtime, "node-2.log"), "owned");
    await writeFile(join(artifacts, "node-2.log"), "retain");
    const r = await captureOwnedLogs(
      runtime,
      artifacts,
      ["command-1.log", "command-2.log", "node-1.log", "node-2.log"],
      [],
    );
    assert.equal(r.status, "failed");
    assert.deepEqual(
      r.logs.map((x) => x.code),
      ["INVALID_LOG_SOURCE", "INVALID_LOG_SOURCE", "EEXIST", "EEXIST"],
    );
    assert(!JSON.stringify(r).includes(secret));
    assert.equal(await readFile(sentinel, "utf8"), secret);
    assert.equal(await readFile(join(artifacts, "node-2.log"), "utf8"), "retain");
  }));
test("capture refuses directory symlinks and over-limit logs with sanitized manifest failures", async () =>
  fixture(async ({ root, runtime, artifacts }) => {
    await writeFile(join(runtime, "command-1.log"), "");
    await truncate(join(runtime, "command-1.log"), MAX_NATIVE_LOG_BYTES + 1);
    const r = await captureOwnedLogs(runtime, artifacts, ["command-1.log"], []);
    assert.deepEqual(r.logs, [
      { file: "command-1.log", status: "failed", code: "LOG_LIMIT_EXCEEDED" },
    ]);
    const alias = join(root, "alias");
    await symlink(artifacts, alias);
    const a = await captureOwnedLogs(runtime, alias, ["command-1.log"], []);
    assert.equal(a.logs[0].code, "INVALID_LOG_DIRECTORY");
    const b = await captureOwnedLogs(alias, artifacts, ["command-1.log"], []);
    assert.equal(b.logs[0].code, "INVALID_LOG_DIRECTORY");
    await assert.rejects(
      readFile(join(artifacts, "command-1.log")),
      (e) => e.code === "ENOENT",
    );
  }));
test("invalid names, duplicate entries and secrets fail before any filesystem capture; early empty manifests are explicit", async () =>
  fixture(async ({ runtime, artifacts }) => {
    for (const names of [
      ["../secret"],
      ["command-0.log"],
      ["node-1.log", "node-1.log"],
      ["command-1.log/../secret"],
      "command-1.log",
      [null],
    ])
      await assert.rejects(
        captureOwnedLogs(runtime, artifacts, names, []),
        /Invalid owned log manifest/,
      );
    for (const secrets of [[""], [null], "secret"])
      await assert.rejects(
        captureOwnedLogs(runtime, artifacts, [], secrets),
        /Invalid owned log manifest/,
      );
    assert.deepEqual(await captureOwnedLogs(runtime, artifacts, [], []), {
      status: "passed",
      logs: [],
    });
  }));
