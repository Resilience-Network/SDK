import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, lstat } from "node:fs/promises";
import { join } from "node:path";
/** Qualification checker, independent of capture; verifies the bytes actually retained. */
export async function verifyCapturedLogs(
  evidence,
  { secrets = [], failedFiles = [] } = {},
) {
  const expected = evidence.commands.map((command) => command.log),
    capture = evidence.logCapture;
  assert.equal(new Set(expected).size, expected.length);
  assert.deepEqual(
    capture.logs.map((entry) => entry.file),
    expected,
  );
  assert.equal(capture.status, failedFiles.length === 0 ? "passed" : "failed");
  if (evidence.status === "passed")
    assert(expected.length > 0, "successful native run must capture real command logs");
  for (const entry of capture.logs) {
    if (failedFiles.includes(entry.file)) {
      assert.equal(entry.status, "failed");
      assert.equal(typeof entry.code, "string");
      continue;
    }
    assert.equal(entry.status, "captured");
    const path = join(evidence.artifacts, entry.file),
      stat = await lstat(path);
    assert(stat.isFile() && !stat.isSymbolicLink());
    const data = await readFile(path);
    assert.equal(entry.sizeBytes, data.length);
    assert.equal(entry.sha256, createHash("sha256").update(data).digest("hex"));
    for (const secret of secrets)
      assert(
        !data.toString("utf8").includes(secret),
        "generated secret leaked to captured log",
      );
  }
  const metadata = await readFile(join(evidence.artifacts, "evidence.json"), "utf8");
  for (const secret of secrets)
    assert(!metadata.includes(secret), "generated secret leaked to evidence");
}
