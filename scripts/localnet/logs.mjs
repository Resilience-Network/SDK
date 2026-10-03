import { constants } from "node:fs";
import { open, writeFile, lstat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
export const MAX_NATIVE_LOG_BYTES = 8 * 1024 * 1024;
const safeCodes = new Set(["ENOENT", "EACCES", "ENOSPC", "EIO", "ELOOP", "EEXIST"]);
const refusal = (code) => Object.assign(Error("Owned log capture refused"), { code });
const localCodes = new Set([
  "INVALID_LOG_SOURCE",
  "INVALID_LOG_DIRECTORY",
  "LOG_LIMIT_EXCEEDED",
]);
/** Script-internal evidence capture. Errors contain only fixed codes, never log/key contents. */
export async function captureOwnedLogs(runtime, artifacts, names, secrets) {
  if (
    !Array.isArray(names) ||
    new Set(names).size !== names.length ||
    !names.every(
      (n) => typeof n === "string" && /^(command|node)-[1-9][0-9]*\.log$/.test(n),
    ) ||
    !Array.isArray(secrets) ||
    !secrets.every((s) => typeof s === "string" && s.length > 0)
  )
    throw Error("Invalid owned log manifest");
  const logs = [],
    orderedSecrets = [...new Set(secrets)].sort((a, b) => b.length - a.length);
  for (const file of names) {
    let handle;
    try {
      for (const directory of [runtime, artifacts]) {
        const stat = await lstat(directory);
        if (!stat.isDirectory() || stat.isSymbolicLink())
          throw refusal("INVALID_LOG_DIRECTORY");
      }
      const path = join(runtime, file),
        stat = await lstat(path);
      if (!stat.isFile() || stat.isSymbolicLink()) throw refusal("INVALID_LOG_SOURCE");
      if (stat.size > MAX_NATIVE_LOG_BYTES) throw refusal("LOG_LIMIT_EXCEEDED");
      handle = await open(
        path,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      );
      const opened = await handle.stat();
      if (!opened.isFile()) throw refusal("INVALID_LOG_SOURCE");
      if (opened.size > MAX_NATIVE_LOG_BYTES) throw refusal("LOG_LIMIT_EXCEEDED");
      // Bound the actual read too, even if the source grows after stat.
      const chunks = [],
        buffer = Buffer.alloc(65536);
      let size = 0;
      while (true) {
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
        if (bytesRead === 0) break;
        size += bytesRead;
        if (size > MAX_NATIVE_LOG_BYTES) throw refusal("LOG_LIMIT_EXCEEDED");
        chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
      }
      let data = Buffer.concat(chunks).toString("utf8");
      for (const secret of orderedSecrets)
        data = data.replaceAll(secret, "[REDACTED_TEST_SECRET]");
      if (orderedSecrets.some((secret) => data.includes(secret)))
        throw Error("Redaction failed");
      const encoded = Buffer.from(data, "utf8");
      // Refuse replacing an existing artifact or following an artifact symlink.
      await writeFile(join(artifacts, file), encoded, { mode: 0o600, flag: "wx" });
      logs.push({
        file,
        status: "captured",
        sizeBytes: encoded.length,
        sha256: createHash("sha256").update(encoded).digest("hex"),
      });
    } catch (error) {
      logs.push({
        file,
        status: "failed",
        code:
          safeCodes.has(error?.code) || localCodes.has(error?.code)
            ? error.code
            : "LOG_CAPTURE_FAILED",
      });
    } finally {
      await handle?.close().catch(() => {});
    }
  }
  // Empty manifests are valid only when the run failed before any command was opened.
  return {
    status: logs.every((l) => l.status === "captured") ? "passed" : "failed",
    logs,
  };
}
