import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { verifyCapturedLogs } from "./localnet/verify-logs.mjs";
import { withNativeLocalnet } from "./localnet/harness.mjs";
import { hexToBytes } from "../dist/core/index.js";
const controller = new AbortController();
const abort = () => controller.abort();
process.once("SIGINT", abort);
process.once("SIGTERM", abort);
try {
  const secrets = [];
  const captured = await withNativeLocalnet(
    { signal: controller.signal },
    async ({ clients, publicWallets, runtime, evidence }) => {
      for (const name of await readdir(join(runtime, "keys")))
        secrets.push(
          JSON.parse(await readFile(join(runtime, "keys", name), "utf8")).privateKey,
        );
      for (const client of clients) {
        const root = await client.getRootAuthority(
          hexToBytes(publicWallets.owner.address),
        );
        assert.equal(root.authorizationMode, 0);
        const fees = await client.getFeeSuggestions();
        assert.equal(fees.advisory, true);
        const receipt = await client.getTransactionReceipt(
          new Uint8Array(32).fill(247),
        );
        assert.equal(receipt.status, "unknown");
      }
      evidence.checks.push({
        name: "actual SDK root/fee/absent-receipt APIs",
        nodes: clients.length,
      });
      return evidence;
    },
  );
  await verifyCapturedLogs(captured, { secrets });
  assert.equal(captured.runtimeRetained, false);
  console.log(
    "Native positive log manifest, byte sizes, hashes and generated wallet-key redaction verified.",
  );
} finally {
  process.removeListener("SIGINT", abort);
  process.removeListener("SIGTERM", abort);
}
