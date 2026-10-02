import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { ChainRpcClient, RpcContractError, hexToBytes } from "../dist/index.js";
import { expected, findFixture } from "./rpc-methods-helpers.mjs";

test(
  "typed reads validate native fixtures through real Node fetch under concurrent operations",
  { timeout: 10_000 },
  async (t) => {
    const f = findFixture("ed25519", "rsc_getSessionGrant"),
      requests = [],
      unexpected = [];
    let corruptIdentity = false,
      corruptGrant = false;
    const http = createServer(async (request, response) => {
      try {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const batch = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        requests.push(batch);
        const replies = batch.map((call) => {
          const source =
            call.method === "rsc_getAuthorizationFinalityStatus"
              ? f.identity
              : findFixture("ed25519", call.method).response;
          const reply = structuredClone(source);
          reply.id = call.id;
          if (corruptIdentity && call.method === "rsc_getAuthorizationFinalityStatus")
            reply.result.chainId = "0x1";
          if (corruptGrant && call.method === "rsc_getSessionGrant")
            delete reply.result.policyHash;
          return reply;
        });
        response.setHeader("Content-Type", "application/json");
        response.end(JSON.stringify(replies.reverse()));
      } catch (error) {
        unexpected.push(error);
        response.destroy();
      }
    });
    await new Promise((resolve, reject) => {
      http.once("error", reject);
      http.listen(0, "127.0.0.1", resolve);
    });
    t.after(async () => {
      http.closeAllConnections();
      await new Promise((resolve, reject) =>
        http.close((error) => (error ? reject(error) : resolve())),
      );
      assert.deepEqual(unexpected, []);
    });
    const client = new ChainRpcClient({
      url: `http://127.0.0.1:${http.address().port}/`,
      expected,
    });
    const owner = hexToBytes(f.params[0]),
      id = hexToBytes(f.params[1]);
    const snapshots = await Promise.all(
      Array.from({ length: 20 }, () => client.getAuthorizationSnapshot(owner, id)),
    );
    assert(
      snapshots.every(
        (s) => s.grant.sessionNonce === 0n && s.grant.usableAtObservedBlock,
      ),
    );
    assert.equal(requests.length, 20);
    const ids = requests.flatMap((batch) => batch.map((call) => call.id));
    assert.equal(new Set(ids).size, 120);
    snapshots[0].grant.publicKey.fill(0);
    assert.notDeepEqual(snapshots[0].grant.publicKey, snapshots[1].grant.publicKey);
    corruptIdentity = true;
    await assert.rejects(
      client.getSessionGrant(owner, id),
      (e) => e instanceof RpcContractError && e.code === "CHAIN_IDENTITY_MISMATCH",
    );
    corruptIdentity = false;
    corruptGrant = true;
    await assert.rejects(
      client.getSessionGrant(owner, id),
      (e) => e instanceof RpcContractError && e.code === "INVALID_RESULT",
    );
    assert.equal(requests.length, 22);
  },
);
