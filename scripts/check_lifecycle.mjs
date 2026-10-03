import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { randomBytes, randomUUID } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import * as sdk from "../dist/index.js";
import { withNativeLocalnet } from "./localnet/harness.mjs";
const controller = new AbortController(),
  abort = () => controller.abort();
process.once("SIGINT", abort);
process.once("SIGTERM", abort);
const signingCounts = new WeakMap();
function testSigner(scheme, secret) {
  const publicKey =
    scheme === 1
      ? ed25519.getPublicKey(secret)
      : p256.getPublicKey(secret, false).slice(1);
  let calls = 0;
  const signer = {
    keyScheme: scheme,
    publicKey,
    async sign({ digest, signal }) {
      assert(!signal.aborted);
      calls++;
      return {
        keyScheme: scheme,
        publicKey: publicKey.slice(),
        signature:
          scheme === 1
            ? ed25519.sign(digest, secret)
            : p256.sign(digest, secret, { prehash: false, lowS: false }),
      };
    },
  };
  signingCounts.set(signer, () => calls);
  return signer;
}
try {
  await withNativeLocalnet(
    { signal: controller.signal, workTimeoutMs: 600000 },
    async (h) => {
      const [client] = h.clients,
        context = { chainId: h.expected.chainId, genesisHash: h.expected.genesisHash };
      const owner = sdk.hexToBytes(h.publicWallets.owner.address),
        recipient = sdk.hexToBytes(h.publicWallets.recipient.address);
      const wallet = JSON.parse(await readFile(h.walletPaths.owner, "utf8"));
      const direct = testSigner(
        1,
        sdk.hexToBytes(`0x${wallet.privateKey}`).slice(0, 32),
      );
      const root = testSigner(1, randomBytes(32)),
        ed = testSigner(1, randomBytes(32)),
        p = testSigner(2, p256.utils.randomSecretKey()),
        nextRoot = testSigner(1, randomBytes(32));
      const config = {
        version: 1,
        threshold: 1,
        keys: [{ keyScheme: 1, publicKey: root.publicKey }],
      };
      const send = client.submitTransaction.bind(client);
      client.submitTransaction = async (canonical, options) => {
        const before = await client.getAccountAuthorizationSnapshot(owner, {
          signal: h.signal,
        });
        const simulation = await client.simulateAuthorizedTransaction(canonical, {
          signal: h.signal,
        });
        const after = await client.getAccountAuthorizationSnapshot(owner, {
          signal: h.signal,
        });
        assert.equal(simulation.advisory, true);
        assert.equal(simulation.authorized, true);
        assert.equal(before.accountNonce, after.accountNonce);
        assert.equal(before.balance, after.balance);
        assert.equal(before.root.authorizationMode, after.root.authorizationMode);
        if (before.root.authorizationMode === 1)
          assert.deepEqual(
            before.root.authority.canonical,
            after.root.authority.canonical,
          );
        h.evidence.checks.push({
          name: "actual advisory native simulation preserves owner state",
          actionStatus: simulation.actionStatus,
          candidateHeight: simulation.candidateHeight.toString(),
        });
        return send(canonical, options);
      };
      const lifecycle = new sdk.SessionLifecycle({
        context,
        client,
        coordinator: new sdk.NonceCoordinator(new sdk.MemoryNonceReservationStore()),
      });
      const fees = {
        gasLimit: 300000n,
        maxFeePerGas: 2000000000n,
        maxPriorityFeePerGas: 1000000000n,
      };
      let reviews = 0;
      const run = async (operation) => {
        const result = await lifecycle.execute({
          owner,
          operation,
          ...fees,
          reservationId: randomUUID(),
          signal: h.signal,
          timeoutMs: 120000,
          reconciliation: { timeoutMs: 90000, maxPolls: 1000, pollIntervalMs: 100 },
          approve: ({ review }) => {
            assert(Object.isFrozen(review));
            reviews++;
            return true;
          },
        });
        h.evidence.checks.push({
          name: operation.kind,
          status: result.flow.reconciliation.status,
          postcondition: result.postcondition,
          transactionHash: sdk.bytesToHex(result.flow.reconciliation.transactionHash),
          reason: result.flow.reconciliation.reason,
          diagnostic: result.flow.reconciliation.diagnostic,
          submission: {
            status: result.flow.submission.status,
            sendAttempts: result.flow.submission.sendAttempts,
            diagnostic: result.flow.submission.diagnostic,
          },
        });
        if (result.flow.reconciliation.status === "unknown") {
          const id = sdk.bytesToHex(result.flow.reconciliation.transactionHash);
          const receipt = await h.http[0].request("rsc_getTransactionReceipt", [id]);
          const transaction = await h.http[0].request("rsc_getTransactionByHash", [id]);
          const block = receipt
            ? await h.http[0].request("rsc_getBlockByNumber", [
                receipt.blockNumber,
                false,
              ])
            : null;
          await writeFile(
            `${h.artifacts}/unknown-${operation.kind}.json`,
            JSON.stringify(
              {
                reason: result.flow.reconciliation.reason,
                diagnostic: result.flow.reconciliation.diagnostic,
                submission: {
                  status: result.flow.submission.status,
                  sendAttempts: result.flow.submission.sendAttempts,
                  diagnostic: result.flow.submission.diagnostic,
                },
                receipt,
                transaction,
                block,
              },
              null,
              2,
            ),
            { mode: 0o600 },
          );
        }
        assert.equal(
          result.flow.reconciliation.status,
          "reported-finalized-success",
          `Included ${operation.kind}: ${result.flow.reconciliation.status}`,
        );
        assert.equal(
          result.postcondition,
          "reported-state",
          `Post-state ${operation.kind}`,
        );
        return result;
      };
      await run({
        kind: "activate",
        config,
        securityReserve: 1000000000000000000n,
        signer: direct,
      });
      const policy = {
        version: 1,
        actionMask: 1n,
        maxAttempts: 50n,
        fee: {
          maxGasLimit: 500000n,
          maxGasPrice: 100000000000n,
          maxFeePerTransaction: 100000000000000000n,
          lifetimeFeeLimit: 1000000000000000000n,
        },
        transfer: {
          recipients: { kind: 0, recipients: [recipient] },
          limits: {
            maxPerTransaction: 10000000000000000000n,
            lifetimeLimit: 100000000000000000000n,
          },
          allowZeroValue: false,
          allowSelfTransfer: false,
        },
      };
      const makeGrant = async (signer) => {
        const identity = await client.getAuthorizationFinalityStatus({
          signal: h.signal,
        });
        const parameters = {
          keyScheme: signer.keyScheme,
          publicKey: signer.publicKey,
          validAfterHeight: identity.state.height + 20n,
          validUntilHeight: identity.state.height + 500n,
          policy,
        };
        return {
          ...parameters,
          storageDeposit: sdk.requiredGrantStorageDeposit(parameters),
        };
      };
      const wait = async (g) => {
        for (let i = 0; i < 250; i++) {
          const observed = await client.getSessionGrant(owner, g.grantId, {
            signal: h.signal,
          });
          if (observed.usableAtObservedBlock) return observed;
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
        throw Error("Grant validity readiness exceeded");
      };
      for (const signer of [ed, p]) {
        const created = await run({
          kind: "create-grant",
          grant: await makeGrant(signer),
          signers: [root],
        });
        const active = await wait(created.grant);
        const transferred = await run({
          kind: "transfer",
          credential: sdk.sessionCredentialFromGrant(active),
          signer,
          destination: recipient,
          value: 1000000000000000000n,
        });
        assert.equal(transferred.grant.sessionNonce, 1n);
        assert.equal(transferred.grant.usage.attempts, 1n);
        assert.equal(transferred.grant.usage.successes, 1n);
        assert.equal(transferred.grant.usage.externalValueSpent, 1000000000000000000n);
        await run({ kind: "revoke-grant", grantId: active.grantId, signers: [root] });
        const calls = signingCounts.get(signer)();
        await assert.rejects(
          lifecycle.execute({
            owner,
            operation: {
              kind: "transfer",
              credential: sdk.sessionCredentialFromGrant(transferred.grant),
              signer,
              destination: recipient,
              value: 1n,
            },
            ...fees,
            reservationId: randomUUID(),
            approve: () => true,
          }),
          (e) => e instanceof sdk.LifecycleError && e.code === "READ_FAILED",
        );
        assert.equal(signingCounts.get(signer)(), calls);
      }
      const created = await run({
        kind: "create-grant",
        grant: await makeGrant(ed),
        signers: [root],
      });
      const replaced = await run({
        kind: "replace-grant",
        oldGrantId: created.grant.grantId,
        newGrant: await makeGrant(ed),
        signers: [root],
      });
      assert.notDeepEqual(replaced.createdGrantId, created.createdGrantId);
      await run({
        kind: "set-reserve",
        securityReserve: 2000000000000000000n,
        signers: [root],
      });
      await run({ kind: "revoke-all", signers: [root] });
      await run({
        kind: "cleanup-grant",
        grantOwner: owner,
        grantId: replaced.grant.grantId,
        authority: { mode: 1, signers: [root] },
      });
      await run({
        kind: "rotate-root",
        config: {
          version: 1,
          threshold: 1,
          keys: [{ keyScheme: 1, publicKey: nextRoot.publicKey }],
        },
        reserveMode: 0,
        replacementReserve: 0n,
        signers: [root],
      });
      await run({
        kind: "set-reserve",
        securityReserve: 1000000000000000000n,
        signers: [nextRoot],
      });
      assert.equal(reviews, 14);
      assert.equal(signingCounts.get(direct)(), 1);
      const nonce = await client.getAccountAuthorizationSnapshot(owner);
      assert.equal(nonce.balance > 990000000000000000000n, true);
      h.evidence.checks.push({
        name: "funded DIRECT activation; both SESSION schemes; replacement/reserve/epoch/cleanup/rotation; rejected revoked keys before sign",
        reviews,
        recipientValue: "2000000000000000000",
      });
    },
  );
} finally {
  process.removeListener("SIGINT", abort);
  process.removeListener("SIGTERM", abort);
}
