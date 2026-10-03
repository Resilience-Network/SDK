import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile, readdir } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { withNativeLocalnet } from "./localnet/harness.mjs";
import { verifyCapturedLogs } from "./localnet/verify-logs.mjs";
import {
  nativeSessionFixture,
  testSigner,
  signingCalls,
} from "../examples/session-localnet.mjs";
import * as sdk from "../dist/index.js";
const controller = new AbortController(),
  abort = () => controller.abort();
process.once("SIGINT", abort);
process.once("SIGTERM", abort);
try {
  const secrets = [];
  const evidence = await withNativeLocalnet(
    { signal: controller.signal, overflowRecipient: true, workTimeoutMs: 900000 },
    async (h) => {
      for (const name of await readdir(`${h.runtime}/keys`))
        secrets.push(
          JSON.parse(await readFile(`${h.runtime}/keys/${name}`, "utf8")).privateKey,
        );
      const f = await nativeSessionFixture(h, {
          observeSecret: (key) => secrets.push(key, key.slice(2)),
        }),
        overflow = sdk.hexToBytes(h.publicWallets.overflow.address);
      assert.equal(
        BigInt(
          await h.http[0].request("rsc_getBalance", [
            h.publicWallets.overflow.address,
            "latest",
          ]),
        ),
        (1n << 256n) - 1n,
      );
      const state = async (grantId) => {
        const a = await f.client.getAccountAuthorizationSnapshot(f.owner, {
          signal: h.signal,
        });
        const g = grantId
          ? await f.client.getSessionGrant(f.owner, grantId, { signal: h.signal })
          : null;
        return {
          balance: a.balance,
          accountNonce: a.accountNonce,
          root: sdk.bytesToHex(a.root.authority.canonical),
          grant: g ? sdk.bytesToHex(g.canonical) : null,
          recipient: await h.http[0].request("rsc_getBalance", [
            h.publicWallets.recipient.address,
            "latest",
          ]),
          recipientNonce: (
            await f.client.getAccountAuthorizationSnapshot(f.recipient, {
              signal: h.signal,
            })
          ).accountNonce,
          overflow: await h.http[0].request("rsc_getBalance", [
            h.publicWallets.overflow.address,
            "latest",
          ]),
        };
      };
      const denied = async (transaction, label, grantId) => {
        const before = await state(grantId),
          hex = sdk.bytesToHex(
            transaction instanceof Uint8Array
              ? transaction
              : sdk.transactionCodec.encode(transaction),
          );
        const outcomes = [];
        for (const method of [
          "rsc_simulateAuthorizedTransaction",
          "rsc_sendRawTransaction",
        ]) {
          await assert.rejects(
            h.http[0].request(method, [hex], { signal: h.signal }),
            (error) => {
              assert(
                error instanceof sdk.RpcClientError && error.kind === "node",
                `${label} must reach actual node rejection`,
              );
              outcomes.push({
                method,
                code: error.code,
                rpcCode: error.rpcCode,
                family: error.authorizationFamily,
              });
              return true;
            },
          );
        }
        assert.deepEqual(
          await state(grantId),
          before,
          `${label} mutated rejected authorization state`,
        );
        h.evidence.checks.push({ name: label, outcomes, stateUnchanged: true });
      };
      for (const scheme of [1, 2]) {
        const signer = f.signer(scheme),
          created = await f.run({
            kind: "create-grant",
            grant: await f.makeGrant(signer),
            signers: [f.root],
          });
        const pending = created.grant;
        await denied(
          await f.sign(pending, signer),
          `scheme ${scheme}: premature grant`,
          pending.grantId,
        );
        let grant = await f.usable(pending),
          valid = await f.sign(grant, signer);
        for (const [name, change] of [
          [
            "wrong grant",
            (tx) => (tx.envelope.credentialId = new Uint8Array(32).fill(249)),
          ],
          ["wrong epoch", (tx) => tx.envelope.authEpoch++],
          ["wrong policy", (tx) => (tx.envelope.policyHash[0] ^= 1)],
          ["future nonce", (tx) => tx.envelope.nonce++],
          [
            "bad signature",
            (tx) => {
              const witness = sdk.sessionWitnessCodec.decode(tx.envelope.witness);
              witness.signature[0] ^= 1;
              tx.envelope.witness = sdk.sessionWitnessCodec.encode(witness);
            },
          ],
        ]) {
          const tx = structuredClone(valid);
          change(tx);
          await denied(tx, `scheme ${scheme}: ${name}`, grant.grantId);
        }
        const genesis = f.context.genesisHash.slice();
        genesis[0] ^= 1;
        await denied(
          await f.sign(grant, signer, f.intent(), {
            ...f.context,
            genesisHash: genesis,
          }),
          `scheme ${scheme}: wrong genesis`,
          grant.grantId,
        );
        const chainId = f.context.chainId + 1n;
        await denied(
          await f.sign(
            grant,
            signer,
            { ...f.intent(), chainId },
            { ...f.context, chainId },
          ),
          `scheme ${scheme}: wrong chain`,
          grant.grantId,
        );
        const outsider = f.signer(scheme);
        await denied(
          await sdk.signSessionTransaction({
            context: f.context,
            intent: f.intent(),
            credential: {
              ...sdk.sessionCredentialFromGrant(grant),
              publicKey: outsider.publicKey,
            },
            signer: outsider,
            approve: () => true,
            signal: h.signal,
          }),
          `scheme ${scheme}: wrong key`,
          grant.grantId,
        );
        await denied(
          await f.sign(grant, signer, f.intent(f.owner)),
          `scheme ${scheme}: denied recipient`,
          grant.grantId,
        );
        await denied(
          await f.sign(
            grant,
            signer,
            f.intent(f.recipient, f.policy.transfer.limits.maxPerTransaction + 1n),
          ),
          `scheme ${scheme}: value limit`,
          grant.grantId,
        );
        const positive = await f.run({
          kind: "transfer",
          credential: sdk.sessionCredentialFromGrant(grant),
          signer,
          destination: f.recipient,
          value: 1000000000000000000n,
        });
        grant = positive.grant;
        const included = sdk.transactionCodec.decode(
          sdk.hexToBytes(positive.flow.reservation.canonicalTransaction),
        );
        await denied(
          included,
          `scheme ${scheme}: exact finalized replay`,
          grant.grantId,
        );
        await denied(
          valid,
          `scheme ${scheme}: consumed nonce different ID`,
          grant.grantId,
        );
        const before = await f.client.getFundedGrantSnapshot(f.owner, grant.grantId),
          stable = await state(grant.grantId);
        const failedTx = await f.sign(grant, signer, f.intent(overflow));
        const simulation = await f.client.simulateAuthorizedTransaction(
          sdk.transactionCodec.encode(failedTx),
          { signal: h.signal },
        );
        assert.equal(simulation.authorized, true);
        assert.equal(simulation.actionStatus, 0);
        assert(simulation.failureCode > 0);
        assert.deepEqual(
          await state(grant.grantId),
          stable,
          "failed-action advisory simulation mutated state",
        );
        const failure = await f.run(
          {
            kind: "transfer",
            credential: sdk.sessionCredentialFromGrant(grant),
            signer,
            destination: overflow,
            value: 1n,
          },
          "reported-finalized-failure",
        );
        const receipt = failure.flow.reconciliation.receipt,
          after = await f.client.getFundedGrantSnapshot(f.owner, grant.grantId);
        assert.equal(after.grant.sessionNonce, before.grant.sessionNonce + 1n);
        assert.equal(after.grant.usage.attempts, before.grant.usage.attempts + 1n);
        assert.equal(after.grant.usage.successes, before.grant.usage.successes);
        assert.equal(
          after.grant.usage.externalValueSpent,
          before.grant.usage.externalValueSpent,
        );
        assert.equal(
          after.grant.usage.feesPaid,
          before.grant.usage.feesPaid + receipt.actualFee,
        );
        assert.equal(after.balance, before.balance - receipt.actualFee);
        assert.equal(receipt.counterDelta.nonceDelta, 1);
        assert.equal(receipt.counterDelta.attemptsDelta, 1);
        assert.equal(receipt.counterDelta.successesDelta, 0);
        assert.equal(receipt.counterDelta.valueDelta, 0n);
        assert.equal(receipt.counterDelta.feeDelta, receipt.actualFee);
        assert.equal((await state(grant.grantId)).overflow, stable.overflow);
        h.evidence.checks.push({
          name: `scheme ${scheme}: included transfer overflow failure`,
          transactionHash: sdk.bytesToHex(failure.flow.reconciliation.transactionHash),
          failureCode: receipt.failureCode,
          fee: receipt.actualFee.toString(),
          nonceDelta: 1,
          attemptsDelta: 1,
          successesDelta: 0,
          valueDelta: "0",
        });
        grant = after.grant;
        // A real competing lifecycle starts while the first owns the signing slot.
        let entered, release;
        const inSign = new Promise((resolve) => (entered = resolve)),
          gate = new Promise((resolve) => (release = resolve));
        const gated = {
          keyScheme: signer.keyScheme,
          publicKey: signer.publicKey,
          async sign(request) {
            entered();
            await gate;
            return signer.sign(request);
          },
        };
        const calls = signingCalls(signer),
          operation = {
            kind: "transfer",
            credential: sdk.sessionCredentialFromGrant(grant),
            signer: gated,
            destination: f.recipient,
            value: 1n,
          };
        const concurrentOptions = f.options(operation);
        const first = f.lifecycle.execute(concurrentOptions);
        // Surface early failures immediately instead of hanging on an unentered gate.
        await Promise.race([
          inSign,
          first.then(() => {
            throw Error("flow bypassed signing gate");
          }),
        ]);
        const key = sdk.nonceAuthorityKey(await sessionAuthority(h, f, grant.grantId));
        assert.equal((await f.coordinator.inspect(key)).state, "signing");
        assert.equal(
          (await f.coordinator.inspect(key)).reservationId,
          concurrentOptions.reservationId,
        );
        try {
          await assert.rejects(
            f.lifecycle.execute(f.options({ ...operation, signer })),
            (e) => e instanceof sdk.LifecycleError && e.code === "FLOW_FAILED",
          );
        } finally {
          release();
        }
        const winner = await first;
        assert.equal(winner.flow.reconciliation.status, "reported-finalized-success");
        assert.equal(signingCalls(signer), calls + 1);
        assert.equal(winner.grant.sessionNonce, grant.sessionNonce + 1n);
        assert.equal(winner.grant.usage.attempts, grant.usage.attempts + 1n);
        h.evidence.checks.push({
          name: `scheme ${scheme}: concurrent slot contention`,
          winnerId: sdk.bytesToHex(winner.flow.reconciliation.transactionHash),
          signatures: 1,
          additionalAttempts: 1,
          loser: "LifecycleError(FLOW_FAILED) from held nonce slot",
        });
        grant = winner.grant;
        await lostAcknowledgment(h, f, grant, signer);
        grant = await f.client.getSessionGrant(f.owner, grant.grantId);
        grant = await cancellation(h, f, grant, signer);
        const revoked = await f.sign(grant, signer);
        await f.run({
          kind: "revoke-grant",
          grantId: grant.grantId,
          signers: [f.root],
        });
        await denied(revoked, `scheme ${scheme}: finalized revoked grant`, null);
      }
      await coordinatedFailure(h, f, f.owner, f.root, 1, overflow);
      const recipientWallet = JSON.parse(
        await readFile(h.walletPaths.recipient, "utf8"),
      );
      await coordinatedFailure(
        h,
        f,
        f.recipient,
        testSigner(
          1,
          sdk.hexToBytes(`0x${recipientWallet.privateKey}`).slice(0, 32),
          (key) => secrets.push(key, key.slice(2)),
        ),
        0,
        overflow,
      );
      const expired = [];
      for (const scheme of [1, 2]) {
        const signer = f.signer(scheme),
          created = await f.run({
            kind: "create-grant",
            grant: await f.makeGrant(signer, { duration: 12n }),
            signers: [f.root],
          });
        expired.push({
          signer,
          grant: created.grant,
          transaction: await f.sign(created.grant, signer),
        });
      }
      const expiryHeight = expired.reduce(
        (height, item) =>
          height > item.grant.validUntilHeight ? height : item.grant.validUntilHeight,
        0n,
      );
      await f.wait(async () => {
        const observed = await f.client.getAuthorizationFinalityStatus({
          signal: h.signal,
        });
        return observed.state.height >= expiryHeight ? observed : null;
      });
      for (const item of expired) {
        const g = await f.client.getSessionGrant(f.owner, item.grant.grantId);
        assert(g.state.height >= g.validUntilHeight);
        assert.equal(g.usableAtObservedBlock, false);
        await denied(
          item.transaction,
          `scheme ${item.signer.keyScheme}: exclusive expiry`,
          g.grantId,
        );
      }
      const epochGrants = [];
      for (const scheme of [1, 2]) {
        const signer = f.signer(scheme),
          created = await f.run({
            kind: "create-grant",
            grant: await f.makeGrant(signer),
            signers: [f.root],
          });
        epochGrants.push({
          signer,
          grant: created.grant,
          transaction: await f.sign(created.grant, signer),
        });
      }
      await f.usable(epochGrants[1].grant);
      const oldRoot = await f.client.getAccountAuthorizationSnapshot(f.owner);
      const rootTx = await sdk.signRootTransaction({
        context: f.context,
        intent: {
          ...f.intent(),
          actionType: sdk.Action.SetSecurityReserve,
          destination: new Uint8Array(20),
          value: 0n,
          data: sdk.setSecurityReserveCodec.encode({
            version: 1,
            securityReserve: 1000000000000000000n,
          }),
        },
        config: f.config,
        authEpoch: oldRoot.root.authority.authEpoch,
        nonce: oldRoot.root.authority.rootNonce,
        signers: [f.root],
        signal: h.signal,
        approve: () => true,
      });
      for (const mode of [0, 1]) {
        const malformed = sdk.transactionCodec.encode(epochGrants[1].transaction);
        malformed[
          sdk.txIntentCodec.encode(epochGrants[1].transaction.intent).length + 2
        ] = mode;
        await denied(
          malformed,
          `native P-256 ${mode === 0 ? "DIRECT" : "ROOT"} refusal`,
          epochGrants[1].grant.grantId,
        );
      }
      await f.run({ kind: "revoke-all", signers: [f.root] });
      const newRoot = await f.client.getAccountAuthorizationSnapshot(f.owner);
      assert.equal(
        newRoot.root.authority.authEpoch,
        oldRoot.root.authority.authEpoch + 1n,
      );
      assert.equal(
        newRoot.root.authority.rootNonce,
        oldRoot.root.authority.rootNonce + 1n,
      );
      await denied(rootTx, "ROOT old epoch after finalized revoke-all", null);
      for (const item of epochGrants) {
        const g = await f.client.getSessionGrant(f.owner, item.grant.grantId);
        assert.equal(g.usableAtObservedBlock, false);
        await denied(
          item.transaction,
          `scheme ${item.signer.keyScheme}: finalized revoke-all epoch`,
          g.grantId,
        );
      }
      for (const item of [...expired, ...epochGrants])
        await f.run({
          kind: "cleanup-grant",
          grantOwner: f.owner,
          grantId: item.grant.grantId,
          authority: { mode: 1, signers: [f.root] },
        });
      assert.equal(
        (await f.client.getAccountAuthorizationSnapshot(f.owner)).root.authority
          .activeGrantCount,
        0,
      );
      const finalAccount = await f.client.getAccountAuthorizationSnapshot(f.owner),
        height = finalAccount.identity.state.height;
      const agreement = await f.wait(async () => {
        const blocks = await Promise.all(
          h.http.map((client) =>
            client.request(
              "rsc_getBlockByNumber",
              [`0x${height.toString(16)}`, false],
              { signal: h.signal },
            ),
          ),
        );
        return blocks.every(
          (block) =>
            block &&
            block.hash === blocks[0].hash &&
            block.stateRoot === blocks[0].stateRoot,
        )
          ? blocks
          : null;
      });
      for (const client of h.clients) {
        const account = await client.getAccountAuthorizationSnapshot(f.owner, {
          signal: h.signal,
        });
        assert(account.identity.state.height >= height);
        assert.deepEqual(
          account.root.authority.canonical,
          finalAccount.root.authority.canonical,
        );
        assert.equal(account.accountNonce, finalAccount.accountNonce);
        assert.equal(account.balance, finalAccount.balance);
      }
      const selected = h.evidence.checks.filter(
        (check) =>
          check.name.includes("included transfer overflow failure") ||
          check.name.includes("lost acknowledgment"),
      );
      assert.equal(selected.length, 6);
      for (const check of selected) {
        const id = sdk.hexToBytes(check.transactionHash),
          receipts = await Promise.all(
            h.clients.map((client) =>
              client.getTransactionReceipt(id, { signal: h.signal }),
            ),
          );
        for (const observed of receipts) {
          assert.equal(observed.status, "reported-included");
          assert.deepEqual(observed.receipt, receipts[0].receipt);
        }
      }
      h.evidence.checks.push({
        name: "post-lifecycle four-validator state/hash and six failure/recovered receipts agree",
        nodes: 4,
        height: height.toString(),
        blockHash: agreement[0].hash,
        stateRoot: agreement[0].stateRoot,
        receiptIds: selected.map((check) => check.transactionHash),
      });
      return h.evidence;
    },
  );
  await verifyCapturedLogs(evidence, { secrets });
  assert.equal(evidence.runtimeRetained, false);
  console.log(
    "Native funded both-scheme domain/key/policy/nonce/replay/revocation rejection, included failure, contention and lost acknowledgment qualification passed.",
  );
} finally {
  process.removeListener("SIGINT", abort);
  process.removeListener("SIGTERM", abort);
}
async function lostAcknowledgment(h, f, grant, signer) {
  let writes = 0,
    dropped = 0;
  const proxy = createServer(async (req, res) => {
    try {
      const chunks = [];
      let length = 0;
      for await (const chunk of req) {
        length += chunk.length;
        assert(length <= 300000);
        chunks.push(chunk);
      }
      const body = Buffer.concat(chunks),
        request = JSON.parse(body.toString());
      const response = await fetch(h.urls[0], {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
        signal: AbortSignal.any([h.signal, AbortSignal.timeout(5000)]),
      });
      const bytes = await response.arrayBuffer();
      if (request.method === "rsc_sendRawTransaction") {
        writes++;
        assert.equal(writes, 1);
        dropped++;
        res.destroy();
      } else {
        res.writeHead(response.status, { "content-type": "application/json" });
        res.end(Buffer.from(bytes));
      }
    } catch {
      res.destroy();
    }
  });
  await new Promise((resolve) => proxy.listen(0, "127.0.0.1", resolve));
  try {
    const client = new sdk.ChainRpcClient({
      url: `http://127.0.0.1:${proxy.address().port}`,
      expected: h.expected,
      timeoutMs: 5000,
      maxContextRefreshes: 3,
    });
    const lifecycle = new sdk.SessionLifecycle({
        context: f.context,
        client,
        coordinator: f.coordinator,
      }),
      calls = signingCalls(signer);
    const result = await lifecycle.execute({
      ...f.options({
        kind: "transfer",
        credential: sdk.sessionCredentialFromGrant(grant),
        signer,
        destination: f.recipient,
        value: 1n,
      }),
      reconciliation: { timeoutMs: 1, maxPolls: 1, pollIntervalMs: 1 },
    });
    assert.equal(result.flow.submission.status, "unknown");
    assert.equal(result.flow.submission.sendAttempts, 1);
    assert.equal(result.flow.reconciliation.status, "unknown");
    assert.equal(result.flow.reservation.state, "uncertain");
    assert.equal(writes, 1);
    assert.equal(dropped, 1);
    assert.equal(signingCalls(signer), calls + 1);
    const reserved = result.flow.reservation;
    assert.equal((await f.coordinator.inspect(reserved.key)).state, "uncertain");
    await assert.rejects(
      f.lifecycle.execute(
        f.options({
          kind: "transfer",
          credential: sdk.sessionCredentialFromGrant(grant),
          signer,
          destination: f.recipient,
          value: 1n,
        }),
      ),
      (e) =>
        e instanceof sdk.LifecycleError &&
        ["FLOW_FAILED", "STALE_AUTHORITY"].includes(e.code),
    );
    assert.equal(signingCalls(signer), calls + 1);
    assert.equal(writes, 1);
    assert.equal((await f.coordinator.inspect(reserved.key)).state, "uncertain");
    const recovered = await f.coordinator.reconcile(
      reserved.key,
      reserved.reservationId,
      f.client,
      { ...f.reconciliation, signal: h.signal },
    );
    assert.equal(recovered.reconciliation.status, "reported-finalized-success");
    assert.equal(recovered.reservation.state, "consumed");
    assert.equal(recovered.reservation.transactionHash, reserved.transactionHash);
    assert.equal(signingCalls(signer), calls + 1);
    assert.equal(writes, 1);
    const after = await f.client.getSessionGrant(f.owner, grant.grantId);
    assert.equal(after.sessionNonce, grant.sessionNonce + 1n);
    assert.equal(after.usage.attempts, grant.usage.attempts + 1n);
    h.evidence.checks.push({
      name: `scheme ${signer.keyScheme}: real HTTP lost acknowledgment`,
      unknownSend: result.flow.submission.status,
      dropped,
      writes,
      signatures: 1,
      readOnlyRecovery: recovered.reconciliation.status,
      transactionHash: recovered.reservation.transactionHash,
    });
  } finally {
    proxy.closeAllConnections();
    await new Promise((resolve) => proxy.close(resolve));
  }
}
async function sessionAuthority(h, f, grantId) {
  const s = await f.client.getFundedGrantSnapshot(f.owner, grantId, {
      signal: h.signal,
    }),
    g = s.grant;
  return {
    context: f.context,
    owner: f.owner,
    mode: 2,
    keyScheme: g.keyScheme,
    credentialId: g.grantId,
    authEpoch: g.authEpoch,
    policyHash: g.policyHash,
    nonce: g.sessionNonce,
    authorityHash: sdk.keccak256(
      Buffer.from(
        JSON.stringify([
          sdk.bytesToHex(s.root.authority.canonical),
          sdk.bytesToHex(g.canonical),
          s.balance.toString(),
        ]),
      ),
    ),
    height: s.identity.state.height,
    blockHash: s.identity.state.blockHash,
    stateRoot: s.identity.state.stateRoot,
  };
}
async function cancellation(h, f, grant, signer) {
  const before = await f.client.getFundedGrantSnapshot(f.owner, grant.grantId),
    intent = {
      ...f.intent(),
      actionType: sdk.Action.SessionCancel,
      destination: new Uint8Array(20),
      value: 0n,
    },
    calls = signingCalls(signer);
  const result = await f.coordinator.execute({
    context: f.context,
    intent,
    reservationId: randomUUID(),
    readAuthority: () => sessionAuthority(h, f, grant.grantId),
    sign: ({ signal }) =>
      sdk.signSessionTransaction({
        context: f.context,
        intent,
        credential: sdk.sessionCredentialFromGrant(grant),
        signer,
        signal,
        approve: () => true,
      }),
    client: f.client,
    signal: h.signal,
    timeoutMs: 120000,
    reconciliation: f.reconciliation,
  });
  assert.equal(result.reconciliation.status, "reported-finalized-success");
  assert.equal(result.reservation.state, "consumed");
  assert.equal(signingCalls(signer), calls + 1);
  const receipt = result.reconciliation.receipt,
    after = await f.client.getFundedGrantSnapshot(f.owner, grant.grantId);
  assert.equal(after.grant.sessionNonce, grant.sessionNonce + 1n);
  assert.equal(after.grant.usage.attempts, grant.usage.attempts + 1n);
  assert.equal(after.grant.usage.successes, grant.usage.successes);
  assert.equal(after.grant.usage.externalValueSpent, grant.usage.externalValueSpent);
  assert.equal(after.grant.usage.feesPaid, grant.usage.feesPaid + receipt.actualFee);
  assert.equal(after.balance, before.balance - receipt.actualFee);
  assert.equal(after.grant.activeIndexPresent, true);
  assert.equal(after.grant.usableAtObservedBlock, true);
  assert.deepEqual(
    receipt.authorizationEvents.map((event) => event.type),
    [0x107, 0x108],
  );
  assert.equal(receipt.counterDelta.successesDelta, 0);
  assert.equal(receipt.counterDelta.valueDelta, 0n);
  h.evidence.checks.push({
    name: `scheme ${signer.keyScheme}: SESSION_CANCEL consumes attempt without revoking`,
    transactionHash: sdk.bytesToHex(result.reconciliation.transactionHash),
    nonceDelta: 1,
    attemptsDelta: 1,
    successesDelta: 0,
    fee: receipt.actualFee.toString(),
  });
  return after.grant;
}
async function coordinatedFailure(h, f, owner, signer, mode, overflow) {
  const read = () =>
    f.client.getAccountAuthorizationSnapshot(owner, { signal: h.signal });
  const authority = async () => {
    const a = await read();
    assert.equal(a.root.authorizationMode, mode);
    return {
      context: f.context,
      owner,
      mode,
      keyScheme: 1,
      credentialId: mode === 0 ? new Uint8Array(32) : a.root.authority.rootConfigHash,
      authEpoch: mode === 0 ? 0n : a.root.authority.authEpoch,
      policyHash: new Uint8Array(32),
      nonce: mode === 0 ? a.accountNonce : a.root.authority.rootNonce,
      authorityHash: sdk.keccak256(
        Buffer.from(
          JSON.stringify([
            mode === 0 ? null : sdk.bytesToHex(a.root.authority.canonical),
            a.accountNonce.toString(),
            a.balance.toString(),
          ]),
        ),
      ),
      height: a.identity.state.height,
      blockHash: a.identity.state.blockHash,
      stateRoot: a.identity.state.stateRoot,
    };
  };
  const before = await read(),
    intent = { ...f.intent(overflow), sender: owner },
    calls = signingCalls(signer);
  const result = await f.coordinator.execute({
    context: f.context,
    intent,
    reservationId: randomUUID(),
    readAuthority: authority,
    sign: ({ snapshot, signal }) =>
      mode === 0
        ? sdk.signDirectTransaction({
            context: f.context,
            intent,
            nonce: BigInt(snapshot.nonce),
            signer,
            signal,
            approve: () => true,
          })
        : sdk.signRootTransaction({
            context: f.context,
            intent,
            config: f.config,
            authEpoch: BigInt(snapshot.authEpoch),
            nonce: BigInt(snapshot.nonce),
            signers: [signer],
            signal,
            approve: () => true,
          }),
    client: f.client,
    signal: h.signal,
    timeoutMs: 120000,
    reconciliation: f.reconciliation,
  });
  assert.equal(result.reconciliation.status, "reported-finalized-failure");
  assert.equal(result.reservation.state, "consumed");
  assert.equal(signingCalls(signer), calls + 1);
  const after = await read(),
    receipt = result.reconciliation.receipt;
  assert.equal(after.accountNonce, before.accountNonce + (mode === 0 ? 1n : 0n));
  assert.equal(after.balance, before.balance - receipt.actualFee);
  if (mode === 1)
    assert.equal(after.root.authority.rootNonce, before.root.authority.rootNonce + 1n);
  assert.equal(receipt.counterDelta.nonceDelta, 1);
  assert.equal(receipt.counterDelta.attemptsDelta, 0);
  assert.equal(receipt.counterDelta.successesDelta, 0);
  assert.equal(receipt.counterDelta.valueDelta, 0n);
  assert.equal(receipt.counterDelta.feeDelta, receipt.actualFee);
  assert.equal(receipt.authorizationEvents.length, 0);
  h.evidence.checks.push({
    name: `${mode === 0 ? "DIRECT" : "ROOT"}: included transfer overflow failure`,
    transactionHash: sdk.bytesToHex(result.reconciliation.transactionHash),
    nonceDelta: 1,
    fee: receipt.actualFee.toString(),
  });
}
