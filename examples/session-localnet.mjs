// Executable disposable-network example. Test keys are externally owned in
// closures, never sent to RPC; this is not a production key-storage adapter.
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { randomBytes, randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import * as sdk from "../dist/index.js";
import { withNativeLocalnet } from "../scripts/localnet/harness.mjs";
import { verifyCapturedLogs } from "../scripts/localnet/verify-logs.mjs";
const counts = new WeakMap();
export function testSigner(
  scheme,
  secret = scheme === 1 ? randomBytes(32) : p256.utils.randomSecretKey(),
  observeSecret = () => {},
) {
  observeSecret(sdk.bytesToHex(secret));
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
  counts.set(signer, () => calls);
  return signer;
}
export const signingCalls = (signer) => counts.get(signer)();
export async function nativeSessionFixture(
  h,
  {
    observeSecret = () => {},
    approve = ({ review }) => {
      assert(Object.isFrozen(review));
      return true;
    },
  } = {},
) {
  const client = h.clients[0],
    context = { chainId: h.expected.chainId, genesisHash: h.expected.genesisHash };
  const owner = sdk.hexToBytes(h.publicWallets.owner.address),
    recipient = sdk.hexToBytes(h.publicWallets.recipient.address);
  const wallet = JSON.parse(await readFile(h.walletPaths.owner, "utf8"));
  const direct = testSigner(
      1,
      sdk.hexToBytes(`0x${wallet.privateKey}`).slice(0, 32),
      observeSecret,
    ),
    root = testSigner(1, undefined, observeSecret);
  const signer = (scheme) => testSigner(scheme, undefined, observeSecret);
  const config = {
    version: 1,
    threshold: 1,
    keys: [{ keyScheme: 1, publicKey: root.publicKey }],
  };
  const coordinator = new sdk.NonceCoordinator(new sdk.MemoryNonceReservationStore());
  const lifecycle = new sdk.SessionLifecycle({ context, client, coordinator });
  const fees = {
    gasLimit: 300000n,
    maxFeePerGas: 2000000000n,
    maxPriorityFeePerGas: 1000000000n,
  };
  const reconciliation = { timeoutMs: 90000, maxPolls: 1000, pollIntervalMs: 100 };
  const options = (operation) => ({
    owner,
    operation,
    ...fees,
    reservationId: randomUUID(),
    signal: h.signal,
    timeoutMs: 120000,
    reconciliation,
    approve,
  });
  const run = async (operation, expected = "reported-finalized-success") => {
    const result = await lifecycle.execute(options(operation));
    h.evidence.checks.push({
      name: operation.kind,
      status: result.flow.reconciliation.status,
      postcondition: result.postcondition,
      transactionHash: sdk.bytesToHex(result.flow.reconciliation.transactionHash),
    });
    assert.equal(result.flow.reconciliation.status, expected);
    assert.equal(
      result.postcondition,
      expected === "reported-finalized-success" ? "reported-state" : "included-failure",
    );
    assert.equal(result.flow.reservation.state, "consumed");
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
      recipients: {
        kind: 0,
        recipients: [
          recipient,
          ...(h.publicWallets.overflow
            ? [sdk.hexToBytes(h.publicWallets.overflow.address)]
            : []),
        ].sort((a, b) => Buffer.compare(a, b)),
      },
      limits: {
        maxPerTransaction: 10000000000000000000n,
        lifetimeLimit: 100000000000000000000n,
      },
      allowZeroValue: false,
      allowSelfTransfer: false,
    },
  };
  const makeGrant = async (signer, { duration = 500n } = {}) => {
    const state = (await client.getAuthorizationFinalityStatus({ signal: h.signal }))
      .state;
    const parameters = {
      keyScheme: signer.keyScheme,
      publicKey: signer.publicKey,
      validAfterHeight: state.height + 12n,
      validUntilHeight: state.height + 12n + duration,
      policy,
    };
    return {
      ...parameters,
      storageDeposit: sdk.requiredGrantStorageDeposit(parameters),
    };
  };
  const wait = async (probe) => {
    const until = performance.now() + 90000;
    while (performance.now() < until) {
      h.signal.throwIfAborted();
      const value = await probe();
      if (value) return value;
      await delay(100, undefined, { signal: h.signal });
    }
    throw Error("Native fixture observation deadline");
  };
  const usable = async (grant) =>
    wait(async () => {
      const g = await client.getSessionGrant(owner, grant.grantId, {
        signal: h.signal,
      });
      return g.usableAtObservedBlock ? g : null;
    });
  const intent = (destination = recipient, value = 1n) => ({
    version: 2,
    chainId: context.chainId,
    sender: owner,
    actionType: 0,
    flags: 0,
    destination,
    value,
    ...fees,
    sponsor: new Uint8Array(20),
    data: new Uint8Array(),
  });
  const sign = async (grant, signer, txIntent = intent(), signedContext = context) =>
    sdk.signSessionTransaction({
      context: signedContext,
      intent: txIntent,
      credential: sdk.sessionCredentialFromGrant(grant),
      signer,
      signal: h.signal,
      approve,
    });
  return {
    client,
    context,
    owner,
    recipient,
    direct,
    root,
    config,
    coordinator,
    lifecycle,
    fees,
    reconciliation,
    options,
    run,
    policy,
    makeGrant,
    wait,
    usable,
    intent,
    sign,
    signer,
  };
}
export async function runSessionExample(h) {
  const secrets = [];
  for (const name of await readdir(`${h.runtime}/keys`))
    secrets.push(
      JSON.parse(await readFile(`${h.runtime}/keys/${name}`, "utf8")).privateKey,
    );
  const f = await nativeSessionFixture(h, {
    observeSecret: (key) => secrets.push(key, key.slice(2)),
  });
  for (const scheme of [1, 2]) {
    const signer = f.signer(scheme),
      created = await f.run({
        kind: "create-grant",
        grant: await f.makeGrant(signer),
        signers: [f.root],
      }),
      grant = await f.usable(created.grant);
    const sent = await f.run({
      kind: "transfer",
      credential: sdk.sessionCredentialFromGrant(grant),
      signer,
      destination: f.recipient,
      value: 1000000000000000000n,
    });
    assert.equal(sent.grant.sessionNonce, 1n);
    assert.equal(sent.grant.usage.successes, 1n);
    await f.run({ kind: "revoke-grant", grantId: grant.grantId, signers: [f.root] });
  }
  return {
    evidence: h.evidence,
    verify: () => verifyCapturedLogs(h.evidence, { secrets }),
  };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const controller = new AbortController(),
    abort = () => controller.abort();
  process.once("SIGINT", abort);
  process.once("SIGTERM", abort);
  try {
    const result = await withNativeLocalnet(
      { signal: controller.signal },
      runSessionExample,
    );
    await result.verify();
    assert.equal(result.evidence.runtimeRetained, false);
    console.log(
      "Disposable SDK example: DIRECT activation, both raw SESSION schemes, finalized ROOT revocation passed.",
    );
  } finally {
    process.removeListener("SIGINT", abort);
    process.removeListener("SIGTERM", abort);
  }
}
