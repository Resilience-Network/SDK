import assert from "node:assert/strict";
import test from "node:test";
import { p256 } from "@noble/curves/nist.js";
import * as sdk from "../dist/index.js";
import { systemClock } from "../dist/rpc/deadline.js";
import { FakeClock } from "./rpc-helpers.mjs";
import { checkSessionTransfer } from "../dist/session/lifecycle-policy.js";
import { expected, findFixture, methodHarness } from "./rpc-methods-helpers.mjs";
import { edSigner, deferred } from "./signer-helpers.mjs";
const sameHex = sdk.bytesToHex,
  zero = (n) => new Uint8Array(n),
  clone = structuredClone;
const fail = (code) => (e) => e instanceof sdk.LifecycleError && e.code === code;
let ids = 0;
async function setup(scheme = 1) {
  const f = findFixture(scheme === 1 ? "ed25519" : "p256", "rsc_getSessionGrant");
  const h = methodHarness(f),
    owner = sdk.hexToBytes(f.params[0]),
    id = sdk.hexToBytes(f.params[1]);
  const native = await h.client.getAuthorizationSnapshot(owner, id);
  const root = edSigner(1);
  const secret = zero(32);
  secret[31] = 3;
  const originalSigner =
    scheme === 1
      ? edSigner(2)
      : {
          keyScheme: 2,
          publicKey: p256.getPublicKey(secret, false).slice(1),
          async sign({ digest }) {
            return {
              keyScheme: 2,
              publicKey: this.publicKey.slice(),
              signature: p256.sign(digest, secret, { prehash: false, lowS: false }),
            };
          },
        };
  let signs = 0,
    sends = 0,
    reads = 0,
    approvals = 0,
    postReads = 0,
    status = "unknown",
    changed = false,
    postThrow = false;
  const signer = {
    keyScheme: scheme,
    publicKey: originalSigner.publicKey,
    async sign(request) {
      signs++;
      return originalSigner.sign(request);
    },
  };
  let target = {
    identity: native.identity,
    root: native.root,
    grant: native.grant,
    balance: 100000000000000000000n,
  };
  let account = {
    identity: native.identity,
    root: native.root,
    balance: target.balance,
    accountNonce: 1n,
  };
  h.client.getFundedGrantSnapshot = async () => clone(target);
  h.client.getAccountAuthorizationSnapshot = async () => {
    postReads++;
    if (postThrow) throw Error("SECRET read diagnostics");
    return clone(account);
  };
  h.client.submitTransaction = async (canonical) => {
    sends++;
    const tx = sdk.transactionCodec.decode(canonical);
    return {
      transactionHash: sdk.transactionId(expected, tx.intent, tx.envelope),
      status: "reported-accepted",
      sendAttempts: 1,
      verification: "node-observation",
    };
  };
  h.client.reconcileTransaction = async (canonical) => {
    reads++;
    const tx = sdk.transactionCodec.decode(canonical),
      transactionHash = sdk.transactionId(expected, tx.intent, tx.envelope);
    changed = true;
    return status === "unknown"
      ? {
          transactionHash,
          status,
          reason: "poll-limit",
          polls: 1,
          authority: null,
          lastObservation: null,
          verification: "node-observation",
        }
      : {
          transactionHash,
          status,
          polls: 1,
          authority: null,
          verification: "node-observation",
          identity: native.identity,
          receipt: {
            transactionHash,
            blockNumber: 12n,
            counterDelta: { nonceDelta: 1 },
          },
        };
  };
  const records = new Map(),
    inner = new sdk.MemoryNonceReservationStore();
  const store = {
    read: (k) => inner.read(k),
    async compareExchange(k, old, next) {
      const success = await inner.compareExchange(k, old, next);
      if (success) records.set(k, next);
      return success;
    },
  };
  const lifecycle = new sdk.SessionLifecycle({
    context: { chainId: expected.chainId, genesisHash: expected.genesisHash },
    client: h.client,
    coordinator: new sdk.NonceCoordinator(store),
  });
  const options = {
    owner,
    operation: {
      kind: "transfer",
      credential: sdk.sessionCredentialFromGrant(target.grant),
      signer,
      destination: sdk.hexToBytes("0x" + "00".repeat(19) + "02"),
      value: 10n,
    },
    gasLimit: 50000n,
    maxFeePerGas: 1n,
    maxPriorityFeePerGas: 1n,
    reservationId: `lifecycle-reservation-${++ids}`,
    approve: () => {
      approvals++;
      return true;
    },
  };
  return {
    lifecycle,
    options,
    signer,
    root,
    client: h.client,
    records,
    get target() {
      return target;
    },
    set target(v) {
      target = v;
    },
    get account() {
      return account;
    },
    set account(v) {
      account = v;
    },
    setStatus: (v) => (status = v),
    setPostThrow: (v) => (postThrow = v),
    stats: () => ({ signs, sends, reads, approvals, postReads, changed }),
  };
}
test("both session schemes sign the reviewed exact native credential once; uncertainty retains bytes", async () => {
  for (const scheme of [1, 2]) {
    const f = await setup(scheme),
      result = await f.lifecycle.execute(f.options);
    assert.equal(result.postcondition, "not-finalized");
    assert.equal(result.flow.reservation.state, "uncertain");
    assert(result.flow.reservation.canonicalTransaction);
    assert.equal(result.review.authority.keyScheme, scheme);
    assert.equal(result.review.authority.publicKey, sameHex(f.signer.publicKey));
    assert.deepEqual(f.stats(), {
      signs: 1,
      sends: 1,
      reads: 1,
      approvals: 1,
      postReads: 0,
      changed: true,
    });
    await assert.rejects(
      f.lifecycle.execute({
        ...f.options,
        reservationId: `lifecycle-new-reservation-${++ids}`,
      }),
      fail("FLOW_FAILED"),
    );
    assert.equal(f.stats().signs, 1);
    assert.equal(f.stats().sends, 1);
  }
});
test("denied grants and policy budgets never invoke approval, signer, submit or reservation", async () => {
  const cases = [
    (f) => (f.target.identity.genesisHash[0] ^= 1),
    (f) => f.target.root.authority.authEpoch++,
    (f) => (f.target.grant.usableAtObservedBlock = false),
    (f) => (f.target.grant.validUntilHeight = f.target.identity.state.height + 1n),
    (f) => f.options.operation.credential.authEpoch++,
    (f) => f.options.operation.credential.nonce++,
    (f) => (f.options.operation.credential.policyHash[0] ^= 1),
    (f) => (f.options.operation.credential.grantId[0] ^= 1),
    (f) => (f.options.operation.credential.publicKey[0] ^= 1),
    (f) => (f.target.grant.usage.attempts = f.target.grant.policy.maxAttempts),
    (f) => (f.options.gasLimit = f.target.grant.policy.fee.maxGasLimit + 1n),
    (f) => (f.options.maxFeePerGas = f.target.grant.policy.fee.maxGasPrice + 1n),
    (f) => (f.target.grant.policy.fee.lifetimeFeeLimit = 1n),
    (f) => (f.target.grant.usage.feeBucket.available = 0n),
    (f) => (f.target.grant.policy.fee.feeTokenBucket.refillPerBlock = 0n),
    (f) =>
      (f.options.operation.value =
        f.target.grant.policy.transfer.limits.maxPerTransaction + 1n),
    (f) => (f.target.grant.policy.transfer.limits.lifetimeLimit = 1n),
    (f) => (f.target.grant.usage.valueBuckets[0].available = 0n),
    (f) => (f.options.operation.destination[0] = 1),
    (f) => (f.options.operation.value = 0n),
    (f) => (f.options.operation.destination = f.options.owner.slice()),
    (f) => (f.target.balance = f.target.root.authority.securityReserve),
  ];
  for (let index = 0; index < cases.length; index++) {
    const f = await setup();
    if (index === 13) f.target.grant.policy.fee.feeTokenBucket.refillPerBlock = 0n;
    if (index === 14) f.target.grant.usage.feeBucket.available = 0n;
    if (index === 17)
      f.target.grant.policy.transfer.limits.valueTokenBucket.refillPerBlock = 0n;
    cases[index](f);
    await assert.rejects(
      f.lifecycle.execute(f.options),
      (e) => e instanceof sdk.LifecycleError,
      `case ${index}`,
    );
    assert.equal(f.stats().signs, 0);
    assert.equal(f.stats().sends, 0);
    assert.equal(f.stats().approvals, 0);
    assert.equal(f.records.size, 0);
  }
});
test("immediate review rejection/failure leaves no nonce reservation or key invocation", async () => {
  for (const [approve, code] of [
    [() => false, "REVIEW_REJECTED"],
    [
      () => {
        throw Error("SECRET approve");
      },
      "REVIEW_FAILED",
    ],
  ]) {
    const f = await setup();
    f.options.approve = approve;
    // This case tests a review outcome, not a race with pre-review work.
    await assert.rejects(f.lifecycle.execute(f.options), fail(code));
    assert.equal(f.records.size, 0);
    assert.equal(f.stats().signs, 0);
    assert.equal(f.stats().sends, 0);
  }
});
function controlledClock(t) {
  const clock = new FakeClock();
  for (const method of ["now", "setTimeout", "clearTimeout"])
    t.mock.method(systemClock, method, clock[method]);
  return clock;
}
test(
  "entered noncooperating review expires deterministically without reservation/sign/send or leaked timers",
  { timeout: 10000 },
  async (t) => {
    const f = await setup(),
      clock = controlledClock(t),
      entered = deferred();
    f.options.timeoutMs = 1000;
    f.options.approve = () => {
      entered.resolve();
      return new Promise(() => {});
    };
    const pending = f.lifecycle.execute(f.options),
      rejected = assert.rejects(pending, fail("TIMEOUT"));
    await entered.promise;
    assert.equal(f.records.size, 0);
    assert.equal(f.stats().signs, 0);
    assert.equal(f.stats().sends, 0);
    assert.equal(clock.time, 0);
    assert(clock.tasks.size > 0);
    await clock.advance(999);
    assert.equal(f.records.size, 0);
    assert.equal(f.stats().signs, 0);
    await clock.advance(1);
    await rejected;
    assert.equal(f.records.size, 0);
    assert.equal(f.stats().signs, 0);
    assert.equal(f.stats().sends, 0);
    assert.equal(clock.tasks.size, 0);
  },
);
test(
  "whole-flow expiry before review is TIMEOUT and never masquerades as rejection",
  { timeout: 10000 },
  async (t) => {
    const f = await setup(),
      clock = controlledClock(t);
    let approvals = 0;
    f.options.timeoutMs = 20;
    f.options.approve = () => {
      approvals++;
      return false;
    };
    const read = f.client.getFundedGrantSnapshot;
    f.client.getFundedGrantSnapshot = async (...args) => {
      const value = await read.apply(f.client, args);
      await clock.advance(21);
      return value;
    };
    await assert.rejects(f.lifecycle.execute(f.options), fail("TIMEOUT"));
    assert.equal(approvals, 0);
    assert.equal(f.records.size, 0);
    assert.equal(f.stats().signs, 0);
    assert.equal(f.stats().sends, 0);
    assert.equal(clock.tasks.size, 0);
  },
);
test("reviewed state never silently refreshes nonce, balance, root or grant", async () => {
  for (const mutate of [
    (f) => f.target.grant.sessionNonce++,
    (f) => f.target.balance--,
    (f) => (f.target.root.authority.canonical[0] ^= 1),
    (f) => (f.target.grant.canonical[0] ^= 1),
  ]) {
    const f = await setup();
    f.options.approve = () => {
      mutate(f);
      return true;
    };
    await assert.rejects(
      f.lifecycle.execute(f.options),
      (e) =>
        e instanceof sdk.LifecycleError &&
        ["STALE_AUTHORITY", "STATE_DENIED"].includes(e.code),
    );
    assert.equal(f.stats().signs, 0);
    assert.equal(f.records.size, 0);
  }
});
test("awaited approval guards actions, fees, credential, proof, callback identity and signal", async () => {
  for (const mutate of [
    (f) => f.options.operation.value++,
    (f) => f.options.operation.credential.nonce++,
    (f) => f.options.maxFeePerGas++,
    (f) => (f.options.operation.signer.sign = async () => {}),
    (f) => (f.options.approve = () => true),
    (f) => (f.options.signal = new AbortController().signal),
    (f) => (f.client.submitTransaction = async () => {}),
  ]) {
    const f = await setup(),
      gate = deferred();
    f.options.approve = () => gate.promise;
    const running = f.lifecycle.execute(f.options);
    await new Promise((r) => setImmediate(r));
    mutate(f);
    gate.resolve(true);
    await assert.rejects(running, fail("MUTATED_INPUT"));
    assert.equal(f.stats().signs, 0);
    assert.equal(f.records.size, 0);
  }
});
test("included action failure remains finalized and consumed; post-read is not claimed", async () => {
  const f = await setup();
  f.setStatus("reported-finalized-failure");
  const result = await f.lifecycle.execute(f.options);
  assert.equal(result.postcondition, "included-failure");
  assert.equal(result.flow.reservation.state, "consumed");
  assert.equal(result.flow.reconciliation.receipt.counterDelta.nonceDelta, 1);
  assert.equal(f.stats().postReads, 0);
});
test("post-finalized observation failure retains receipt and consumed signed bytes", async () => {
  const f = await setup();
  f.setStatus("reported-finalized-success");
  f.setPostThrow(true);
  const result = await f.lifecycle.execute(f.options);
  assert.equal(result.postcondition, "unknown");
  assert.equal(result.flow.reconciliation.status, "reported-finalized-success");
  assert.equal(result.flow.reservation.state, "consumed");
  assert(result.flow.reservation.canonicalTransaction);
  assert(
    !JSON.stringify(result, (_key, value) =>
      typeof value === "bigint" ? value.toString() : value,
    ).includes("SECRET"),
  );
});
test("invalid operations/options and reused root keys are denied before signer", async () => {
  for (const mutate of [
    (f) => (f.options.operation.kind = "unsupported"),
    (f) => (f.options.gasLimit = -1n),
    (f) => (f.options.reservationId = "short"),
    (f) => (f.options.approve = undefined),
    (f) => (f.options.reconciliation = { maxPolls: 0 }),
    (f) => (f.options.operation.extra = "unknown"),
  ]) {
    const f = await setup();
    mutate(f);
    await assert.rejects(f.lifecycle.execute(f.options), fail("INVALID_ARGUMENT"));
    assert.equal(f.stats().signs, 0);
    assert.equal(f.records.size, 0);
  }
  const f = await setup();
  const spec = {
    keyScheme: 1,
    publicKey: f.root.publicKey,
    validAfterHeight: 20n,
    validUntilHeight: 100n,
    policy: f.target.grant.policy,
    storageDeposit: 1000000000000000000n,
  };
  f.options.operation = { kind: "create-grant", grant: spec, signers: [f.root] };
  await assert.rejects(f.lifecycle.execute(f.options), fail("STATE_DENIED"));
});
test("root selections and maintenance preconditions reject before approval", async () => {
  const cases = [
    { kind: "set-reserve", securityReserve: 0n, signers: [edSigner(1)] },
    {
      kind: "rotate-root",
      config: {
        version: 1,
        threshold: 1,
        keys: [{ keyScheme: 1, publicKey: edSigner(3).publicKey }],
      },
      reserveMode: 1,
      replacementReserve: 10n ** 30n,
      signers: [edSigner(1)],
    },
    { kind: "revoke-all", signers: [edSigner(2)] },
    { kind: "revoke-all", signers: [] },
    {
      kind: "cleanup-grant",
      grantOwner: zero(20),
      grantId: zero(32),
      authority: { mode: 0, signer: edSigner(1) },
    },
  ];
  for (const op of cases) {
    const f = await setup();
    f.options.operation = op;
    await assert.rejects(
      f.lifecycle.execute(f.options),
      (e) => e instanceof sdk.LifecycleError,
    );
    assert.equal(f.stats().signs, 0);
    assert.equal(f.records.size, 0);
    assert.equal(f.stats().approvals, 0);
  }
});
test("DIRECT activation reviews a native external owner and rejects already-rooted/wrong owner", async () => {
  const f = await setup(),
    direct = edSigner(7),
    owner = sdk.keccak256(direct.publicKey).slice(12);
  f.options.owner = owner;
  f.account = {
    ...f.account,
    root: { ...f.account.root, owner, authorizationMode: 0, authority: null },
    accountNonce: 0n,
  };
  const config = {
    version: 1,
    threshold: 1,
    keys: [{ keyScheme: 1, publicKey: f.root.publicKey }],
  };
  f.options.operation = {
    kind: "activate",
    config,
    securityReserve: 1000000000000000000n,
    signer: direct,
  };
  const result = await f.lifecycle.execute(f.options);
  assert.equal(result.review.authority.mode, "DIRECT");
  assert.equal(result.postcondition, "not-finalized");
  const bad = await setup();
  bad.options.operation = f.options.operation;
  await assert.rejects(bad.lifecycle.execute(bad.options), fail("STATE_DENIED"));
  assert.equal(bad.records.size, 0);
});
test("refill arithmetic is checked before capacity capping and rejects malformed/future values", () => {
  assert.equal(
    sdk.refilledBucketAvailable(
      { capacity: 100n, refillPerBlock: 10n },
      { available: 95n, lastRefillHeight: 1n },
      3n,
    ),
    100n,
  );
  assert.equal(
    sdk.refilledBucketAvailable(
      { capacity: 100n, refillPerBlock: 0n },
      { available: 95n, lastRefillHeight: 1n },
      3n,
    ),
    95n,
  );
  const max = (1n << 256n) - 1n;
  for (const args of [
    [
      { capacity: 1n, refillPerBlock: max },
      { available: 0n, lastRefillHeight: 0n },
      2n,
    ],
    [
      { capacity: 1n, refillPerBlock: 1n },
      { available: max, lastRefillHeight: 0n },
      1n,
    ],
    [
      { capacity: 10n, refillPerBlock: 1n },
      { available: 5n, lastRefillHeight: 2n },
      1n,
    ],
    [
      { capacity: 10n, refillPerBlock: 1n },
      { available: -1n, lastRefillHeight: 0n },
      1n,
    ],
    [
      { capacity: -1n, refillPerBlock: 0n },
      { available: 0n, lastRefillHeight: 0n },
      0n,
    ],
  ])
    assert.throws(() => sdk.refilledBucketAvailable(...args));
});
test("storage deposit matches native grant fixtures for both schemes and supported policy forms", async () => {
  for (const scheme of [1, 2]) {
    const f = await setup(scheme),
      g = f.target.grant;
    assert.equal(
      sdk.requiredGrantStorageDeposit({
        keyScheme: g.keyScheme,
        publicKey: g.publicKey,
        validAfterHeight: g.validAfterHeight,
        validUntilHeight: g.validUntilHeight,
        policy: g.policy,
      }),
      g.storageDeposit,
    );
  }
});
test("odd-count Merkle proofs use position-derived padding siblings and reject wrong position/domain/root", async () => {
  const f = await setup();
  const recipient = f.options.operation.destination,
    context = expected;
  const leaf = sdk.recipientLeafHash(context, 0, recipient),
    one = sdk.recipientLeafHash(
      context,
      0,
      sdk.hexToBytes("0x" + "00".repeat(19) + "03"),
    ),
    two = sdk.recipientLeafHash(
      context,
      0,
      sdk.hexToBytes("0x" + "00".repeat(19) + "04"),
    ),
    empty = sdk.recipientEmptyLeafHash(context, 0, 3);
  const left = sdk.recipientNodeHash(context, 0, one, two),
    right = sdk.recipientNodeHash(context, 0, leaf, empty),
    root = sdk.recipientNodeHash(context, 0, left, right);
  f.target.grant.policy.transfer.recipients = {
    kind: 1,
    merkleRoot: root,
    leafCount: 3,
  };
  const proof = { leafIndex: 2, leafCount: 3, siblings: [empty, left] };
  const intent = {
    version: 2,
    chainId: context.chainId,
    sender: f.options.owner,
    actionType: 0,
    flags: 0,
    destination: recipient,
    value: 10n,
    gasLimit: 50000n,
    maxFeePerGas: 1n,
    maxPriorityFeePerGas: 1n,
    sponsor: zero(20),
    data: zero(0),
  };
  checkSessionTransfer(context, intent, f.target, proof);
  for (const change of [
    (p) => (p.leafIndex = 0),
    (p) => (p.leafCount = 4),
    (p) => (p.siblings[0] = leaf),
    (p) => p.siblings.push(empty),
    (p) => (p.siblings[1][0] ^= 1),
  ]) {
    const bad = clone(proof);
    change(bad);
    assert.throws(() => checkSessionTransfer(context, intent, f.target, bad));
  }
  assert.throws(() =>
    checkSessionTransfer(
      { ...context, genesisHash: zero(32) },
      intent,
      f.target,
      proof,
    ),
  );
});

test("lifecycle reconstructs hostile typed approval failures without signing", async () => {
  for (const mutation of ["message", "invalid-code", "code-getter", "prototype-trap"]) {
    const f = await setup();
    let injected = new sdk.LifecycleError("REVIEW_FAILED");
    injected.message = "private-sentinel";
    injected.cause = "private-sentinel";
    if (mutation === "invalid-code") injected.code = "private-sentinel";
    if (mutation === "code-getter")
      Object.defineProperty(injected, "code", {
        get() {
          throw Error("private-sentinel");
        },
      });
    if (mutation === "prototype-trap")
      injected = new Proxy(
        {},
        {
          getPrototypeOf() {
            throw Error("private-sentinel");
          },
        },
      );
    await assert.rejects(
      f.lifecycle.execute({
        ...f.options,
        approve: () => {
          throw injected;
        },
      }),
      (failure) => {
        assert(failure instanceof sdk.LifecycleError);
        assert.notEqual(failure, injected);
        assert.equal(
          failure.code,
          mutation === "message" ? "REVIEW_FAILED" : "READ_FAILED",
        );
        assert.ok(!failure.message.includes("private-sentinel"));
        assert.equal(failure.cause, undefined);
        return true;
      },
    );
    assert.equal(f.stats().signs, 0);
    assert.equal(f.stats().sends, 0);
    assert.equal(f.records.size, 0);
  }
});

test("lifecycle constructor sanitizes hostile option inspection", () => {
  assert.throws(
    () =>
      new sdk.SessionLifecycle(
        new Proxy(
          {},
          {
            ownKeys() {
              throw Error("private-sentinel");
            },
          },
        ),
      ),
    (failure) => {
      assert(failure instanceof sdk.LifecycleError);
      assert.equal(failure.code, "INVALID_ARGUMENT");
      assert.ok(!failure.message.includes("private-sentinel"));
      return true;
    },
  );
});
