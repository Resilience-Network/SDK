import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { sdk, bytes, hex, context, vectors, zero } from "./helpers.mjs";
import {
  deferred,
  directOptions,
  rootInput,
  sessionOptions,
} from "./signer-helpers.mjs";
const code = (expected) => (e) =>
  e instanceof sdk.CoordinatorError && e.code === expected;
const reservationId = (n) => `test-reservation-${String(n).padStart(8, "0")}`;
function setup(
  kind = "direct",
  store = new sdk.MemoryNonceReservationStore(),
  number = 1,
) {
  const signing =
    kind === "root"
      ? rootInput()
      : kind === "session"
        ? sessionOptions()
        : directOptions();
  const mode = kind === "direct" ? 0 : kind === "root" ? 1 : 2;
  const snapshot = {
    context: structuredClone(signing.context),
    owner: new Uint8Array(signing.intent.sender),
    mode,
    keyScheme: mode === 2 ? signing.credential.keyScheme : 1,
    credentialId:
      mode === 0
        ? zero(32)
        : mode === 1
          ? sdk.rootConfigHash(signing.config)
          : signing.credential.grantId.slice(),
    authEpoch:
      mode === 0 ? 0n : mode === 1 ? signing.authEpoch : signing.credential.authEpoch,
    policyHash: mode === 2 ? signing.credential.policyHash.slice() : zero(32),
    nonce: mode === 2 ? signing.credential.nonce : signing.nonce,
    authorityHash: new Uint8Array(32).fill(4),
    height: 10n,
    blockHash: new Uint8Array(32).fill(6),
    stateRoot: new Uint8Array(32).fill(8),
  };
  const coordinator = new sdk.NonceCoordinator(store);
  let signs = 0,
    sends = 0,
    reads = 0,
    finalized = true,
    failure = false,
    submission = "reported-accepted";
  const client = {
    async submitTransaction(canonical) {
      sends++;
      const tx = sdk.transactionCodec.decode(canonical);
      return {
        transactionHash: sdk.transactionId(context, tx.intent, tx.envelope),
        status: submission,
        verification: "node-observation",
        sendAttempts: 1,
      };
    },
    async reconcileTransaction(canonical) {
      reads++;
      const tx = sdk.transactionCodec.decode(canonical),
        transactionHash = sdk.transactionId(context, tx.intent, tx.envelope);
      return finalized
        ? {
            transactionHash,
            status: failure
              ? "reported-finalized-failure"
              : "reported-finalized-success",
            verification: "node-observation",
            receipt: { transactionHash, counterDelta: { nonceDelta: 1 } },
            polls: 1,
            authority: null,
            identity: {},
          }
        : {
            transactionHash,
            status: "unknown",
            verification: "node-observation",
            reason: "poll-limit",
            polls: 1,
            authority: null,
            lastObservation: null,
          };
    },
  };
  const options = {
    context: signing.context,
    intent: signing.intent,
    reservationId: reservationId(number),
    readAuthority: async () => structuredClone(snapshot),
    sign: async (request) => {
      signs++;
      assert(Object.isFrozen(request) && Object.isFrozen(request.snapshot));
      assert.equal(
        request.intentCanonical,
        hex(sdk.txIntentCodec.encode(signing.intent)),
      );
      return mode === 0
        ? sdk.signDirectTransaction(signing)
        : mode === 1
          ? sdk.signRootTransaction(signing)
          : sdk.signSessionTransaction(signing);
    },
    client,
  };
  return {
    coordinator,
    store,
    options,
    snapshot,
    signing,
    key: sdk.nonceAuthorityKey(snapshot),
    stats: () => ({ signs, sends, reads }),
    setFinalized: (v) => (finalized = v),
    setFailure: (v) => (failure = v),
    setSubmission: (v) => (submission = v),
  };
}
test("concurrent duplicate authority flows produce one signature/send; no speculative next nonce", async () => {
  const f = setup();
  const gate = deferred(),
    original = f.options.sign;
  f.options.sign = async (r) => {
    await gate.promise;
    return original(r);
  };
  const first = f.coordinator.execute(f.options);
  await new Promise((resolve) => setImmediate(resolve));
  await assert.rejects(
    f.coordinator.execute({ ...f.options, reservationId: reservationId(2) }),
    code("CONFLICT"),
  );
  gate.resolve();
  const result = await first;
  assert.equal(result.reservation.state, "consumed");
  assert.deepEqual(f.stats(), { signs: 1, sends: 1, reads: 1 });
  await assert.rejects(
    f.coordinator.execute({ ...f.options, reservationId: reservationId(3) }),
    code("STALE_AUTHORITY"),
  );
});
test("included failure consumes reservation; each authority accepts only a fresh observed nonce", async () => {
  for (const kind of ["direct", "root", "session"]) {
    const f = setup(kind);
    f.setFailure(true);
    const result = await f.coordinator.execute(f.options);
    assert.equal(result.reconciliation.status, "reported-finalized-failure");
    assert.equal(result.reservation.state, "consumed");
    f.snapshot.nonce++;
    f.snapshot.height++;
    f.snapshot.blockHash.fill(9);
    f.snapshot.stateRoot.fill(9);
    f.snapshot.authorityHash.fill(9);
    if (kind === "session") f.signing.credential.nonce++;
    else f.signing.nonce++;
    const next = await f.coordinator.execute({
      ...f.options,
      reservationId: reservationId(2),
    });
    assert.equal(next.reservation.snapshot.nonce, f.snapshot.nonce.toString());
    assert.equal(f.stats().sends, 2);
  }
});
test("unknown/rejected send retains signed bytes; recreated coordinators recover by reads only", async () => {
  for (const status of [
    "unknown",
    "reported-rejected",
    "not-sent",
    "reported-accepted",
  ]) {
    const f = setup();
    f.setSubmission(status);
    f.setFinalized(false);
    const result = await f.coordinator.execute(f.options);
    assert.equal(result.reservation.state, "uncertain");
    assert.equal(
      hex(
        sdk.transactionId(
          context,
          ...Object.values(
            sdk.transactionCodec.decode(bytes(result.reservation.canonicalTransaction)),
          ),
        ),
      ),
      result.reservation.transactionHash,
    );
    await assert.rejects(
      f.coordinator.releaseUnsigned(f.key, f.options.reservationId),
      code("CONFLICT"),
    );
    f.snapshot.nonce++;
    await assert.rejects(
      new sdk.NonceCoordinator(f.store).execute({
        ...f.options,
        reservationId: reservationId(2),
      }),
      code("CONFLICT"),
    );
    f.setFinalized(true);
    const recovered = await new sdk.NonceCoordinator(f.store).reconcile(
      f.key,
      f.options.reservationId,
      f.options.client,
      { maxPolls: 1 },
    );
    assert.equal(recovered.reservation.state, "consumed");
    assert.equal(f.stats().sends, 1);
    assert.equal(f.stats().signs, 1);
  }
});
test("abort/timeout before reservation sends nothing; after signing starts retains uncertainty", async () => {
  const f = setup(),
    abort = new AbortController();
  abort.abort("secret");
  await assert.rejects(
    f.coordinator.execute({ ...f.options, signal: abort.signal }),
    code("ABORTED"),
  );
  assert.equal(await f.coordinator.inspect(f.key), null);
  const g = setup();
  g.options.sign = () => new Promise(() => {});
  await assert.rejects(
    g.coordinator.execute({ ...g.options, timeoutMs: 10 }),
    code("TIMEOUT"),
  );
  assert.equal((await g.coordinator.inspect(g.key)).state, "signing");
  assert.equal(g.stats().sends, 0);
  await assert.rejects(
    g.coordinator.releaseUnsigned(g.key, g.options.reservationId),
    code("CONFLICT"),
  );
  const h = setup(),
    controller = new AbortController();
  h.options.sign = () => new Promise(() => {});
  const pending = h.coordinator.execute({ ...h.options, signal: controller.signal });
  await new Promise((r) => setImmediate(r));
  controller.abort("secret");
  await assert.rejects(pending, code("ABORTED"));
  assert.equal((await h.coordinator.inspect(h.key)).state, "signing");
});
test("authority nonce/epoch/policy/usage/context changes fail without refreshing or sending", async () => {
  for (const edit of [
    (s) => s.nonce++,
    (s) => s.authEpoch++,
    (s) => s.policyHash.fill(8),
    (s) => s.credentialId.fill(7),
    (s) => s.authorityHash.fill(6),
    (s) => s.context.chainId++,
    (s) => s.height--,
    (s) => s.stateRoot.fill(0),
  ]) {
    const f = setup("session");
    let reads = 0;
    f.options.readAuthority = async () => {
      const s = structuredClone(f.snapshot);
      if (++reads === 3) edit(s);
      return s;
    };
    await assert.rejects(f.coordinator.execute(f.options));
    assert.equal(f.stats().sends, 0);
    assert.equal((await f.coordinator.inspect(f.key)).state, "signed");
  }
  const f = setup("root");
  let reads = 0;
  f.options.readAuthority = async () => {
    const s = structuredClone(f.snapshot);
    if (++reads === 2) s.nonce++;
    return s;
  };
  await assert.rejects(f.coordinator.execute(f.options), code("STALE_AUTHORITY"));
  assert.equal(f.stats().signs, 0);
  assert.equal((await f.coordinator.inspect(f.key)).state, "reserved");
  await f.coordinator.releaseUnsigned(f.key, f.options.reservationId);
  assert.equal((await f.coordinator.inspect(f.key)).state, "released");
});
test("caller and callback-owned mutations are detected at read/sign/storage/submit/reconcile boundaries", async () => {
  for (const boundary of ["read", "sign", "storage", "submit", "reconcile"]) {
    const f = setup();
    let record = null,
      calls = 0;
    if (boundary === "storage") {
      const store = f.store,
        exchange = store.compareExchange.bind(store);
      store.compareExchange = async (...args) => {
        const result = await exchange(...args);
        if (++calls === 3) f.signing.intent.gasLimit++;
        return result;
      };
    }
    if (boundary === "read") {
      const read = f.options.readAuthority;
      f.options.readAuthority = async (...args) => {
        const result = await read(...args);
        f.options.intent.gasLimit++;
        return result;
      };
    }
    if (boundary === "sign") {
      const sign = f.options.sign;
      f.options.sign = async (r) => {
        record = await sign(r);
        f.options.context.genesisHash.fill(5);
        return record;
      };
    }
    if (boundary === "submit") {
      const submit = f.options.client.submitTransaction;
      f.options.client.submitTransaction = async (...args) => {
        const result = await submit(...args);
        f.options.intent.gasLimit++;
        return result;
      };
    }
    if (boundary === "reconcile") {
      const reconcile = f.options.client.reconcileTransaction;
      f.options.client.reconcileTransaction = async (...args) => {
        const result = await reconcile(...args);
        f.options.intent.gasLimit++;
        return result;
      };
    }
    await assert.rejects(f.coordinator.execute(f.options), code("MUTATED_INPUT"));
    assert(f.stats().sends <= 1);
  }
  const f = setup();
  let signed;
  const sign = f.options.sign;
  f.options.sign = async (r) => (signed = await sign(r));
  let reads = 0;
  f.options.readAuthority = async () => {
    if (++reads === 3) signed.intent.gasLimit++;
    return structuredClone(f.snapshot);
  };
  await assert.rejects(f.coordinator.execute(f.options), code("MUTATED_INPUT"));
  assert.equal(f.stats().sends, 0);
  const g = setup();
  let first,
    reads2 = 0;
  g.options.readAuthority = async () => {
    if (++reads2 === 1) return (first = structuredClone(g.snapshot));
    first.nonce++;
    return structuredClone(g.snapshot);
  };
  await assert.rejects(g.coordinator.execute(g.options), code("MUTATED_INPUT"));
  assert.equal(g.stats().signs, 0);
});
test("distinct grants/accounts/networks have independent slots; root epoch never bypasses uncertain slot", async () => {
  const f = setup("root");
  f.setFinalized(false);
  await f.coordinator.execute(f.options);
  const g = setup("root", f.store, 2);
  g.snapshot.authEpoch++;
  g.signing.authEpoch++;
  assert.equal(f.key, g.key);
  await assert.rejects(g.coordinator.execute(g.options), code("CONFLICT"));
  const a = setup("session"),
    b = setup("session", a.store, 2);
  b.snapshot.credentialId.fill(10);
  b.signing.credential.grantId.fill(10);
  assert.notEqual(a.key, sdk.nonceAuthorityKey(b.snapshot));
  await Promise.all([
    a.coordinator.execute(a.options),
    b.coordinator.execute(b.options),
  ]);
  const c = structuredClone(a.snapshot);
  c.context.genesisHash.fill(8);
  assert.notEqual(a.key, sdk.nonceAuthorityKey(c));
});
test("malformed/untrusted storage and CAS contention fail closed; no error exposes adapter exception", async () => {
  const f = setup();
  const evil = {
    read: async () => ({ version: 9 }),
    compareExchange: async () => true,
  };
  await assert.rejects(
    new sdk.NonceCoordinator(evil).execute(f.options),
    code("INVALID_STORE"),
  );
  const fail = {
    read: async () => {
      throw Error("secret");
    },
    compareExchange: async () => true,
  };
  await assert.rejects(
    new sdk.NonceCoordinator(fail).execute(f.options),
    (e) => code("ADAPTER_FAILED")(e) && !e.message.includes("secret"),
  );
  const conflict = { read: async () => null, compareExchange: async () => false };
  await assert.rejects(
    new sdk.NonceCoordinator(conflict).execute(f.options),
    code("CONFLICT"),
  );
  assert.equal(f.stats().signs, 0);
  for (const mutation of [
    (r) => (r.snapshot.nonce = "01"),
    (r) => (r.revision = Number.MAX_SAFE_INTEGER),
    (r) => (r.transactionHash = "0x00"),
    (r) => (r.canonicalTransaction = "0x00"),
    (r) => (r.snapshot.credentialId = "0xff"),
    (r) => (r.extra = true),
  ]) {
    const g = setup();
    g.setFinalized(false);
    await g.coordinator.execute(g.options);
    const record = structuredClone(await g.coordinator.inspect(g.key));
    mutation(record);
    await assert.rejects(
      new sdk.NonceCoordinator({
        read: async () => record,
        compareExchange: async () => true,
      }).inspect(g.key),
      code("INVALID_STORE"),
    );
  }
});
test("bounded memory store retains watermarks and refuses unowned release/recovery", async () => {
  const f = setup("direct", new sdk.MemoryNonceReservationStore(1));
  await f.coordinator.execute(f.options);
  await assert.rejects(
    f.coordinator.releaseUnsigned(f.key, reservationId(999)),
    code("CONFLICT"),
  );
  await assert.rejects(
    f.coordinator.reconcile(f.key, reservationId(999), f.options.client),
    code("CONFLICT"),
  );
  const g = setup("session", f.store, 2);
  await assert.rejects(g.coordinator.execute(g.options), code("CONFLICT"));
  assert.equal(g.stats().sends, 0);
  for (const max of [0, -1, 10001, NaN])
    assert.throws(
      () => new sdk.MemoryNonceReservationStore(max),
      code("INVALID_ARGUMENT"),
    );
});

test("explicit obsolete retirement requires consumed nonce or advanced ROOT epoch and keeps evidence", async () => {
  for (const kind of ["direct", "root", "session"]) {
    const f = setup(kind);
    f.setFinalized(false);
    await f.coordinator.execute(f.options);
    await assert.rejects(
      f.coordinator.retireObsolete(f.key, f.options.reservationId, f.snapshot),
      code("STALE_AUTHORITY"),
    );
    const fresh = structuredClone(f.snapshot);
    fresh.nonce++;
    fresh.height++;
    fresh.blockHash.fill(9);
    fresh.stateRoot.fill(9);
    fresh.authorityHash.fill(9);
    const retired = await f.coordinator.retireObsolete(
      f.key,
      f.options.reservationId,
      fresh,
    );
    assert.equal(retired.state, "obsolete");
    assert(retired.canonicalTransaction);
    assert.equal(retired.retirement.nonce, fresh.nonce.toString());
    // Old signed nonce cannot return, even after an explicit retirement.
    await assert.rejects(
      f.coordinator.execute({ ...f.options, reservationId: reservationId(2) }),
      code("STALE_AUTHORITY"),
    );
    Object.assign(f.snapshot, fresh);
    if (kind === "session") f.signing.credential.nonce++;
    else f.signing.nonce++;
    f.setFinalized(true);
    const next = await f.coordinator.execute({
      ...f.options,
      reservationId: reservationId(3),
    });
    assert.equal(next.reservation.state, "consumed");
  }
  const f = setup("root");
  f.options.sign = () => new Promise(() => {});
  await assert.rejects(
    f.coordinator.execute({ ...f.options, timeoutMs: 5 }),
    code("TIMEOUT"),
  );
  const fresh = structuredClone(f.snapshot);
  fresh.authEpoch++;
  fresh.nonce = 0n;
  fresh.height++;
  fresh.blockHash.fill(9);
  fresh.stateRoot.fill(9);
  const result = await f.coordinator.retireObsolete(
    f.key,
    f.options.reservationId,
    fresh,
  );
  assert.equal(result.state, "obsolete");
  assert.equal(result.canonicalTransaction, null);
});

test("invalid context/reconciliation options fail before authority read, signing or submission", async () => {
  for (const patch of [
    { reconciliation: { maxPolls: 0 } },
    { reconciliation: { pollIntervalMs: NaN } },
    { reconciliation: { timeoutMs: Infinity } },
    { reconciliation: { maxPolls: 1n } },
    { reconciliation: { extra: 1 } },
    { context: { ...context, chainId: 1n } },
  ]) {
    const f = setup();
    let reads = 0;
    f.options.readAuthority = async () => {
      reads++;
      return f.snapshot;
    };
    await assert.rejects(
      f.coordinator.execute({ ...f.options, ...patch }),
      code("INVALID_ARGUMENT"),
    );
    assert.equal(reads, 0);
    assert.equal(f.stats().sends, 0);
  }
});
test("32 independent coordinator instances sharing atomic storage allow one conflicting flow", async () => {
  const store = new sdk.MemoryNonceReservationStore(),
    f = setup("session", store);
  const results = await Promise.allSettled(
    Array.from({ length: 32 }, (_, i) =>
      new sdk.NonceCoordinator(store).execute({
        ...f.options,
        reservationId: reservationId(i + 1),
      }),
    ),
  );
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal(
    results.filter((r) => r.status === "rejected" && code("CONFLICT")(r.reason)).length,
    31,
  );
  assert.equal(f.stats().sends, 1);
  assert.equal(f.stats().signs, 1);
});
test("storage cancellation can commit late; the persisted reservation is retained and explicitly released unsigned", async () => {
  const f = setup();
  let value = null,
    release;
  const gate = deferred();
  const adapter = {
    read: async () => value,
    compareExchange: async (k, old, next) => {
      await gate.promise;
      if (JSON.stringify(value) !== JSON.stringify(old)) return false;
      value = next;
      return true;
    },
  };
  const coordinator = new sdk.NonceCoordinator(adapter);
  await assert.rejects(
    coordinator.execute({ ...f.options, timeoutMs: 5 }),
    code("TIMEOUT"),
  );
  assert.equal(f.stats().signs, 0);
  gate.resolve();
  await new Promise((r) => setImmediate(r));
  assert.equal(value.state, "reserved");
  await coordinator.releaseUnsigned(f.key, f.options.reservationId);
  assert.equal(value.state, "released");
});
test("read-only recovery has an overall storage/transport budget and detects options mutation", async () => {
  const f = setup();
  f.setFinalized(false);
  await f.coordinator.execute(f.options);
  const ignored = { reconcileTransaction: () => new Promise(() => {}) };
  await assert.rejects(
    f.coordinator.reconcile(f.key, f.options.reservationId, ignored, { timeoutMs: 5 }),
    code("TIMEOUT"),
  );
  assert.equal((await f.coordinator.inspect(f.key)).state, "uncertain");
  const options = { maxPolls: 1 };
  const mutated = {
    reconcileTransaction: async (bytes) => {
      const r = await f.options.client.reconcileTransaction(bytes);
      options.maxPolls++;
      return r;
    },
  };
  await assert.rejects(
    f.coordinator.reconcile(f.key, f.options.reservationId, mutated, options),
    code("MUTATED_INPUT"),
  );
  assert.equal(f.stats().sends, 1);
});

test(
  "coordinated native projection recovery over actual HTTP consumes one lost-response write",
  { timeout: 10000 },
  async (t) => {
    const f = JSON.parse(
      readFileSync(new URL("./fixtures/rpc-reconciliation.json", import.meta.url)),
    ).fixtures[0];
    const tx = sdk.transactionCodec.decode(bytes(f.canonical)),
      identity = f.identity.result;
    const ctx = {
      chainId: BigInt(identity.chainId),
      genesisHash: bytes(identity.genesisHash),
    };
    const snapshot = {
      context: ctx,
      owner: tx.intent.sender,
      mode: 0,
      keyScheme: 1,
      credentialId: zero(32),
      authEpoch: 0n,
      policyHash: zero(32),
      nonce: tx.envelope.nonce,
      authorityHash: new Uint8Array(32).fill(1),
      height: BigInt(identity.state.height),
      blockHash: bytes(identity.state.blockHash),
      stateRoot: bytes(identity.state.stateRoot),
    };
    let sends = 0;
    const errors = [];
    const server = createServer(async (req, res) => {
      try {
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const input = JSON.parse(Buffer.concat(chunks));
        if (!Array.isArray(input)) {
          sends++;
          assert.equal(input.method, "rsc_sendRawTransaction");
          assert.equal(input.params[0], f.canonical);
          res.socket.destroy();
          return;
        }
        const output = input.map((r) => {
          const field = {
            rsc_getAuthorizationFinalityStatus: "identity",
            rsc_getRootAuthority: "root",
            rsc_getTransactionReceipt: "receipt",
            rsc_getTransactionByHash: "transaction",
            rsc_getBlockByNumber: "block",
            rsc_getTransactionCount: "accountNonce",
          }[r.method];
          assert(field);
          return { ...structuredClone(f[field]), id: r.id };
        });
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify(output.reverse()));
      } catch (e) {
        errors.push(e);
        res.destroy();
      }
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    t.after(() => new Promise((r) => server.close(r)));
    const client = new sdk.ChainRpcClient({
      url: `http://127.0.0.1:${server.address().port}`,
      expected: { ...ctx, authorizationCapability: sdk.AUTHORIZATION_CAPABILITY },
      maxRetries: 3,
    });
    const coordinator = new sdk.NonceCoordinator(new sdk.MemoryNonceReservationStore());
    const result = await coordinator.execute({
      context: ctx,
      intent: tx.intent,
      reservationId: reservationId(91),
      readAuthority: async () => structuredClone(snapshot),
      sign: async () => structuredClone(tx),
      client,
      reconciliation: { maxPolls: 1 },
    });
    assert.equal(result.submission.status, "unknown");
    assert.equal(result.reconciliation.status, "reported-finalized-success");
    assert.equal(result.reservation.state, "consumed");
    assert.equal(result.reservation.transactionHash, f.transactionHash);
    assert.equal(sends, 1);
    assert.deepEqual(errors, []);
  },
);

test("synchronous callback failure still checks mutated authorization inputs", async () => {
  const f = setup();
  f.options.readAuthority = () => {
    f.options.intent.value++;
    throw Error("secret");
  };
  await assert.rejects(f.coordinator.execute(f.options), code("MUTATED_INPUT"));
  assert.equal(f.stats().sends, 0);
});

test("coordinator sanitizes typed store read/write errors before signing", async () => {
  for (const boundary of ["read", "write"])
    for (const mutation of [
      "message",
      "invalid-code",
      "code-getter",
      "prototype-trap",
    ]) {
      let injected = new sdk.CoordinatorError("CONFLICT");
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
      const store = {
          async read() {
            if (boundary === "read") throw injected;
            return null;
          },
          async compareExchange() {
            throw injected;
          },
        },
        f = setup("direct", store, 99);
      await assert.rejects(
        boundary === "read"
          ? f.coordinator.inspect(f.key)
          : f.coordinator.execute(f.options),
        (failure) => {
          assert(failure instanceof sdk.CoordinatorError);
          assert.notEqual(failure, injected);
          assert.equal(
            failure.code,
            mutation === "message" ? "CONFLICT" : "ADAPTER_FAILED",
          );
          assert.ok(!failure.message.includes("private-sentinel"));
          assert.equal(failure.cause, undefined);
          return true;
        },
      );
      assert.equal(f.stats().signs, 0);
      assert.equal(f.stats().sends, 0);
    }
});

test("coordinator constructor sanitizes hostile store accessors", () => {
  assert.throws(
    () =>
      new sdk.NonceCoordinator({
        get read() {
          throw Error("private-sentinel");
        },
        compareExchange() {},
      }),
    (failure) => {
      assert(failure instanceof sdk.CoordinatorError);
      assert.equal(failure.code, "INVALID_ARGUMENT");
      assert.ok(!failure.message.includes("private-sentinel"));
      return true;
    },
  );
});
