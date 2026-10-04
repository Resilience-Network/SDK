import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { p256 } from "@noble/curves/nist.js";
import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import {
  parseClientDataJSON,
  parseAuthenticatorData,
  derToP256Signature,
} from "../dist/webauthn/index.js";
import { sessionDigest } from "../dist/session/index.js";
import { context as chainContext, intent } from "./helpers.mjs";
import {
  ReferenceRelyingParty,
  ReferenceMemoryRpStore,
  ReferenceRpError,
  REFERENCE_VERIFIER,
} from "../examples/webauthn/reference-rp.mjs";
import {
  signedFixture,
  fixtureCbor,
  responseBody,
} from "./webauthn/signed-fixtures.mjs";

const inventory = JSON.parse(
    readFileSync(new URL("./webauthn/rp-contract-cases.json", import.meta.url)),
  ),
  account = "public-fixture-account",
  session = "public-fixture-browser-binding",
  trusted = () => ({
    accountId: account,
    browserSessionId: session,
    enrollmentAuthorized: true,
  });
const error = (value) => {
  assert(value instanceof ReferenceRpError);
  assert.equal(value.message, "Reference RP verification failed");
  return true;
};
async function setup({
  registration = false,
  backupEligible = false,
  backupState = false,
  counter = 5,
  hooks = {},
  recordPatch = {},
} = {}) {
  const fixture = signedFixture({ backupEligible, backupState, counter }),
    store = new ReferenceMemoryRpStore();
  store.putAccount(account, fixture.userHandle);
  let now = 1000000;
  const rp = new ReferenceRelyingParty({
    store,
    config: { rpId: "wallet.example", origins: ["https://wallet.example"] },
    clock: () => now,
    hooks,
  });
  if (!registration)
    store.seedCredential({
      version: 1,
      id: fixture.id,
      accountId: account,
      userHandle: Buffer.from(fixture.userHandle).toString("base64url"),
      algorithm: -7,
      coseKey: Buffer.from(fixture.cose).toString("base64url"),
      rpId: "wallet.example",
      profile: REFERENCE_VERIFIER.profile,
      backupEligible,
      backupState,
      counter,
      state: "active",
      revoked: false,
      storageVersion: 1,
      ...recordPatch,
    });
  const ceremony = registration ? "registration" : "authentication",
    challenge = rp.issueChallenge(ceremony, trusted()),
    valid = () =>
      registration ? fixture.registration(challenge) : fixture.assertion(challenge);
  return {
    fixture,
    store,
    rp,
    challenge,
    registration,
    valid,
    clock: (value) => (now = value),
    now: () => now,
  };
}
const verify = (state, response = state.valid(), binding = trusted(), options = {}) =>
  state.rp.verify(state.challenge.requestId, responseBody(response), binding, options);
function clientChange(response, patch) {
  const value = JSON.parse(
    Buffer.from(response.response.clientDataJSON, "base64url").toString(),
  );
  response.response.clientDataJSON = Buffer.from(
    JSON.stringify({ ...value, ...patch }),
  ).toString("base64url");
}

for (const entry of inventory.cases)
  test(`RP normative: ${entry.id}`, async (t) => {
    const registration = entry.ceremony === "registration",
      mutation = entry.mutation,
      synced = entry.id.includes("synced-"),
      zero = entry.id.includes("zero-counter"),
      state = await setup({
        registration,
        backupEligible: synced,
        counter: zero ? 0 : 5,
      }),
      response = state.valid(),
      original = state.store.credential(state.fixture.id);
    let binding = trusted(),
      body;
    switch (mutation) {
      case "wrong-type":
        clientChange(response, {
          type: registration ? "webauthn.get" : "webauthn.create",
        });
        break;
      case "wrong-challenge":
        clientChange(response, {
          challenge: Buffer.alloc(32, 255).toString("base64url"),
        });
        break;
      case "wrong-origin":
        clientChange(response, { origin: "https://other.example" });
        break;
      case "origin-suffix-confusion":
        clientChange(response, { origin: "https://wallet.example.evil.example" });
        break;
      case "wrong-rp-id-hash":
        Object.assign(
          response,
          registration
            ? state.fixture.registration(state.challenge, { rpId: "other.example" })
            : state.fixture.assertion(state.challenge, { rpId: "other.example" }),
        );
        break;
      case "missing-up":
        Object.assign(
          response,
          registration
            ? state.fixture.registration(state.challenge, { flags: 0x44 })
            : state.fixture.assertion(state.challenge, { flags: 4 }),
        );
        break;
      case "missing-uv":
        Object.assign(
          response,
          registration
            ? state.fixture.registration(state.challenge, { flags: 0x41 })
            : state.fixture.assertion(state.challenge, { flags: 1 }),
        );
        break;
      case "cross-origin":
        clientChange(response, { crossOrigin: true });
        break;
      case "top-origin":
        clientChange(response, { topOrigin: "https://wallet.example" });
        break;
      case "malformed-client-json":
        response.response.clientDataJSON = Buffer.from("{").toString("base64url");
        break;
      case "duplicate-client-json-key": {
        const client = Buffer.from(
          response.response.clientDataJSON,
          "base64url",
        ).toString();
        response.response.clientDataJSON = Buffer.from(
          client.slice(0, -1) +
            ',"type":"' +
            (registration ? "webauthn.create" : "webauthn.get") +
            '"}',
        ).toString("base64url");
        break;
      }
      case "oversized-response":
        body = new Uint8Array(65537);
        break;
      case "expired-at-boundary":
        state.clock(state.challenge.expiresAt);
        break;
      case "clock-before-issuance":
        state.clock(state.challenge.issuedAt - 1);
        break;
      case "wrong-session-binding":
        binding.browserSessionId = "other-binding";
        break;
      case "wrong-account-binding":
        binding.accountId = "other-account";
        break;
      case "replay-consumed-challenge":
        await verify(state);
        break;
      case "storage-take-failure":
        state.store.faults.take = true;
        break;
      case "commit-failure-after-take":
        state.store.faults.commit = true;
        break;
      case "unsupported-algorithm": {
        const key = new Map(state.fixture.coseMap);
        key.set(3, -8);
        Object.assign(
          response,
          state.fixture.registration(state.challenge, { cose: fixtureCbor(key) }),
        );
        break;
      }
      case "invalid-p256-point": {
        const key = new Map(state.fixture.coseMap);
        key.set(-2, Buffer.alloc(32));
        key.set(-3, Buffer.alloc(32));
        Object.assign(
          response,
          state.fixture.registration(state.challenge, { cose: fixtureCbor(key) }),
        );
        break;
      }
      case "non-none-attestation":
        Object.assign(
          response,
          state.fixture.registration(state.challenge, { format: "packed" }),
        );
        break;
      case "nonempty-none-statement":
        Object.assign(
          response,
          state.fixture.registration(state.challenge, {
            statement: new Map([["sig", Buffer.of(1)]]),
          }),
        );
        break;
      case "missing-at":
        Object.assign(
          response,
          state.fixture.registration(state.challenge, { flags: 5 }),
        );
        break;
      case "duplicate-credential-id":
        state.store.seedCredential({
          id: state.fixture.id,
          accountId: "different-account",
        });
        break;
      case "tampered-signature": {
        const signature = Buffer.from(response.response.signature, "base64url");
        signature[signature.length - 1] ^= 1;
        response.response.signature = signature.toString("base64url");
        break;
      }
      case "tampered-original-client-bytes":
        response.response.clientDataJSON = Buffer.from(
          Buffer.from(response.response.clientDataJSON, "base64url").toString() + " ",
        ).toString("base64url");
        break;
      case "unknown-credential":
        response.id = response.rawId = Buffer.of(255).toString("base64url");
        break;
      case "revoked-credential":
        state.store.revoke(state.fixture.id);
        break;
      case "wrong-user-handle":
        response.response.userHandle = Buffer.of(255).toString("base64url");
        break;
      case "credential-id-raw-id-mismatch":
        response.rawId = Buffer.of(255).toString("base64url");
        break;
      case "unexpected-at":
        Object.assign(
          response,
          state.fixture.assertion(state.challenge, { flags: 0x45 }),
        );
        break;
      case "unexpected-ed":
        Object.assign(
          response,
          state.fixture.assertion(state.challenge, { flags: 0x85 }),
        );
        break;
      case "backup-state-without-eligibility":
        Object.assign(
          response,
          state.fixture.assertion(state.challenge, { flags: 0x15 }),
        );
        break;
      case "changed-backup-eligibility":
        Object.assign(
          response,
          state.fixture.assertion(state.challenge, { flags: 0x0d }),
        );
        break;
      case "single-device-counter-regression":
        Object.assign(
          response,
          state.fixture.assertion(state.challenge, { counter: 5 }),
        );
        break;
      case "credential-version-conflict":
        state.rp.hooks.afterVerification = () =>
          state.store.bumpVersion(state.fixture.id);
        break;
      case "synced-counter-nonincreasing":
        Object.assign(
          response,
          state.fixture.assertion(state.challenge, { counter: 0 }),
        );
        break;
      case "synced-backup-state-change":
        Object.assign(
          response,
          state.fixture.assertion(state.challenge, { counter: 0, flags: 0x1d }),
        );
        break;
      case "zero-counter-single-device":
        Object.assign(
          response,
          state.fixture.assertion(state.challenge, { counter: 0 }),
        );
        break;
      case "null-handle-account-bound":
        Object.assign(
          response,
          state.fixture.assertion(state.challenge, { nullHandle: true }),
        );
        break;
      default:
        assert(
          [
            "concurrent-challenge-take",
            "invalid-response-burns-challenge",
            "lost-result-does-not-revive",
            "credential-revoked-during-verification",
            "registration-none-awaits-proof",
            "authentication-expiry-during-verification",
            "authentication-late-verifier-completion-after-cancel",
          ].includes(entry.id),
          `Unhandled inventory mutation ${mutation}`,
        );
        break;
    }
    // Cross-cutting scenarios exercise actual maintained cryptographic verification before commit.
    if (entry.id === "concurrent-challenge-take") {
      const results = await Promise.allSettled([verify(state), verify(state)]);
      assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
      assert.equal(state.store.authenticationCount(), 1);
      return;
    }
    if (entry.id === "invalid-response-burns-challenge") {
      const invalid = state.valid();
      invalid.response.signature = Buffer.from([0x30, 6, 2, 1, 0, 2, 1, 1]).toString(
        "base64url",
      );
      await assert.rejects(verify(state, invalid), error);
      await assert.rejects(verify(state), error);
      assert.equal(state.store.challengeState(state.challenge.requestId), "taken");
      assert.equal(state.store.authenticationCount(), 0);
      return;
    }
    if (entry.id === "lost-result-does-not-revive") {
      await verify(state);
      await assert.rejects(verify(state), error);
      assert.equal(state.store.authenticationCount(), 1);
      return;
    }
    if (entry.id === "credential-revoked-during-verification")
      state.rp.hooks.afterVerification = () => state.store.revoke(state.fixture.id);
    if (entry.id === "registration-none-awaits-proof") {
      const pending = await setup({ registration: true });
      const result = await verify(pending);
      assert.equal(result.status, "awaiting-proof");
      assert.equal(result.applicationAuthenticated, false);
      assert.equal(
        pending.store.credential(pending.fixture.id).state,
        "awaiting-proof",
      );
      assert.equal(pending.store.authenticationCount(), 0);
      const proof = pending.rp.issueChallenge("authentication", trusted());
      const authenticated = await pending.rp.verify(
        proof.requestId,
        responseBody(pending.fixture.assertion(proof)),
        trusted(),
      );
      assert.equal(authenticated.status, "authenticated");
      assert.equal(pending.store.credential(pending.fixture.id).state, "active");
      assert.equal(pending.store.authenticationCount(), 1);
      return;
    }
    if (entry.id === "authentication-expiry-during-verification")
      state.rp.hooks.afterVerification = () => state.clock(state.challenge.expiresAt);
    if (entry.id === "authentication-late-verifier-completion-after-cancel") {
      let entered, release;
      const atHook = new Promise((resolve) => (entered = resolve)),
        held = new Promise((resolve) => (release = resolve));
      state.rp.hooks.afterVerification = async () => {
        entered();
        await held;
      };
      const controller = new AbortController(),
        pending = verify(state, response, trusted(), { signal: controller.signal });
      await atHook;
      controller.abort("private-sentinel");
      await assert.rejects(pending, error);
      release();
      await Promise.resolve();
      await Promise.resolve();
      assert.deepEqual(state.store.credential(state.fixture.id), original);
      assert.equal(state.store.authenticationCount(), 0);
      return;
    }
    if (entry.expected.startsWith("accept-if")) {
      const result = await verify(state, response, binding);
      assert.equal(result.status, "authenticated");
      assert.equal(state.store.authenticationCount(), 1);
      assert.equal(
        result.counter,
        Math.max(
          original.counter,
          mutation === "zero-counter-single-device"
            ? 0
            : mutation?.startsWith("synced-")
              ? 0
              : 6,
        ),
      );
      return;
    }
    assert(
      entry.expected.startsWith("reject"),
      `Unimplemented inventory scenario ${entry.id}`,
    );
    await assert.rejects(
      state.rp.verify(
        state.challenge.requestId,
        body ?? responseBody(response),
        binding,
      ),
      error,
    );
    if (mutation !== "replay-consumed-challenge")
      assert.equal(state.store.authenticationCount(), 0);
    if (
      !registration &&
      ![
        "revoked-credential",
        "credential-version-conflict",
        "replay-consumed-challenge",
      ].includes(mutation) &&
      entry.id !== "credential-revoked-during-verification"
    )
      assert.deepEqual(state.store.credential(state.fixture.id), original);
  });

test("actual ES256 signature verifies under maintained verifier but cannot authorize native SessionDigest", async () => {
  const state = await setup(),
    response = state.valid();
  assert.equal(
    parseClientDataJSON(Buffer.from(response.response.clientDataJSON, "base64url"))
      .type,
    "webauthn.get",
  );
  assert.equal(
    parseAuthenticatorData(
      Buffer.from(response.response.authenticatorData, "base64url"),
      "authentication",
    ).userVerified,
    true,
  );
  const raw = derToP256Signature(Buffer.from(response.response.signature, "base64url"));
  const result = await verifyAuthenticationResponse({
    response,
    expectedChallenge: state.challenge.challenge,
    expectedOrigin: state.challenge.origin,
    expectedRPID: state.challenge.rpId,
    requireUserVerification: true,
    credential: {
      id: state.fixture.id,
      publicKey: state.fixture.cose,
      counter: state.fixture.counter,
    },
  });
  assert.equal(result.verified, true);
  const publicKey = Buffer.concat([
    Buffer.of(4),
    state.fixture.coseMap.get(-2),
    state.fixture.coseMap.get(-3),
  ]);
  const digest = sessionDigest(chainContext, intent, {
    grantId: new Uint8Array(32),
    authEpoch: 1n,
    policyHash: new Uint8Array(32),
    nonce: 1n,
  });
  assert.equal(
    p256.verify(raw, digest, publicKey, { prehash: false, lowS: false }),
    false,
  );
  const tampered = structuredClone(response);
  const signature = Buffer.from(tampered.response.signature, "base64url");
  signature[signature.length - 1] ^= 1;
  tampered.response.signature = signature.toString("base64url");
  assert.equal(
    (
      await verifyAuthenticationResponse({
        response: tampered,
        expectedChallenge: state.challenge.challenge,
        expectedOrigin: state.challenge.origin,
        expectedRPID: state.challenge.rpId,
        credential: { id: state.fixture.id, publicKey: state.fixture.cose, counter: 5 },
      })
    ).verified,
    false,
  );
});

test("synced counter override is deliberate around the maintained verifier's strict default", async () => {
  const state = await setup({ backupEligible: true }),
    response = state.fixture.assertion(state.challenge, { counter: 0 });
  await assert.rejects(
    verifyAuthenticationResponse({
      response,
      expectedChallenge: state.challenge.challenge,
      expectedOrigin: state.challenge.origin,
      expectedRPID: state.challenge.rpId,
      credential: { id: state.fixture.id, publicKey: state.fixture.cose, counter: 5 },
    }),
  );
  const result = await verify(state, response);
  assert.equal(result.counter, 5);
  assert.equal(result.backupEligible, true);
  assert.equal(state.store.credential(state.fixture.id).counter, 5);
});
test("two fresh challenges competing for one credential commit at most once and require fresh recovery", async () => {
  const state = await setup(),
    second = state.rp.issueChallenge("authentication", trusted());
  const results = await Promise.allSettled([
    verify(state),
    state.rp.verify(
      second.requestId,
      responseBody(state.fixture.assertion(second)),
      trusted(),
    ),
  ]);
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(state.store.authenticationCount(), 1);
  assert.equal(state.store.challengeState(state.challenge.requestId), "taken");
  assert.equal(state.store.challengeState(second.requestId), "taken");
  const fresh = state.rp.issueChallenge("authentication", trusted());
  const result = await state.rp.verify(
    fresh.requestId,
    responseBody(state.fixture.assertion(fresh, { counter: 7 })),
    trusted(),
  );
  assert.equal(result.counter, 7);
  assert.equal(state.store.authenticationCount(), 2);
});
test("raw request duplicates/depth and client-supplied verification claims fail after atomic take", async () => {
  for (const mutation of ["duplicate", "depth", "verified", "extensions"]) {
    const state = await setup(),
      response = state.valid();
    let body = responseBody(response);
    if (mutation === "duplicate")
      body = Buffer.from(
        Buffer.from(body).toString().replace("{", '{"type":"public-key",'),
      );
    if (mutation === "depth")
      body = Buffer.from('{"extra":' + "[".repeat(5) + "0" + "]".repeat(5) + "}");
    if (mutation === "verified") {
      response.verified = true;
      body = responseBody(response);
    }
    if (mutation === "extensions") {
      response.clientExtensionResults = { prf: { enabled: true } };
      body = responseBody(response);
    }
    await assert.rejects(
      state.rp.verify(state.challenge.requestId, body, trusted()),
      error,
    );
    assert.equal(state.store.challengeState(state.challenge.requestId), "taken");
    assert.equal(state.store.authenticationCount(), 0);
  }
});
test("unknown request IDs and nonmatching account/browser bindings cannot authenticate or burn a different pending challenge", async () => {
  const state = await setup();
  await assert.rejects(
    state.rp.verify(
      Buffer.alloc(32, 255).toString("base64url"),
      responseBody(state.valid()),
      trusted(),
    ),
    error,
  );
  assert.equal(state.store.challengeState(state.challenge.requestId), "pending");
  await assert.rejects(
    verify(state, state.valid(), { ...trusted(), browserSessionId: "wrong" }),
    error,
  );
  assert.equal(state.store.challengeState(state.challenge.requestId), "pending");
  assert.equal((await verify(state)).applicationAuthenticated, true);
});

test("malformed stored credential versions/counters/backup records fail closed before success", async () => {
  for (const recordPatch of [
    { counter: NaN },
    { counter: -1 },
    { counter: 0x100000000 },
    { storageVersion: 0 },
    { storageVersion: 1.5 },
    { version: 2 },
    { algorithm: -8 },
    { state: "legacy" },
    { backupEligible: "false" },
    { backupState: true },
    { coseKey: "AQ" },
  ]) {
    const state = await setup({ recordPatch }),
      previous = state.store.credential(state.fixture.id);
    await assert.rejects(verify(state), error);
    assert.equal(state.store.authenticationCount(), 0);
    assert.deepEqual(state.store.credential(state.fixture.id), previous);
  }
});

test("actual verifier accepts both mathematical s values while consumed challenge still blocks replay", async () => {
  const state = await setup(),
    response = state.valid(),
    raw = derToP256Signature(Buffer.from(response.response.signature, "base64url"));
  const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  let scalar = 0n;
  for (const byte of raw.subarray(32)) scalar = (scalar << 8n) | BigInt(byte);
  const reflected = (order - scalar).toString(16).padStart(64, "0");
  const integer = (hex) => {
    let bytes = Buffer.from(hex, "hex");
    while (bytes.length > 1 && bytes[0] === 0) bytes = bytes.subarray(1);
    if (bytes[0] & 128) bytes = Buffer.concat([Buffer.of(0), bytes]);
    return Buffer.concat([Buffer.of(2, bytes.length), bytes]);
  };
  const pair = Buffer.concat([
      integer(Buffer.from(raw.subarray(0, 32)).toString("hex")),
      integer(reflected),
    ]),
    other = structuredClone(response);
  other.response.signature = Buffer.concat([
    Buffer.of(0x30, pair.length),
    pair,
  ]).toString("base64url");
  for (const candidate of [response, other])
    assert.equal(
      (
        await verifyAuthenticationResponse({
          response: candidate,
          expectedChallenge: state.challenge.challenge,
          expectedOrigin: state.challenge.origin,
          expectedRPID: state.challenge.rpId,
          credential: {
            id: state.fixture.id,
            publicKey: state.fixture.cose,
            counter: 5,
          },
        })
      ).verified,
      true,
    );
  await verify(state, other);
  await assert.rejects(verify(state, response), error);
  assert.equal(state.store.authenticationCount(), 1);
});
