import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { randomBytes, createHash } from "node:crypto";
import { platform, release, arch } from "node:os";
import { p256 } from "@noble/curves/nist.js";
import {
  createBrowserConsumer,
  withOwnedBrowser,
  importConsumer,
} from "./browser_harness.mjs";
import {
  ReferenceMemoryRpStore,
  ReferenceRelyingParty,
} from "../examples/webauthn/reference-rp.mjs";
import { responseBody } from "../tests/webauthn/signed-fixtures.mjs";
import { derToP256Signature, parseCoseP256PublicKey } from "../dist/webauthn/index.js";
import { sessionDigest } from "../dist/session/index.js";
import { context as nativeContext, intent } from "../tests/helpers.mjs";
const root = fileURLToPath(new URL("../", import.meta.url)),
  engines = (process.env.RSC_BROWSER_ENGINES ?? "chromium,firefox,webkit").split(",");
assert(
  engines.length > 0 &&
    engines.length <= 3 &&
    new Set(engines).size === engines.length &&
    engines.every((engine) => ["chromium", "firefox", "webkit"].includes(engine)),
);
const vectors = JSON.parse(
    await readFile(new URL("../tests/vectors/chain-v1.json", import.meta.url), "utf8"),
  ),
  report = {
    version: 1,
    kind: "actual-installed-browser-qualification",
    sdkRevision: execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: root,
      encoding: "utf8",
    }).trim(),
    trackedClean:
      execFileSync("git", ["status", "--porcelain", "--untracked-files=no"], {
        cwd: root,
        encoding: "utf8",
      }).trim() === "",
    node: process.version,
    os: { platform: platform(), release: release(), arch: arch() },
    requestedEngines: engines,
    unrequestedEngines: ["chromium", "firefox", "webkit"].filter(
      (engine) => !engines.includes(engine),
    ),
    engines: [],
    limitations: [
      "Chromium CDP virtual authenticator only; Firefox/WebKit virtual ceremonies are not advertised",
      "No physical biometric/device/hardware qualification",
      "No durable/multi-worker production RP or independent review",
    ],
  };
const fixture = await createBrowserConsumer();
report.archiveSha256 = fixture.archiveSha256;
report.browserBundleBytes = fixture.bundleBytes;
let successful = false;
function checked(record, name, condition) {
  assert(condition, name);
  record.checks.push({ name, result: "pass" });
  console.log(`${record.engine}: ${name} PASS`);
}
async function ceremony(page, challenge, registration = false, extra = {}) {
  return page.evaluate(
    async ({ challenge, registration, extra }) => {
      const bytes = (value) =>
          Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (char) =>
            char.charCodeAt(0),
          ),
        options = {
          rpId: challenge.rpId,
          origin: challenge.origin,
          developmentLoopback: true,
          challenge: bytes(challenge.challenge),
          ...extra,
        };
      if (registration)
        return sdkConsumer.webauthn.createPasskeyCredential({
          ...options,
          rpName: "Disposable fixture",
          userHandle: bytes(challenge.userHandle),
          userName: "public-fixture",
          userDisplayName: "Public fixture",
        });
      return sdkConsumer.webauthn.getPasskeyAssertion({
        ...options,
        allowCredentialIds: challenge.allowedCredentialIds.map(bytes),
      });
    },
    { challenge, registration, extra },
  );
}
async function virtual({ page, context }, record) {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      defaultBackupEligibility: false,
      defaultBackupState: false,
    },
  });
  try {
    const store = new ReferenceMemoryRpStore();
    store.putAccount("public-browser-fixture", randomBytes(32));
    const rp = new ReferenceRelyingParty({
        store,
        config: {
          rpId: "localhost",
          origins: [fixture.origin],
          developmentLoopback: true,
        },
      }),
      binding = {
        accountId: "public-browser-fixture",
        browserSessionId: "public-fixture-binding",
        enrollmentAuthorized: true,
      },
      registration = rp.issueChallenge("registration", binding),
      created = await ceremony(page, registration, true),
      pending = await rp.verify(registration.requestId, responseBody(created), binding);
    checked(
      record,
      "actual-virtual-registration-awaits-proof",
      pending.status === "awaiting-proof" &&
        !pending.applicationAuthenticated &&
        store.authenticationCount() === 0,
    );
    const challenge = rp.issueChallenge("authentication", binding),
      assertion = await ceremony(page, challenge),
      authenticated = await rp.verify(
        challenge.requestId,
        responseBody(assertion),
        binding,
      );
    checked(
      record,
      "actual-virtual-assertion-real-verifier-commit",
      authenticated.status === "authenticated" &&
        authenticated.applicationAuthenticated &&
        store.authenticationCount() === 1,
    );
    await assert.rejects(
      rp.verify(challenge.requestId, responseBody(assertion), binding),
    );
    checked(record, "actual-response-replay-denied", store.authenticationCount() === 1);
    const stored = store.credential(assertion.id),
      publicKey = parseCoseP256PublicKey(
        Buffer.from(stored.coseKey, "base64url"),
      ).publicKey,
      point = Buffer.concat([Buffer.of(4), publicKey]),
      raw = derToP256Signature(Buffer.from(assertion.response.signature, "base64url")),
      digest = sessionDigest(nativeContext, intent, {
        grantId: new Uint8Array(32),
        authEpoch: 1n,
        policyHash: new Uint8Array(32),
        nonce: 1n,
      });
    checked(
      record,
      "actual-browser-signature-not-native-session",
      !p256.verify(raw, digest, point, { prehash: false, lowS: false }),
    );
    for (const mutation of [
      "challenge",
      "origin",
      "type",
      "rpHash",
      "uv",
      "signature",
      "id",
      "backup",
      "extension",
    ]) {
      const request = rp.issueChallenge("authentication", binding),
        value = await ceremony(page, request),
        before = store.credential(value.id);
      if (["challenge", "origin", "type"].includes(mutation)) {
        const client = JSON.parse(
          Buffer.from(value.response.clientDataJSON, "base64url").toString(),
        );
        client[mutation] =
          mutation === "challenge"
            ? Buffer.alloc(32, 255).toString("base64url")
            : mutation === "origin"
              ? "https://other.example"
              : "webauthn.create";
        value.response.clientDataJSON = Buffer.from(JSON.stringify(client)).toString(
          "base64url",
        );
      }
      if (["rpHash", "uv", "backup"].includes(mutation)) {
        const auth = Buffer.from(value.response.authenticatorData, "base64url");
        if (mutation === "rpHash") auth[0] ^= 1;
        else if (mutation === "uv") auth[32] &= ~4;
        else auth[32] ^= 8;
        value.response.authenticatorData = auth.toString("base64url");
      }
      if (mutation === "signature") {
        const signature = Buffer.from(value.response.signature, "base64url");
        signature[signature.length - 1] ^= 1;
        value.response.signature = signature.toString("base64url");
      }
      if (mutation === "id") value.rawId = Buffer.of(255).toString("base64url");
      if (mutation === "extension")
        value.clientExtensionResults = { prf: { enabled: true } };
      await assert.rejects(rp.verify(request.requestId, responseBody(value), binding));
      assert.deepEqual(store.credential(before.id), before);
      checked(
        record,
        "actual-response-mutated-" + mutation + "-rejected",
        store.authenticationCount() === 1 &&
          store.challengeState(request.requestId) === "taken",
      );
    }
    const pre = rp.issueChallenge("authentication", binding),
      preCode = await page.evaluate(async (request) => {
        const bytes = (value) =>
            Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (char) =>
              char.charCodeAt(0),
            ),
          controller = new AbortController();
        controller.abort();
        try {
          await sdkConsumer.webauthn.getPasskeyAssertion({
            rpId: request.rpId,
            origin: request.origin,
            developmentLoopback: true,
            challenge: bytes(request.challenge),
            allowCredentialIds: request.allowedCredentialIds.map(bytes),
            signal: controller.signal,
          });
          return "unexpected-success";
        } catch (error) {
          return error.code;
        }
      }, pre);
    checked(record, "actual-browser-pre-abort", preCode === "CANCELLED");
    await cdp.send("WebAuthn.setAutomaticPresenceSimulation", {
      authenticatorId,
      enabled: false,
    });
    const cancellation = rp.issueChallenge("authentication", binding);
    await page.evaluate((request) => {
      const bytes = (value) =>
        Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (char) =>
          char.charCodeAt(0),
        );
      globalThis.fixtureAbort = new AbortController();
      globalThis.fixtureOutcome = "pending";
      globalThis.fixtureGetStarted = false;
      globalThis.fixtureNativeSettled = false;
      const container = navigator.credentials,
        original = container.get;
      container.get = function (options) {
        globalThis.fixtureGetStarted = true;
        return original.call(this, options).finally(() => {
          globalThis.fixtureNativeSettled = true;
          container.get = original;
        });
      };
      sdkConsumer.webauthn
        .getPasskeyAssertion({
          rpId: request.rpId,
          origin: request.origin,
          developmentLoopback: true,
          challenge: bytes(request.challenge),
          allowCredentialIds: request.allowedCredentialIds.map(bytes),
          signal: fixtureAbort.signal,
          timeoutMs: 5000,
        })
        .then(
          () => (globalThis.fixtureOutcome = "unexpected-success"),
          (error) => (globalThis.fixtureOutcome = error.code),
        );
    }, cancellation);
    await page.waitForFunction(() => fixtureGetStarted);
    await page.evaluate(() => fixtureAbort.abort());
    await page.waitForFunction(() => fixtureOutcome !== "pending");
    checked(
      record,
      "actual-browser-in-flight-abort",
      await page.evaluate(() => fixtureOutcome === "CANCELLED"),
    );
    await page.waitForFunction(() => fixtureNativeSettled);
    const timeout = rp.issueChallenge("authentication", binding);
    // Return only the SDK classification from the real browser, never browser exception text.
    const controlled = await page.evaluate(async (request) => {
      globalThis.fixtureTimeoutNativeSettled = false;
      const container = navigator.credentials,
        original = container.get;
      container.get = function (options) {
        return original.call(this, options).finally(() => {
          globalThis.fixtureTimeoutNativeSettled = true;
          container.get = original;
        });
      };
      const bytes = (value) =>
        Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (char) =>
          char.charCodeAt(0),
        );
      try {
        await sdkConsumer.webauthn.getPasskeyAssertion({
          rpId: request.rpId,
          origin: request.origin,
          developmentLoopback: true,
          challenge: bytes(request.challenge),
          allowCredentialIds: request.allowedCredentialIds.map(bytes),
          timeoutMs: 100,
        });
        return "unexpected-success";
      } catch (error) {
        return error.code;
      }
    }, timeout);
    record.presenceBlockedOutcome = controlled;
    console.log("chromium: controlled presence-blocked outcome " + controlled);
    checked(
      record,
      "actual-browser-presence-blocked-bounded-failure",
      ["TIMEOUT", "DENIED_OR_UNAVAILABLE"].includes(controlled),
    );
    await page.waitForFunction(() => fixtureTimeoutNativeSettled);
    await cdp.send("WebAuthn.setAutomaticPresenceSimulation", {
      authenticatorId,
      enabled: true,
    });
    await cdp.send("WebAuthn.setResponseOverrideBits", {
      authenticatorId,
      isBadUV: true,
    });
    const uvRequest = rp.issueChallenge("authentication", binding),
      uvCode = await page.evaluate(async (request) => {
        const bytes = (value) =>
          Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (char) =>
            char.charCodeAt(0),
          );
        try {
          await sdkConsumer.webauthn.getPasskeyAssertion({
            rpId: request.rpId,
            origin: request.origin,
            developmentLoopback: true,
            challenge: bytes(request.challenge),
            allowCredentialIds: request.allowedCredentialIds.map(bytes),
            timeoutMs: 1000,
          });
          return "unexpected-success";
        } catch (error) {
          return error.code;
        }
      }, uvRequest);
    record.uvOverrideOutcome = uvCode;
    checked(
      record,
      "actual-virtual-uv-override-fails",
      ["INVALID_RESPONSE", "DENIED_OR_UNAVAILABLE", "TIMEOUT"].includes(uvCode),
    );
    await cdp.send("WebAuthn.setResponseOverrideBits", { authenticatorId });
    const fresh = rp.issueChallenge("authentication", binding),
      freshResponse = await ceremony(page, fresh),
      recovered = await rp.verify(
        fresh.requestId,
        responseBody(freshResponse),
        binding,
      );
    checked(
      record,
      "fresh-actual-ceremony-recovers-after-negatives",
      recovered.applicationAuthenticated && store.authenticationCount() === 2,
    );
    const revoked = rp.issueChallenge("authentication", binding),
      revokedResponse = await ceremony(page, revoked);
    store.revoke(revokedResponse.id);
    await assert.rejects(
      rp.verify(revoked.requestId, responseBody(revokedResponse), binding),
    );
    checked(
      record,
      "actual-credential-revocation-rejected",
      store.authenticationCount() === 2,
    );
  } finally {
    await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
    await cdp.send("WebAuthn.disable");
    await cdp.detach();
  }
}
try {
  for (const engine of engines)
    await withOwnedBrowser(fixture, engine, async (runtime) => {
      const record = {
        engine,
        version: runtime.version,
        distribution: runtime.distribution,
        checks: [],
        virtualAuthenticator:
          engine === "chromium" ? "ctap2_1-cdp-internal-uv" : "not-advertised",
      };
      report.engines.push(record);
      const imported = await importConsumer(runtime.page);
      checked(
        record,
        "installed-entrypoints-cold-no-prompts-fetch",
        Object.values(imported.calls).every((value) => value === 0) &&
          Object.values(imported.entries).every((value) => value > 0),
      );
      checked(record, "loopback-browser-secure-context", imported.secureContext);
      const primitive = await runtime.page.evaluate((vectors) => {
        const { core, session } = sdkConsumer,
          context = {
            chainId: BigInt(vectors.chain.chainId),
            genesisHash: core.hexToBytes(vectors.chain.genesisHash),
          },
          intent = session.txIntentCodec.decode(
            core.hexToBytes(vectors.directTransfer.intentCanonical),
          );
        return {
          hash: core.bytesToHex(core.keccak256(new Uint8Array())),
          intentHash: core.bytesToHex(session.intentHash(context, intent)),
          canonical: core.bytesToHex(session.txIntentCodec.encode(intent)),
          max: core.decodeUint64(core.encodeUint64((1n << 64n) - 1n)).toString(),
          nodeGlobals: [
            typeof globalThis.Buffer,
            typeof globalThis.process,
            typeof globalThis.require,
          ],
        };
      }, vectors);
      checked(
        record,
        "browser-keccak-native-canonical-vector-bigint",
        primitive.hash ===
          "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" &&
          primitive.intentHash === vectors.directTransfer.intentHash &&
          primitive.canonical === vectors.directTransfer.intentCanonical &&
          primitive.max === "18446744073709551615",
      );
      checked(
        record,
        "browser-no-node-globals",
        primitive.nodeGlobals.every((value) => value === "undefined"),
      );
      const signers = await runtime.page.evaluate(
        (vectors) => sdkConsumer.nativeSignerSmoke(vectors),
        vectors,
      );
      checked(
        record,
        "browser-external-ed25519-p256-raw-signers",
        signers.signatures === 2 &&
          signers.directCanonicalBytes > 0 &&
          signers.sessionCanonicalBytes > 0 &&
          signers.reviewBindingMatches,
      );
      if (engine === "chromium") await virtual(runtime, record);
    });
  successful = true;
  report.result = "pass";
  report.failures = 0;
  report.skipped = 0;
  report.todo = 0;
} catch (error) {
  report.result = "failed";
  report.failures = 1;
  report.failureClassification = "browser-qualification-failed";
  throw error;
} finally {
  await fixture.close(successful);
  report.ownedConsumerRemoved = successful;
  const directory = fileURLToPath(new URL("../artifacts/browser/", import.meta.url));
  await mkdir(directory, { recursive: true });
  const sources = [
      "scripts/check_browser.mjs",
      "scripts/browser_harness.mjs",
      "tests/browser/consumer.mjs",
    ],
    hashes = {};
  for (const source of sources)
    hashes[source] = createHash("sha256")
      .update(await readFile(new URL("../" + source, import.meta.url)))
      .digest("hex");
  report.sourceSha256 = hashes;
  await writeFile(directory + "latest.json", JSON.stringify(report, null, 2) + "\n", {
    mode: 0o600,
  });
}
console.log(
  `Actual installed browser qualification PASS: ${report.engines.map((value) => value.distribution + " " + value.version + " (" + value.checks.length + " checks)").join("; ")}.`,
);
