// Actual browser app authentication + separate native authorization on an owned
// disposable network. Test-only keys are externally owned, never passkey-derived.
import assert from "node:assert/strict";
import { readFile, readdir, mkdir, writeFile } from "node:fs/promises";
import { randomBytes, createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as sdk from "../../dist/index.js";
import {
  createBrowserConsumer,
  withOwnedBrowser,
  importConsumer,
} from "../../scripts/browser_harness.mjs";
import { withNativeLocalnet } from "../../scripts/localnet/harness.mjs";
import { verifyCapturedLogs } from "../../scripts/localnet/verify-logs.mjs";
import { nativeSessionFixture, signingCalls } from "../session-localnet.mjs";
import {
  ReferenceMemoryRpStore,
  ReferenceRelyingParty,
} from "../webauthn/reference-rp.mjs";
import { responseBody } from "../../tests/webauthn/signed-fixtures.mjs";
import { ExampleApplicationGate } from "./app-gate.mjs";
const root = fileURLToPath(new URL("../../", import.meta.url)),
  controller = new AbortController(),
  abort = () => controller.abort(),
  account = "public-combined-app-fixture",
  browserSessionId = "public-combined-browser-binding",
  gate = new ExampleApplicationGate(),
  checks = [],
  report = {
    version: 1,
    kind: "actual-browser-and-native-session-example",
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
    checks,
    limitations: [
      "Virtual Chrome profile only; no physical-device provenance",
      "Separate externally owned native test keys; no passkey-derived signing or custody",
      "Single-process in-memory RP/application policy, not production session/unlock",
      "Other engines #69, devices #31 and independent review #34 remain unqualified",
    ],
  };
process.once("SIGINT", abort);
process.once("SIGTERM", abort);
let fixture,
  successful = false;
const checked = (name, condition) => {
  assert(condition, name);
  checks.push({ name, result: "pass" });
  console.log(name + " PASS");
};
async function ceremony(page, request, registration = false, cancelled = false) {
  return page.evaluate(
    async ({ request, registration, cancelled }) => {
      const bytes = (value) =>
        Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (char) =>
          char.charCodeAt(0),
        );
      const controller = new AbortController();
      if (cancelled) controller.abort();
      const options = {
        rpId: request.rpId,
        origin: request.origin,
        developmentLoopback: true,
        challenge: bytes(request.challenge),
        signal: controller.signal,
        timeoutMs: 5000,
      };
      if (registration)
        return sdkConsumer.webauthn.createPasskeyCredential({
          ...options,
          rpName: "Disposable combined fixture",
          userHandle: bytes(request.userHandle),
          userName: "public-fixture",
          userDisplayName: "Public fixture",
        });
      try {
        const result = await sdkConsumer.webauthn.getPasskeyAssertion({
          ...options,
          allowCredentialIds: request.allowedCredentialIds.map(bytes),
        });
        return cancelled ? "unexpected-success" : result;
      } catch (error) {
        if (cancelled) return error.code;
        throw error;
      }
    },
    { request, registration, cancelled },
  );
}
try {
  fixture = await createBrowserConsumer();
  report.archiveSha256 = fixture.archiveSha256;
  await withOwnedBrowser(fixture, "chromium", async (runtime) => {
    report.browser = {
      distribution: runtime.distribution,
      version: runtime.version,
      virtualAuthenticator: "ctap2_1-internal-uv",
    };
    const imported = await importConsumer(runtime.page);
    checked(
      "installed browser imports without unsolicited calls",
      Object.values(imported.calls).every((value) => value === 0),
    );
    const cdp = await runtime.context.newCDPSession(runtime.page);
    let authenticatorId;
    try {
      await cdp.send("WebAuthn.enable", { enableUI: false });
      ({ authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
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
      }));
      let offset = 0;
      const store = new ReferenceMemoryRpStore();
      store.putAccount(account, randomBytes(32));
      const rp = new ReferenceRelyingParty({
          store,
          config: {
            rpId: "localhost",
            origins: [fixture.origin],
            developmentLoopback: true,
          },
          clock: () => Date.now() + offset,
        }),
        binding = { accountId: account, browserSessionId, enrollmentAuthorized: true },
        request = rp.issueChallenge("registration", binding),
        registration = await ceremony(runtime.page, request, true),
        pending = await rp.verify(
          request.requestId,
          responseBody(registration),
          binding,
        );
      assert.throws(() => gate.accept(pending, account));
      checked(
        "registration alone cannot authorize application or native work",
        !gate.allowed(account) && store.authenticationCount() === 0,
      );
      const invalid = rp.issueChallenge("authentication", binding),
        bad = await ceremony(runtime.page, invalid);
      const signature = Buffer.from(bad.response.signature, "base64url");
      signature[signature.length - 1] ^= 1;
      bad.response.signature = signature.toString("base64url");
      await assert.rejects(rp.verify(invalid.requestId, responseBody(bad), binding));
      checked(
        "invalid actual browser assertion leaves application gate closed",
        !gate.allowed(account) && store.authenticationCount() === 0,
      );
      const expired = rp.issueChallenge("authentication", binding),
        expiredResponse = await ceremony(runtime.page, expired);
      offset += 180000;
      await assert.rejects(
        rp.verify(expired.requestId, responseBody(expiredResponse), binding),
      );
      checked(
        "expired actual assertion cannot unlock native workflow",
        !gate.allowed(account) && store.authenticationCount() === 0,
      );
      const cancelled = rp.issueChallenge("authentication", binding);
      assert.equal(await ceremony(runtime.page, cancelled, false, true), "CANCELLED");
      checked(
        "cancelled browser ceremony leaves application gate closed",
        !gate.allowed(account) && store.authenticationCount() === 0,
      );
      const login = rp.issueChallenge("authentication", binding),
        assertion = await ceremony(runtime.page, login),
        authenticated = await rp.verify(
          login.requestId,
          responseBody(assertion),
          binding,
        );
      gate.accept(authenticated, account);
      checked(
        "fresh actual browser login opens only application policy gate",
        gate.allowed(account) && store.authenticationCount() === 1,
      );
      await assert.rejects(
        rp.verify(login.requestId, responseBody(assertion), binding),
      );
      gate.clear();
      checked(
        "replayed login cannot restore cleared application gate",
        !gate.allowed(account) && store.authenticationCount() === 1,
      );
      const fresh = rp.issueChallenge("authentication", binding),
        freshResponse = await ceremony(runtime.page, fresh);
      gate.accept(
        await rp.verify(fresh.requestId, responseBody(freshResponse), binding),
        account,
      );
      checked(
        "fresh verified login required before external native key provisioning",
        gate.allowed(account, controller.signal),
      );
      const authority = async (client, owner) => {
        const snapshot = await client.getAccountAuthorizationSnapshot(owner);
        return {
          balance: snapshot.balance,
          accountNonce: snapshot.accountNonce,
          root: sdk.bytesToHex(snapshot.root.authority.canonical),
        };
      };
      let approvals = 0;
      const result = await withNativeLocalnet(
        { signal: controller.signal },
        async (h) => {
          assert(gate.allowed(account, h.signal));
          const secrets = [];
          for (const name of await readdir(`${h.runtime}/keys`))
            secrets.push(
              JSON.parse(await readFile(`${h.runtime}/keys/${name}`, "utf8"))
                .privateKey,
            );
          const f = await nativeSessionFixture(h, {
            observeSecret: (key) => secrets.push(key, key.slice(2)),
            approve: ({ review }) => {
              assert(gate.allowed(account, h.signal));
              assert(Object.isFrozen(review));
              // Explicit fixture approval, separate from the authenticated app login.
              // Production apps must show this canonical review and obtain user consent.
              approvals++;
              return true;
            },
          });
          let writes = 0;
          const send = f.client.submitTransaction.bind(f.client);
          f.client.submitTransaction = async (...args) => {
            writes++;
            return send(...args);
          };
          const held = signingCalls(f.root),
            before = await authority(f.client, f.owner),
            cancelledNative = new AbortController();
          cancelledNative.abort();
          gate.clear();
          await assert.rejects(
            f.lifecycle.execute({
              ...f.options({ kind: "revoke-all", signers: [f.root] }),
              approve: () => gate.allowed(account, h.signal),
            }),
            (error) =>
              error instanceof sdk.LifecycleError && error.code === "REVIEW_REJECTED",
          );
          checked(
            "denied canonical native approval signs and submits nothing",
            writes === 0 && signingCalls(f.root) === held,
          );
          await assert.rejects(
            f.lifecycle.execute({
              ...f.options({ kind: "revoke-all", signers: [f.root] }),
              signal: cancelledNative.signal,
            }),
            (error) => error instanceof sdk.LifecycleError && error.code === "ABORTED",
          );
          assert.deepEqual(await authority(f.client, f.owner), before);
          checked(
            "pre-aborted native operation preserves authority and avoids signing",
            writes === 0 && signingCalls(f.root) === held,
          );
          const unlock = rp.issueChallenge("authentication", binding),
            unlocked = await ceremony(runtime.page, unlock);
          gate.accept(
            await rp.verify(unlock.requestId, responseBody(unlocked), binding),
            account,
          );
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
            checked(
              `raw native scheme ${scheme} transfer finalized`,
              sent.grant.sessionNonce === 1n && sent.grant.usage.successes === 1n,
            );
            const signed = await f.sign(sent.grant, signer);
            await f.run({
              kind: "revoke-grant",
              grantId: grant.grantId,
              signers: [f.root],
            });
            const canonical = sdk.transactionCodec.encode(signed),
              snapshot = await authority(f.client, f.owner);
            const rejected = (error) => {
              assert(error instanceof sdk.RpcClientError);
              assert.equal(error.kind, "node");
              assert.equal(error.rpcCode, -32000);
              assert.equal(error.authorizationFamily, "AUTH_MALFORMED");
              return true;
            };
            await assert.rejects(
              f.client.simulateAuthorizedTransaction(canonical, {
                signal: h.signal,
              }),
              rejected,
            );
            checked(
              `raw native scheme ${scheme} revoked authority simulation denied`,
              true,
            );
            const admission = await send(canonical, { signal: h.signal });
            assert.equal(admission.status, "reported-rejected");
            assert.equal(admission.sendAttempts, 1);
            assert.equal(admission.diagnostic?.code, "NODE_ERROR");
            assert.equal(admission.diagnostic?.rpcCode, -32000);
            // This pinned admission endpoint supplies no authorization family;
            // simulation above supplies the precise family independently.
            assert.equal(admission.diagnostic?.authorizationFamily, undefined);
            assert.deepEqual(await authority(f.client, f.owner), snapshot);
            checked(
              `raw native scheme ${scheme} finalized revocation rejects actual admission`,
              true,
            );
          }
          h.evidence.checks.push({
            name: "combined app authentication and separate native approvals",
            browser: report.browser,
            approvals,
            checks: checks.map((value) => ({ ...value })),
          });
          return {
            evidence: h.evidence,
            verify: () => verifyCapturedLogs(h.evidence, { secrets }),
          };
        },
      );
      await result.verify();
      assert.equal(result.evidence.runtimeRetained, false);
      assert(result.evidence.teardown.allOwnedChildrenClosed);
      report.native = {
        ownershipId: result.evidence.ownershipId,
        chainRevision: result.evidence.chainRevision,
        cgo: result.evidence.cgo,
        go: result.evidence.goVersion,
        rust: result.evidence.rustVersion,
        checks: result.evidence.checks.length,
        logCount: result.evidence.logCapture.logs.length,
        redactionVerified: true,
        ownedChildrenClosed: true,
        runtimeRetained: false,
      };
      gate.clear();
      checked(
        "logout closes app policy after independently finalized native revocation",
        !gate.allowed(account),
      );
    } finally {
      gate.clear();
      if (authenticatorId)
        await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
      await cdp.send("WebAuthn.disable");
      await cdp.detach();
    }
  });
  successful = true;
  report.result = "pass";
} catch (error) {
  report.result = "failed";
  throw error;
} finally {
  gate.clear();
  process.removeListener("SIGINT", abort);
  process.removeListener("SIGTERM", abort);
  if (fixture) await fixture.close(successful);
  report.ownedBrowserConsumerRemoved = successful;
  const directory = fileURLToPath(
    new URL("../../artifacts/passkey-session/", import.meta.url),
  );
  await mkdir(directory, { recursive: true });
  report.sourceSha256 = {};
  for (const source of [
    "examples/passkey-session/run.mjs",
    "examples/passkey-session/app-gate.mjs",
    "examples/session-localnet.mjs",
  ])
    report.sourceSha256[source] = createHash("sha256")
      .update(await readFile(new URL("../../" + source, import.meta.url)))
      .digest("hex");
  await writeFile(directory + "latest.json", JSON.stringify(report, null, 2) + "\n", {
    mode: 0o600,
  });
}
console.log(
  `Combined actual browser/native session example PASS: ${checks.length} checks; ${report.browser.distribution} ${report.browser.version}.`,
);
