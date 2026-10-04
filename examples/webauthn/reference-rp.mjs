// Disposable Node conformance reference, not a shipped service or durable store.
import { randomBytes } from "node:crypto";
import {
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { JsonReader, decodeBase64url } from "../../dist/webauthn/client-data.js";
import { ownedBytes } from "../../dist/webauthn/errors.js";
import {
  serializePasskeyRegistration,
  serializePasskeyAssertion,
  parseClientDataJSON,
  parseCoseP256PublicKey,
  parseAuthenticatorData,
  parseNoneAttestationObject,
} from "../../dist/webauthn/index.js";

export const REFERENCE_VERIFIER = Object.freeze({
  package: "@simplewebauthn/server",
  version: "14.0.3",
  profile: "account-bound-es256-same-origin-uv-required-none-attestation",
  store: "single-process-in-memory-conformance-only",
});
export class ReferenceRpError extends Error {
  constructor(code) {
    super("Reference RP verification failed");
    this.name = "ReferenceRpError";
    this.code = [
      "INVALID_ARGUMENT",
      "INVALID_BINDING",
      "CONFLICT",
      "STORE_FAILURE",
      "CHALLENGE_UNAVAILABLE",
      "INVALID_RESPONSE",
      "EXPIRED_OR_CANCELLED",
      "VERIFICATION_FAILED",
    ].includes(code)
      ? code
      : "VERIFICATION_FAILED";
  }
}
const requireState = (condition, code = "INVALID_RESPONSE") => {
    if (!condition) throw new ReferenceRpError(code);
  },
  encoded = (value) => Buffer.from(value).toString("base64url"),
  clone = (value) => structuredClone(value),
  nowValid = (record, now) =>
    Number.isSafeInteger(now) && now >= record.issuedAt && now < record.expiresAt;
function keys(object, allowed) {
  requireState(object && typeof object === "object" && !Array.isArray(object));
  requireState(Object.keys(object).every((key) => allowed.includes(key)));
}
function decoded(value, maximum) {
  return decodeBase64url(value, maximum);
}
function asBuffer(value, maximum) {
  return decoded(value, maximum).buffer;
}

/** Atomic transitions in one JS process only. Never use this Map as a multi-worker lock. */
export class ReferenceMemoryRpStore {
  #accounts = new Map();
  #challenges = new Map();
  #credentials = new Map();
  #outcomes = [];
  faults = { take: false, commit: false };
  putAccount(accountId, userHandle) {
    requireState(
      typeof accountId === "string" && accountId.length > 0 && accountId.length <= 128,
      "INVALID_ARGUMENT",
    );
    requireState(!this.#accounts.has(accountId), "CONFLICT");
    this.#accounts.set(
      accountId,
      Object.freeze({ accountId, userHandle: encoded(ownedBytes(userHandle, 64)) }),
    );
  }
  account(accountId) {
    const value = this.#accounts.get(accountId);
    requireState(value, "INVALID_BINDING");
    return clone(value);
  }
  insertChallenge(record) {
    requireState(!this.#challenges.has(record.requestId), "CONFLICT");
    this.#challenges.set(record.requestId, clone(record));
  }
  take(requestId, context, now) {
    if (this.faults.take) throw new ReferenceRpError("STORE_FAILURE");
    const record = this.#challenges.get(requestId);
    requireState(record && record.state === "pending", "CHALLENGE_UNAVAILABLE");
    // An observed expiry is terminal, even if the application clock later rolls
    // backward. This synchronous transition precedes parsing/crypto and cannot
    // revive through a failed binding or a repeated request.
    if (Number.isSafeInteger(now) && now >= record.expiresAt) {
      record.state = "expired";
      throw new ReferenceRpError("CHALLENGE_UNAVAILABLE");
    }
    requireState(nowValid(record, now), "CHALLENGE_UNAVAILABLE");
    requireState(
      record.accountId === context.accountId &&
        record.browserSessionId === context.browserSessionId,
      "INVALID_BINDING",
    );
    requireState(
      record.ceremony !== "registration" || context.enrollmentAuthorized === true,
      "INVALID_BINDING",
    );
    record.state = "taken"; // No await/read-then-delete/revival between comparison and transition.
    return clone(record);
  }
  challengeState(requestId) {
    return this.#challenges.get(requestId)?.state;
  }
  credential(id) {
    const value = this.#credentials.get(id);
    return value ? clone(value) : undefined;
  }
  credentialIds(accountId) {
    return [...this.#credentials.values()]
      .filter((value) => value.accountId === accountId && !value.revoked)
      .map((value) => value.id);
  }
  revoke(id) {
    const value = this.#credentials.get(id);
    requireState(value, "INVALID_RESPONSE");
    value.revoked = true;
    value.storageVersion++;
  }
  bumpVersion(id) {
    const value = this.#credentials.get(id);
    requireState(value, "INVALID_RESPONSE");
    value.storageVersion++;
  }
  // Fixture-only seeding for independently signed counter/backup scenarios.
  seedCredential(record) {
    requireState(!this.#credentials.has(record.id), "CONFLICT");
    this.#credentials.set(record.id, clone(record));
  }
  commitRegistration(challenge, record, now, signal) {
    requireState(!signal?.aborted && nowValid(challenge, now), "EXPIRED_OR_CANCELLED");
    if (this.faults.commit) throw new ReferenceRpError("STORE_FAILURE");
    requireState(!this.#credentials.has(record.id), "CONFLICT");
    requireState(
      this.account(record.accountId).userHandle === record.userHandle,
      "INVALID_BINDING",
    );
    this.#credentials.set(record.id, clone(record));
    return clone(record);
  }
  commitAuthentication(challenge, previous, observed, now, signal) {
    requireState(!signal?.aborted && nowValid(challenge, now), "EXPIRED_OR_CANCELLED");
    if (this.faults.commit) throw new ReferenceRpError("STORE_FAILURE");
    const current = this.#credentials.get(previous.id);
    requireState(
      current &&
        !current.revoked &&
        current.storageVersion === previous.storageVersion &&
        current.accountId === challenge.accountId &&
        current.userHandle === challenge.userHandle &&
        current.rpId === challenge.profile.rpId &&
        current.profile === challenge.profile.name,
      "CONFLICT",
    );
    requireState(
      this.account(current.accountId).userHandle === current.userHandle,
      "INVALID_BINDING",
    );
    const next = {
      ...current,
      state: "active",
      counter: Math.max(current.counter, observed.signCount),
      backupState: observed.backupState,
      storageVersion: current.storageVersion + 1,
    };
    this.#credentials.set(next.id, next);
    this.#outcomes.push(
      Object.freeze({
        accountId: next.accountId,
        credentialId: next.id,
        version: next.storageVersion,
      }),
    );
    return clone(next);
  }
  authenticationCount() {
    return this.#outcomes.length;
  }
}

function profile(config) {
  keys(config, ["rpId", "origins", "developmentLoopback"]);
  requireState(
    typeof config.rpId === "string" &&
      /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(config.rpId) &&
      config.rpId.length <= 253,
    "INVALID_ARGUMENT",
  );
  requireState(
    Array.isArray(config.origins) &&
      config.origins.length > 0 &&
      config.origins.length <= 8 &&
      new Set(config.origins).size === config.origins.length,
    "INVALID_ARGUMENT",
  );
  requireState(
    config.developmentLoopback === undefined ||
      typeof config.developmentLoopback === "boolean",
    "INVALID_ARGUMENT",
  );
  for (const value of config.origins) {
    requireState(typeof value === "string" && value.length <= 512, "INVALID_ARGUMENT");
    const origin = new URL(value);
    requireState(
      origin.origin === value && !origin.username && !origin.password,
      "INVALID_ARGUMENT",
    );
    requireState(
      origin.hostname === config.rpId || origin.hostname.endsWith("." + config.rpId),
      "INVALID_ARGUMENT",
    );
    requireState(
      origin.protocol === "https:" ||
        (origin.protocol === "http:" &&
          ["localhost", "127.0.0.1"].includes(origin.hostname) &&
          config.developmentLoopback === true),
      "INVALID_ARGUMENT",
    );
  }
  return Object.freeze({
    version: 1,
    name: REFERENCE_VERIFIER.profile,
    rpId: config.rpId,
    origins: Object.freeze([...config.origins]),
  });
}
function canonicalResponse(body, registration) {
  const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
    ownedBytes(body, 65536),
  );
  const value = new JsonReader(text).read();
  keys(value, [
    "id",
    "rawId",
    "type",
    "response",
    "clientExtensionResults",
    "authenticatorAttachment",
  ]);
  const response = value.response;
  keys(
    response,
    registration
      ? ["clientDataJSON", "attestationObject", "transports"]
      : ["clientDataJSON", "authenticatorData", "signature", "userHandle"],
  );
  const credential = {
    id: value.id,
    rawId: asBuffer(value.rawId, 1023),
    type: value.type,
    ...(value.authenticatorAttachment === undefined
      ? {}
      : { authenticatorAttachment: value.authenticatorAttachment }),
    getClientExtensionResults: () => value.clientExtensionResults,
    response: registration
      ? {
          clientDataJSON: asBuffer(response.clientDataJSON, 8192),
          attestationObject: asBuffer(response.attestationObject, 16384),
          getTransports: () => response.transports ?? [],
        }
      : {
          clientDataJSON: asBuffer(response.clientDataJSON, 8192),
          authenticatorData: asBuffer(response.authenticatorData, 8192),
          signature: asBuffer(response.signature, 72),
          userHandle:
            response.userHandle === null ? null : asBuffer(response.userHandle, 64),
        },
  };
  return registration
    ? serializePasskeyRegistration(credential)
    : serializePasskeyAssertion(credential);
}
function validCredential(record) {
  requireState(
    record &&
      record.version === 1 &&
      record.algorithm === -7 &&
      ["awaiting-proof", "active"].includes(record.state),
  );
  requireState(
    typeof record.revoked === "boolean" &&
      typeof record.backupEligible === "boolean" &&
      typeof record.backupState === "boolean" &&
      (!record.backupState || record.backupEligible),
  );
  requireState(
    Number.isSafeInteger(record.counter) &&
      record.counter >= 0 &&
      record.counter <= 0xffffffff &&
      Number.isSafeInteger(record.storageVersion) &&
      record.storageVersion >= 1,
  );
  decoded(record.id, 1023);
  decoded(record.userHandle, 64);
  parseCoseP256PublicKey(decoded(record.coseKey, 1024));
}

async function boundedVerification(record, clock, signal, work) {
  requireState(!signal?.aborted && nowValid(record, clock()), "EXPIRED_OR_CANCELLED");
  let timeout, abort;
  try {
    return await new Promise((resolve, reject) => {
      let settled = false;
      const fail = () => {
        if (!settled) {
          settled = true;
          reject(new ReferenceRpError("EXPIRED_OR_CANCELLED"));
        }
      };
      abort = fail;
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) {
        fail();
        return;
      }
      timeout = setTimeout(fail, record.expiresAt - clock());
      Promise.resolve()
        .then(() => (settled ? undefined : work()))
        .then(
          (result) => {
            if (settled) return;
            if (signal?.aborted || !nowValid(record, clock())) {
              fail();
              return;
            }
            settled = true;
            resolve(result);
          },
          () => {
            if (!settled) {
              settled = true;
              reject(new ReferenceRpError("VERIFICATION_FAILED"));
            }
          },
        );
    });
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
    if (abort) signal?.removeEventListener("abort", abort);
  }
}

export class ReferenceRelyingParty {
  constructor({ store, config, clock = Date.now, hooks = {} }) {
    this.store = store;
    this.profile = profile(config);
    this.clock = clock;
    this.hooks = hooks;
  }
  issueChallenge(ceremony, context, { allowedCredentialIds } = {}) {
    requireState(
      ["registration", "authentication"].includes(ceremony),
      "INVALID_ARGUMENT",
    );
    requireState(
      typeof context.browserSessionId === "string" &&
        context.browserSessionId.length > 0 &&
        context.browserSessionId.length <= 128,
      "INVALID_BINDING",
    );
    requireState(
      ceremony !== "registration" || context.enrollmentAuthorized === true,
      "INVALID_BINDING",
    );
    const account = this.store.account(context.accountId),
      issuedAt = this.clock(),
      ids = allowedCredentialIds ?? this.store.credentialIds(account.accountId);
    requireState(
      Number.isSafeInteger(issuedAt) &&
        issuedAt >= 0 &&
        issuedAt <= Number.MAX_SAFE_INTEGER - 180000,
      "INVALID_ARGUMENT",
    );
    requireState(
      Array.isArray(ids) &&
        ids.length <= 32 &&
        new Set(ids).size === ids.length &&
        (ceremony === "registration" || ids.length > 0),
      "INVALID_ARGUMENT",
    );
    for (const id of ids) {
      decoded(id, 1023);
      const credential = this.store.credential(id);
      requireState(
        credential && !credential.revoked && credential.accountId === account.accountId,
        "INVALID_BINDING",
      );
    }
    const requestId = encoded(randomBytes(32)),
      challenge = encoded(randomBytes(32));
    const record = {
      version: 1,
      requestId,
      challenge,
      ceremony,
      ...account,
      browserSessionId: context.browserSessionId,
      allowedCredentialIds: [...ids],
      profile: clone(this.profile),
      issuedAt,
      expiresAt: issuedAt + 180000,
      state: "pending",
    };
    this.store.insertChallenge(record);
    return Object.freeze({
      requestId,
      challenge,
      ceremony,
      rpId: record.profile.rpId,
      origin: record.profile.origins[0],
      userHandle: record.userHandle,
      allowedCredentialIds: Object.freeze([...ids]),
      issuedAt,
      expiresAt: record.expiresAt,
    });
  }
  async verify(requestId, body, context, { signal } = {}) {
    try {
      requireState(
        typeof requestId === "string" &&
          requestId.length === 43 &&
          decoded(requestId, 32).length === 32,
        "INVALID_ARGUMENT",
      );
      // Take precedes parsing/crypto: invalid bound responses burn their challenge.
      const challenge = this.store.take(requestId, context, this.clock()),
        registration = challenge.ceremony === "registration";
      requireState(
        challenge.version === 1 &&
          challenge.profile.version === 1 &&
          challenge.profile.name === REFERENCE_VERIFIER.profile,
      );
      const response = canonicalResponse(body, registration),
        client = parseClientDataJSON(decoded(response.response.clientDataJSON, 8192));
      requireState(
        encoded(client.challenge) === challenge.challenge &&
          challenge.profile.origins.includes(client.origin),
      );
      const auth = registration
        ? parseNoneAttestationObject(
            decoded(response.response.attestationObject, 16384),
          ).authenticator
        : parseAuthenticatorData(
            decoded(response.response.authenticatorData, 8192),
            "authentication",
          );
      const previous = registration ? undefined : this.store.credential(response.id);
      if (!registration) {
        validCredential(previous);
        requireState(
          previous &&
            !previous.revoked &&
            previous.version === 1 &&
            ["awaiting-proof", "active"].includes(previous.state) &&
            previous.algorithm === -7 &&
            previous.accountId === challenge.accountId &&
            previous.userHandle === challenge.userHandle &&
            previous.rpId === challenge.profile.rpId &&
            previous.profile === challenge.profile.name &&
            challenge.allowedCredentialIds.includes(response.id),
        );
        requireState(
          response.response.userHandle === null ||
            response.response.userHandle === previous.userHandle,
        );
        requireState(auth.backupEligible === previous.backupEligible);
        if (!previous.backupEligible && (auth.signCount > 0 || previous.counter > 0))
          requireState(auth.signCount > previous.counter);
      }
      const verification = await boundedVerification(
        challenge,
        this.clock,
        signal,
        async () => {
          await this.hooks.beforeVerification?.();
          const result = registration
            ? await verifyRegistrationResponse({
                response,
                expectedChallenge: challenge.challenge,
                expectedOrigin: challenge.profile.origins,
                expectedRPID: challenge.profile.rpId,
                expectedType: "webauthn.create",
                requireUserPresence: true,
                requireUserVerification: true,
                supportedAlgorithmIDs: [-7],
              })
            : await verifyAuthenticationResponse({
                response,
                expectedChallenge: challenge.challenge,
                expectedOrigin: challenge.profile.origins,
                expectedRPID: challenge.profile.rpId,
                expectedType: "webauthn.get",
                requireUserVerification: true,
                credential: {
                  id: previous.id,
                  publicKey: decoded(previous.coseKey, 1024),
                  counter: previous.backupEligible ? 0 : previous.counter,
                },
              });
          requireState(result.verified === true, "VERIFICATION_FAILED");
          await this.hooks.afterVerification?.();
          return result;
        },
      );
      requireState(verification.verified === true, "VERIFICATION_FAILED");
      if (registration) {
        requireState(
          verification.registrationInfo.credential.id === response.id &&
            encoded(verification.registrationInfo.credential.publicKey) ===
              encoded(auth.credential.key.coseKey),
        );
        const record = {
          version: 1,
          id: response.id,
          accountId: challenge.accountId,
          userHandle: challenge.userHandle,
          algorithm: -7,
          coseKey: encoded(auth.credential.key.coseKey),
          rpId: challenge.profile.rpId,
          profile: challenge.profile.name,
          backupEligible: auth.backupEligible,
          backupState: auth.backupState,
          counter: auth.signCount,
          state: "awaiting-proof",
          revoked: false,
          storageVersion: 1,
        };
        const committed = this.store.commitRegistration(
          challenge,
          record,
          this.clock(),
          signal,
        );
        return Object.freeze({
          status: "awaiting-proof",
          accountId: committed.accountId,
          credentialId: committed.id,
          storageVersion: committed.storageVersion,
          applicationAuthenticated: false,
        });
      }
      const committed = this.store.commitAuthentication(
        challenge,
        previous,
        auth,
        this.clock(),
        signal,
      );
      return Object.freeze({
        status: "authenticated",
        accountId: committed.accountId,
        credentialId: committed.id,
        storageVersion: committed.storageVersion,
        applicationAuthenticated: true,
        userPresent: auth.userPresent,
        userVerified: auth.userVerified,
        backupEligible: auth.backupEligible,
        backupState: auth.backupState,
        counter: committed.counter,
      });
    } catch (error) {
      let code = "VERIFICATION_FAILED";
      try {
        if (error instanceof ReferenceRpError) code = error.code;
      } catch {}
      throw new ReferenceRpError(code);
    }
  }
}
