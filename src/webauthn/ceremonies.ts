import { sha256 } from "@noble/hashes/sha2.js";
import { compareBytes } from "../core/bytes.js";
import { ownedBytes } from "./errors.js";
import { decodeBase64url, parseClientDataJSON } from "./client-data.js";
import { parseNoneAttestationObject, parseAuthenticatorData } from "./parsers.js";
import { browserFailure, insist, WebAuthnBrowserError } from "./browser-errors.js";
import {
  encodeBase64url,
  serializePasskeyRegistration,
  serializePasskeyAssertion,
  type SerializedPasskeyRegistration,
  type SerializedPasskeyAssertion,
} from "./serialization.js";

export interface PasskeyCeremonyOptions {
  readonly rpId: string;
  readonly origin: string;
  /** Explicit permission for HTTP localhost/127.0.0.1 in disposable development. */
  readonly developmentLoopback?: boolean;
  readonly challenge: Uint8Array;
  readonly timeoutMs?: number;
  readonly signal?: AbortSignal;
}
export interface PasskeyRegistrationOptions extends PasskeyCeremonyOptions {
  readonly rpName: string;
  readonly userHandle: Uint8Array;
  readonly userName: string;
  readonly userDisplayName: string;
  readonly excludeCredentialIds?: readonly Uint8Array[];
}
export interface PasskeyAssertionOptions extends PasskeyCeremonyOptions {
  readonly allowCredentialIds: readonly Uint8Array[];
}
export interface WebAuthnCapabilities {
  readonly secureContext: boolean;
  readonly registrationAvailable: boolean;
  readonly authenticationAvailable: boolean;
}
/** Call-time API availability only; no prompt, network, device or biometric claim. */
export function webAuthnCapabilities(): WebAuthnCapabilities {
  try {
    const secureContext = globalThis.isSecureContext === true,
      publicKey = typeof globalThis.PublicKeyCredential === "function";
    return Object.freeze({
      secureContext,
      registrationAvailable:
        secureContext &&
        publicKey &&
        typeof globalThis.navigator?.credentials?.create === "function",
      authenticationAvailable:
        secureContext &&
        publicKey &&
        typeof globalThis.navigator?.credentials?.get === "function",
    });
  } catch {
    return Object.freeze({
      secureContext: false,
      registrationAvailable: false,
      authenticationAvailable: false,
    });
  }
}
const sharedFields = [
  "rpId",
  "origin",
  "developmentLoopback",
  "challenge",
  "timeoutMs",
  "signal",
];
function fields(
  value: unknown,
  extra: string[],
): asserts value is Record<string, unknown> {
  insist(
    value !== null && typeof value === "object" && !Array.isArray(value),
    "INVALID_ARGUMENT",
  );
  const prototype = Object.getPrototypeOf(value);
  insist(prototype === Object.prototype || prototype === null, "INVALID_ARGUMENT");
  insist(
    ["rpId", "origin", "challenge"].every((key) => Object.hasOwn(value, key)),
    "INVALID_ARGUMENT",
  );
  insist(
    Reflect.ownKeys(value).every(
      (key) =>
        typeof key === "string" &&
        [...sharedFields, ...extra].includes(key) &&
        Object.hasOwn(Object.getOwnPropertyDescriptor(value, key)!, "value"),
    ),
    "INVALID_ARGUMENT",
  );
}
function text(value: unknown, maximum: number): asserts value is string {
  insist(
    typeof value === "string" &&
      value.length > 0 &&
      value.length <= maximum &&
      !/[\u0000-\u001f\u007f]/.test(value),
    "INVALID_ARGUMENT",
  );
}
function ids(
  value: readonly Uint8Array[],
  minimum: number,
): PublicKeyCredentialDescriptor[] {
  insist(Array.isArray(value), "INVALID_ARGUMENT");
  const length = value.length;
  insist(
    Number.isSafeInteger(length) && length >= minimum && length <= 32,
    "INVALID_ARGUMENT",
  );
  const result: PublicKeyCredentialDescriptor[] = [];
  for (let index = 0; index < length; index++) {
    const item = value[index]!;
    const id = ownedBytes(item, 1023);
    insist(
      !result.some(
        (previous) =>
          compareBytes(new Uint8Array(previous.id as ArrayBuffer), id) === 0,
      ),
      "INVALID_ARGUMENT",
    );
    result.push({ type: "public-key", id: id.buffer as ArrayBuffer });
  }
  return result;
}
function snapshot(options: PasskeyCeremonyOptions) {
  text(options.rpId, 253);
  text(options.origin, 512);
  insist(/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(options.rpId), "INVALID_ARGUMENT");
  const origin = new URL(options.origin);
  insist(
    origin.origin === options.origin &&
      origin.username === "" &&
      origin.password === "",
    "INVALID_ARGUMENT",
  );
  insist(
    origin.hostname === options.rpId || origin.hostname.endsWith("." + options.rpId),
    "INVALID_ARGUMENT",
  );
  insist(
    options.developmentLoopback === undefined ||
      typeof options.developmentLoopback === "boolean",
    "INVALID_ARGUMENT",
  );
  const loopback = ["localhost", "127.0.0.1"].includes(origin.hostname);
  insist(
    origin.protocol === "https:" ||
      (origin.protocol === "http:" && loopback && options.developmentLoopback === true),
    "INVALID_ARGUMENT",
  );
  const challenge = ownedBytes(options.challenge, 32, 32),
    timeoutMs = options.timeoutMs ?? 180000;
  insist(
    Number.isSafeInteger(timeoutMs) && timeoutMs >= 1 && timeoutMs <= 180000,
    "INVALID_ARGUMENT",
  );
  insist(
    options.signal === undefined || options.signal instanceof AbortSignal,
    "INVALID_ARGUMENT",
  );
  return {
    rpId: options.rpId,
    origin: origin.origin,
    challenge,
    timeoutMs,
    signal: options.signal,
  };
}
function ready(context: ReturnType<typeof snapshot>, registration: boolean) {
  if (context.signal?.aborted) throw new WebAuthnBrowserError("CANCELLED");
  const capability = webAuthnCapabilities();
  insist(capability.secureContext, "INVALID_CONTEXT");
  insist(
    registration
      ? capability.registrationAvailable
      : capability.authenticationAvailable,
    "UNSUPPORTED",
  );
  insist(globalThis.location.origin === context.origin, "INVALID_CONTEXT");
  // This profile intentionally excludes embedded cross-origin and related-origin flows.
  insist(globalThis.window.top === globalThis.window.self, "INVALID_CONTEXT");
}
async function bounded<T>(
  context: ReturnType<typeof snapshot>,
  work: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const controller = new AbortController(),
    deadline = performance.now() + context.timeoutMs;
  let timer: ReturnType<typeof setTimeout> | undefined, abort: (() => void) | undefined;
  try {
    return await new Promise<T>((resolve, reject) => {
      let settled = false;
      const fail = (code: "CANCELLED" | "TIMEOUT") => {
        if (settled) return;
        settled = true;
        reject(new WebAuthnBrowserError(code));
        controller.abort();
      };
      abort = () => fail("CANCELLED");
      context.signal?.addEventListener("abort", abort, { once: true });
      if (context.signal?.aborted) {
        fail("CANCELLED");
        return;
      }
      timer = setTimeout(() => fail("TIMEOUT"), context.timeoutMs);
      Promise.resolve()
        .then(() => {
          if (settled) return undefined;
          return work(controller.signal);
        })
        .then(
          (value) => {
            if (settled) return;
            if (performance.now() >= deadline) {
              fail("TIMEOUT");
              return;
            }
            if (context.signal?.aborted) {
              fail("CANCELLED");
              return;
            }
            settled = true;
            resolve(value as T);
          },
          (error) => {
            if (settled) return;
            settled = true;
            reject(browserFailure(error));
          },
        );
    });
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    if (abort) context.signal?.removeEventListener("abort", abort);
  }
}
function bind(
  result: SerializedPasskeyRegistration | SerializedPasskeyAssertion,
  context: ReturnType<typeof snapshot>,
  registration: boolean,
) {
  const client = parseClientDataJSON(
    decodeBase64url(result.response.clientDataJSON, 8192),
  );
  insist(
    client.origin === context.origin &&
      compareBytes(client.challenge, context.challenge) === 0,
    "INVALID_RESPONSE",
  );
  const auth = registration
    ? parseNoneAttestationObject(
        decodeBase64url(
          (result as SerializedPasskeyRegistration).response.attestationObject,
          16384,
        ),
      ).authenticator
    : parseAuthenticatorData(
        decodeBase64url(
          (result as SerializedPasskeyAssertion).response.authenticatorData,
          8192,
        ),
        "authentication",
      );
  insist(
    compareBytes(auth.rpIdHash, sha256(new TextEncoder().encode(context.rpId))) === 0,
    "INVALID_RESPONSE",
  );
}
/** Prompts once; never fetches a challenge, retries, stores keys or verifies the ceremony. */
export async function createPasskeyCredential(
  options: PasskeyRegistrationOptions,
): Promise<SerializedPasskeyRegistration> {
  try {
    fields(options, [
      "rpName",
      "userHandle",
      "userName",
      "userDisplayName",
      "excludeCredentialIds",
    ]);
    insist(
      ["rpName", "userHandle", "userName", "userDisplayName"].every((key) =>
        Object.hasOwn(options, key),
      ),
      "INVALID_ARGUMENT",
    );
    const context = snapshot(options);
    text(options.rpName, 128);
    text(options.userName, 256);
    text(options.userDisplayName, 256);
    const userHandle = ownedBytes(options.userHandle, 64),
      excludeCredentials = ids(options.excludeCredentialIds ?? [], 0);
    const publicKey: PublicKeyCredentialCreationOptions = {
      rp: { id: context.rpId, name: options.rpName },
      user: {
        id: userHandle.buffer as ArrayBuffer,
        name: options.userName,
        displayName: options.userDisplayName,
      },
      challenge: context.challenge.slice().buffer,
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      timeout: context.timeoutMs,
      attestation: "none",
      authenticatorSelection: {
        userVerification: "required",
        residentKey: "preferred",
      },
      excludeCredentials,
    };
    ready(context, true);
    return await bounded(context, async (signal) => {
      const value = await globalThis.navigator.credentials.create({
        publicKey,
        signal,
      });
      insist(!signal.aborted, "CANCELLED");
      const result = serializePasskeyRegistration(value);
      bind(result, context, true);
      return result;
    });
  } catch (error) {
    throw browserFailure(error, "INVALID_ARGUMENT");
  }
}
/** Account-bound allow-list only; RP verification and store commit still required. */
export async function getPasskeyAssertion(
  options: PasskeyAssertionOptions,
): Promise<SerializedPasskeyAssertion> {
  try {
    fields(options, ["allowCredentialIds"]);
    insist(Object.hasOwn(options, "allowCredentialIds"), "INVALID_ARGUMENT");
    const context = snapshot(options),
      allowCredentials = ids(options.allowCredentialIds, 1);
    const allowedIds = new Set(
      allowCredentials.map((credential) =>
        encodeBase64url(new Uint8Array(credential.id as ArrayBuffer)),
      ),
    );
    const publicKey: PublicKeyCredentialRequestOptions = {
      rpId: context.rpId,
      challenge: context.challenge.slice().buffer,
      allowCredentials,
      userVerification: "required",
      timeout: context.timeoutMs,
    };
    ready(context, false);
    return await bounded(context, async (signal) => {
      const value = await globalThis.navigator.credentials.get({ publicKey, signal });
      insist(!signal.aborted, "CANCELLED");
      const result = serializePasskeyAssertion(value);
      insist(allowedIds.has(result.rawId), "INVALID_RESPONSE");
      bind(result, context, false);
      return result;
    });
  } catch (error) {
    throw browserFailure(error, "INVALID_ARGUMENT");
  }
}
