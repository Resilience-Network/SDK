import {
  codec,
  isZero,
  objectFields,
  requireCondition,
  Reader,
  Writer,
} from "../core/bytes.js";
import { validateSessionPublicKey } from "./keys.js";
import { policyCodec, readPolicy } from "./policy.js";
import { readRootBody, versionOne, writeRootBody } from "./root.js";
import type {
  ActivateAuthorization,
  CleanupGrant,
  CreateGrant,
  GrantSpec,
  ReplaceGrant,
  RevokeGrant,
  RotateRoot,
  Scheme,
  SetSecurityReserve,
} from "./types.js";

function writeGrant(w: Writer, grant: GrantSpec): void {
  objectFields(grant, [
    "keyScheme",
    "publicKey",
    "validAfterHeight",
    "validUntilHeight",
    "policy",
    "storageDeposit",
  ]);
  validateSessionPublicKey(grant.keyScheme, grant.publicKey);
  requireCondition(
    grant.validAfterHeight < grant.validUntilHeight,
    "Invalid grant interval",
    "NON_CANONICAL",
  );
  requireCondition(
    grant.storageDeposit > 0n,
    "Zero grant storage deposit",
    "NON_CANONICAL",
  );
  w.number(grant.keyScheme, 8);
  w.fixed(grant.publicKey, grant.keyScheme === 1 ? 32 : 64);
  w.uint(grant.validAfterHeight, 64);
  w.uint(grant.validUntilHeight, 64);
  w.fixed(policyCodec.encode(grant.policy));
  w.uint(grant.storageDeposit, 256);
}
function readGrant(r: Reader): GrantSpec {
  const keyScheme = r.number(8) as Scheme;
  requireCondition(
    keyScheme === 1 || keyScheme === 2,
    "Unsupported session scheme",
    "UNSUPPORTED_FEATURE",
  );
  return {
    keyScheme,
    publicKey: r.fixed(keyScheme === 1 ? 32 : 64),
    validAfterHeight: r.uint(64),
    validUntilHeight: r.uint(64),
    policy: readPolicy(r),
    storageDeposit: r.uint(256),
  };
}
function actionVersion(w: Writer, value: { version: 1 }): void {
  versionOne(value.version);
  w.number(value.version, 16);
}
function readVersion(r: Reader): 1 {
  versionOne(r.number(16));
  return 1;
}

export const activateAuthorizationCodec = codec<ActivateAuthorization>(
  65_536,
  (w, v) => {
    objectFields(v, ["version", "config", "securityReserve"]);
    actionVersion(w, v);
    writeRootBody(w, v.config);
    w.uint(v.securityReserve, 256);
  },
  (r) => ({
    version: readVersion(r),
    config: readRootBody(r),
    securityReserve: r.uint(256),
  }),
);
export const createGrantCodec = codec<CreateGrant>(
  65_536,
  (w, v) => {
    objectFields(v, ["version", "grant"]);
    actionVersion(w, v);
    writeGrant(w, v.grant);
  },
  (r) => ({ version: readVersion(r), grant: readGrant(r) }),
);
export const revokeGrantCodec = codec<RevokeGrant>(
  34,
  (w, v) => {
    objectFields(v, ["version", "grantId"]);
    actionVersion(w, v);
    w.fixed(v.grantId, 32);
    requireCondition(!isZero(v.grantId), "Zero grant ID", "NON_CANONICAL");
  },
  (r) => ({ version: readVersion(r), grantId: r.fixed(32) }),
);
export const replaceGrantCodec = codec<ReplaceGrant>(
  65_536,
  (w, v) => {
    objectFields(v, ["version", "oldGrantId", "newGrant"]);
    actionVersion(w, v);
    w.fixed(v.oldGrantId, 32);
    requireCondition(!isZero(v.oldGrantId), "Zero old grant ID", "NON_CANONICAL");
    writeGrant(w, v.newGrant);
  },
  (r) => ({ version: readVersion(r), oldGrantId: r.fixed(32), newGrant: readGrant(r) }),
);
export const rotateRootCodec = codec<RotateRoot>(
  65_536,
  (w, v) => {
    objectFields(v, ["version", "config", "reserveMode", "replacementReserve"]);
    actionVersion(w, v);
    writeRootBody(w, v.config);
    requireCondition(
      v.reserveMode === 0 || v.reserveMode === 1,
      "Unsupported reserve mode",
      "UNSUPPORTED_FEATURE",
    );
    requireCondition(
      v.reserveMode !== 0 || v.replacementReserve === 0n,
      "Preserve mode requires zero replacement reserve",
      "NON_CANONICAL",
    );
    w.number(v.reserveMode, 8);
    w.uint(v.replacementReserve, 256);
  },
  (r) => ({
    version: readVersion(r),
    config: readRootBody(r),
    reserveMode: r.number(8) as 0 | 1,
    replacementReserve: r.uint(256),
  }),
);
export const setSecurityReserveCodec = codec<SetSecurityReserve>(
  34,
  (w, v) => {
    objectFields(v, ["version", "securityReserve"]);
    actionVersion(w, v);
    w.uint(v.securityReserve, 256);
  },
  (r) => ({ version: readVersion(r), securityReserve: r.uint(256) }),
);
export const cleanupGrantCodec = codec<CleanupGrant>(
  54,
  (w, v) => {
    objectFields(v, ["version", "owner", "grantId"]);
    actionVersion(w, v);
    w.fixed(v.owner, 20);
    w.fixed(v.grantId, 32);
    requireCondition(
      !isZero(v.owner) && !isZero(v.grantId),
      "Empty cleanup identity",
      "NON_CANONICAL",
    );
  },
  (r) => ({ version: readVersion(r), owner: r.fixed(20), grantId: r.fixed(32) }),
);
