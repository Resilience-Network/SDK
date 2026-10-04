import * as sdk from "@resilience-network/sdk";
import * as core from "@resilience-network/sdk/core";
import * as session from "@resilience-network/sdk/session";
import * as rpc from "@resilience-network/sdk/rpc";
import * as display from "@resilience-network/sdk/display";
import * as webauthn from "@resilience-network/sdk/webauthn";
import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
export { sdk, core, session, rpc, display, webauthn };
export async function nativeSignerSmoke(vectors) {
  const context = {
    chainId: BigInt(vectors.chain.chainId),
    genesisHash: core.hexToBytes(vectors.chain.genesisHash),
  };
  const secret = crypto.getRandomValues(new Uint8Array(32)),
    publicKey = ed25519.getPublicKey(secret),
    intent = session.txIntentCodec.decode(
      core.hexToBytes(vectors.directTransfer.intentCanonical),
    );
  intent.sender = core.keccak256(publicKey).slice(12);
  let signatures = 0;
  const signer = {
    keyScheme: 1,
    publicKey,
    async sign(request) {
      signatures++;
      return {
        keyScheme: 1,
        publicKey: request.publicKey,
        signature: ed25519.sign(request.digest, secret),
      };
    },
  };
  const direct = await session.signDirectTransaction({
    context,
    intent,
    nonce: 1n,
    signer,
    approve: () => true,
  });
  const tx = session.transactionCodec.decode(session.transactionCodec.encode(direct));
  const pSecret = p256.utils.randomSecretKey(),
    pPublic = p256.getPublicKey(pSecret, false).slice(1);
  const pSigner = {
    keyScheme: 2,
    publicKey: pPublic,
    async sign(request) {
      signatures++;
      return {
        keyScheme: 2,
        publicKey: request.publicKey,
        signature: p256.sign(request.digest, pSecret, { prehash: false, lowS: false }),
      };
    },
  };
  const credential = {
    grantId: new Uint8Array(32).fill(1),
    authEpoch: 1n,
    policyHash: new Uint8Array(32).fill(2),
    nonce: 1n,
    keyScheme: 2,
    publicKey: pPublic,
  };
  const signed = await session.signSessionTransaction({
    context,
    intent,
    credential,
    signer: pSigner,
    approve: () => true,
  });
  const encoded = session.transactionCodec.encode(signed);
  secret.fill(0);
  pSecret.fill(0);
  return {
    signatures,
    directCanonicalBytes: session.transactionCodec.encode(tx).length,
    sessionCanonicalBytes: encoded.length,
    reviewBindingMatches:
      display.reviewTransaction(context, encoded).binding.hash ===
      core.bytesToHex(session.transactionId(context, signed.intent, signed.envelope)),
  };
}
