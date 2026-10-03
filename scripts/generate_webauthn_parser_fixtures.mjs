// Explicit regeneration only: signatures/keys are disposable public test fixtures.
// Independent oracle is Node/OpenSSL, not the SDK or noble implementation.
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

assert.deepEqual(
  process.argv.slice(2),
  ["--write"],
  "Use --write for intentional fixture regeneration.",
);
const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const der = (raw) => {
  const parts = [raw.subarray(0, 32), raw.subarray(32)].map((scalar) => {
    let start = 0;
    while (start < scalar.length - 1 && scalar[start] === 0) start++;
    const value = scalar.subarray(start),
      padded = value[0] & 128 ? Buffer.concat([Buffer.of(0), value]) : value;
    return Buffer.concat([Buffer.of(2, padded.length), padded]);
  });
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.of(0x30, body.length), body]);
};
const { publicKey, privateKey } = generateKeyPairSync("ec", {
  namedCurve: "prime256v1",
});
const message = Buffer.from(
    "Public SDK parser interoperability fixture v1; not native SessionDigest",
  ),
  signatures = [];
for (let mask = 0; mask < 4; mask++) {
  let raw;
  for (let attempt = 0; attempt < 256; attempt++) {
    const candidate = sign("sha256", message, {
      key: privateKey,
      dsaEncoding: "ieee-p1363",
    });
    if (((candidate[0] >>> 7) | ((candidate[32] >>> 7) << 1)) === mask) {
      raw = candidate;
      break;
    }
  }
  assert(raw, "OpenSSL padding fixture generation bound exceeded");
  const s = BigInt(`0x${raw.subarray(32).toString("hex")}`),
    reflected = Buffer.concat([
      raw.subarray(0, 32),
      Buffer.from((order - s).toString(16).padStart(64, "0"), "hex"),
    ]);
  for (const [suffix, value] of [
    ["original", raw],
    ["reflected-s", reflected],
  ]) {
    const encoded = der(value);
    assert(verify("sha256", message, publicKey, encoded));
    assert(
      verify("sha256", message, { key: publicKey, dsaEncoding: "ieee-p1363" }, value),
    );
    signatures.push({
      id: `padding-${mask}-${suffix}`,
      raw: value.toString("hex"),
      der: encoded.toString("hex"),
    });
  }
}
const x = "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d",
  y = "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c";
const fixtures = {
  version: 1,
  oracle:
    "Node/OpenSSL SHA-256 ECDSA P1363 output, independently DER-verified; no SDK/noble imports",
  node: process.version,
  openssl: process.versions.openssl,
  w3c: {
    source: "https://www.w3.org/TR/webauthn-3/#sctn-public-key-examples",
    specification:
      "Level 3 Recommendation 2026-08-25, section 6.5.1.1 ES256 COSE example",
    cose: `a5010203262001215820${x}225820${y}`,
    publicKey: x + y,
  },
  message: message.toString("base64url"),
  publicKey: publicKey.export({ format: "jwk" }),
  signatures,
};
const output = JSON.stringify(fixtures, null, 2) + "\n",
  source = await readFile(new URL(import.meta.url));
await writeFile(new URL("../tests/webauthn/parser-v1.json", import.meta.url), output);
await writeFile(
  new URL("../tests/webauthn/parser-v1.provenance.json", import.meta.url),
  JSON.stringify(
    {
      version: 1,
      fixtureSha256: createHash("sha256").update(output).digest("hex"),
      generatorSha256: createHash("sha256").update(source).digest("hex"),
      generatedBy: "scripts/generate_webauthn_parser_fixtures.mjs --write",
      note: "Intentional regeneration uses new disposable keys/signatures; review semantic/provenance changes. No private key stored.",
    },
    null,
    2,
  ) + "\n",
);
console.log(
  "W3C public-key example and 8 OpenSSL-verified DER/P1363 fixtures written; no private key persisted.",
);
