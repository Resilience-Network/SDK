import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const npmCli = process.env.npm_execpath;
assert(npmCli, "Run this check through npm run package:check.");
const temporary = await mkdtemp(join(tmpdir(), "resilience-sdk-package-"));

try {
  const packed = JSON.parse(
    execFileSync(
      process.execPath,
      [npmCli, "pack", "--ignore-scripts", "--json", "--pack-destination", temporary],
      {
        cwd: root,
        encoding: "utf8",
      },
    ),
  )[0];
  const paths = packed.files.map((file) => file.path);
  for (const path of [
    "dist/index.js",
    "dist/index.d.ts",
    "dist/core/index.js",
    "dist/core/index.d.ts",
    "dist/session/index.js",
    "dist/session/index.d.ts",
    "README.md",
    "package.json",
  ]) {
    assert(paths.includes(path), `Missing package file: ${path}`);
  }
  assert(
    paths.every(
      (path) =>
        path.startsWith("dist/") || ["README.md", "package.json"].includes(path),
    ),
  );
  await writeFile(
    join(temporary, "package.json"),
    '{"private":true,"type":"module"}\n',
  );
  execFileSync(
    process.execPath,
    [
      npmCli,
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      join(temporary, packed.filename),
    ],
    {
      cwd: temporary,
      stdio: "pipe",
    },
  );
  const metadata = JSON.parse(
    await readFile(new URL("../package.json", import.meta.url), "utf8"),
  );
  const smoke = `
import assert from "node:assert/strict";
import * as sdk from ${JSON.stringify(metadata.name)};
import * as core from ${JSON.stringify(`${metadata.name}/core`)};
import * as session from ${JSON.stringify(`${metadata.name}/session`)};
assert.equal(core.decodeUint64(core.encodeUint64((1n << 64n) - 1n)), (1n << 64n) - 1n);
assert.equal(core.bytesToHex(core.keccak256(new Uint8Array())), "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
assert.deepEqual(session.setSecurityReserveCodec.decode(session.setSecurityReserveCodec.encode({ version: 1, securityReserve: 1n << 200n })), { version: 1, securityReserve: 1n << 200n });
assert.equal(sdk.policyCodec, session.policyCodec);
assert.equal(sdk.CodecError, core.CodecError);
console.log("Installed root/core/session imports and canonical API smoke checks OK; exports:", Object.keys(sdk).length);
`;
  execFileSync(process.execPath, ["--input-type=module", "-e", smoke], {
    cwd: temporary,
    stdio: "inherit",
  });
  await writeFile(
    join(temporary, "consumer.ts"),
    `
import { encodeUint256 } from ${JSON.stringify(`${metadata.name}/core`)};
import { setSecurityReserveCodec, type SetSecurityReserve, type ChainContext } from ${JSON.stringify(`${metadata.name}/session`)};
import { chainDomain } from ${JSON.stringify(metadata.name)};
const reserve: SetSecurityReserve = { version: 1, securityReserve: 1n << 200n };
const context: ChainContext = { chainId: 1n, genesisHash: new Uint8Array(32) };
encodeUint256(reserve.securityReserve);
setSecurityReserveCodec.encode(reserve);
chainDomain(context);
// @ts-expect-error Protocol integers must remain bigint.
encodeUint256(1);
`,
  );
  execFileSync(
    process.execPath,
    [
      join(root, "node_modules/typescript/bin/tsc"),
      "--noEmit",
      "--strict",
      "--module",
      "NodeNext",
      "--target",
      "ES2022",
      "consumer.ts",
    ],
    {
      cwd: temporary,
      stdio: "inherit",
    },
  );
  console.log(
    "Package archive and downstream root/core/session TypeScript resolution OK.",
  );
} finally {
  await rm(temporary, { recursive: true, force: true });
}
