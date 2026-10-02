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
    "dist/rpc/index.js",
    "dist/rpc/index.d.ts",
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
import * as rpc from ${JSON.stringify(`${metadata.name}/rpc`)};
assert.equal(core.decodeUint64(core.encodeUint64((1n << 64n) - 1n)), (1n << 64n) - 1n);
assert.equal(core.bytesToHex(core.keccak256(new Uint8Array())), "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
assert.deepEqual(session.setSecurityReserveCodec.decode(session.setSecurityReserveCodec.encode({ version: 1, securityReserve: 1n << 200n })), { version: 1, securityReserve: 1n << 200n });
assert.equal(sdk.policyCodec, session.policyCodec);
assert.equal(sdk.CodecError, core.CodecError);
assert.equal(sdk.HttpRpcClient, rpc.HttpRpcClient);
assert.equal(sdk.ChainRpcClient, rpc.ChainRpcClient);
assert.equal(sdk.AUTHORIZATION_CAPABILITY, "resilience/tx-auth/2");
const client = new rpc.HttpRpcClient({ url: "https://rpc.example.invalid", fetch: async (_url, init) => {
  const request = JSON.parse(init.body);
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: request.id, result: "0x1" }));
} });
assert.equal(await client.request("rsc_chainId"), "0x1");
const typed = new rpc.ChainRpcClient({ url: "https://rpc.example.invalid", expected: {
  chainId: 1337n, genesisHash: new Uint8Array(32), authorizationCapability: rpc.AUTHORIZATION_CAPABILITY,
}, fetch: async (_url, init) => new Response(JSON.stringify(JSON.parse(init.body).map(request => ({
  jsonrpc: "2.0", id: request.id, result: {
    chainId: "0x539", genesisHash: "0x" + "00".repeat(32), authorizationCapability: rpc.AUTHORIZATION_CAPABILITY,
    state: { blockHash: "0x" + "01".repeat(32), height: "0x1", stateRoot: "0x" + "02".repeat(32), finality: "finalized" },
  },
})))) });
assert.equal((await typed.getAuthorizationFinalityStatus()).state.height, 1n);
console.log("Installed root/core/session/rpc imports and API smoke checks OK; exports:", Object.keys(sdk).length);
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
import { ChainRpcClient, AUTHORIZATION_CAPABILITY, RpcContractError, HttpRpcClient, RpcClientError, type RpcCall, type RpcClock, type RpcOutcome, type AuthorizationSnapshot, type ExpectedChainIdentity, type AuthorizationErrorFamily } from ${JSON.stringify(`${metadata.name}/rpc`)};
const reserve: SetSecurityReserve = { version: 1, securityReserve: 1n << 200n };
const context: ChainContext = { chainId: 1n, genesisHash: new Uint8Array(32) };
encodeUint256(reserve.securityReserve);
setSecurityReserveCodec.encode(reserve);
chainDomain(context);
// @ts-expect-error Protocol integers must remain bigint.
encodeUint256(1);
const client = new HttpRpcClient({ url: "https://rpc.example.invalid" });
const call: RpcCall = { method: "rsc_chainId", params: [] };
const outcomes: Promise<readonly RpcOutcome[]> = client.batch([call]);
const result: Promise<unknown> = client.request("rsc_chainId", [], { signal: new AbortController().signal });
const kind: string = new RpcClientError("TIMEOUT", 1).kind;
const clock: RpcClock = { now: () => 0, setTimeout: () => 1, clearTimeout: () => {} };
// @ts-expect-error RPC quantities require an explicit JSON wire representation.
client.request("rsc_chainId", [1n]);
const expected: ExpectedChainIdentity = { ...context, authorizationCapability: AUTHORIZATION_CAPABILITY };
const typed = new ChainRpcClient({ url: "https://rpc.example.invalid", expected });
const snapshot: Promise<AuthorizationSnapshot> = typed.getAuthorizationSnapshot(new Uint8Array(20), new Uint8Array(32));
const contractCode: string = new RpcContractError("INVALID_RESULT").code;
const family: AuthorizationErrorFamily | undefined = new RpcClientError("NODE_ERROR").authorizationFamily;
// @ts-expect-error Chain identity must be supplied by the application.
new ChainRpcClient({ url: "https://rpc.example.invalid" });
// @ts-expect-error Nonces and chain identity remain bigint, never number.
new ChainRpcClient({ url: "https://rpc.example.invalid", expected: { ...expected, chainId: 1 } });
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
    "Package archive and downstream root/core/session/rpc TypeScript resolution OK.",
  );
} finally {
  await rm(temporary, { recursive: true, force: true });
}
