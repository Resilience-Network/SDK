// Local API/package qualification; does not authorize publication or platform claims.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { mkdtemp, mkdir, readFile, readdir, writeFile, rm } from "node:fs/promises";
import { tmpdir, platform, arch } from "node:os";
import { join } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { performance } from "node:perf_hooks";
import { build } from "esbuild";
import { p256 } from "@noble/curves/nist.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const hash = (data) => createHash("sha256").update(data).digest("hex");
const config = JSON.parse(await readFile(join(root, "qualification/api-v1.json")));
assert.equal(config.schema, 1);
assert.equal(process.version, config.node, "Unqualified Node runtime");
const tooling = {};
for (const [name, expected] of Object.entries(config.tooling)) {
  const metadata = JSON.parse(
    await readFile(join(root, "node_modules", name, "package.json")),
  );
  assert.equal(metadata.version, expected, `Unqualified tool ${name}`);
  tooling[name] = metadata.version;
}
const run = (args, cwd = root) =>
  execFileSync(process.execPath, [process.env.npm_execpath, ...args], {
    cwd,
    encoding: "utf8",
    timeout: 90000,
    maxBuffer: 2 * 1024 * 1024,
  });
assert(process.env.npm_execpath, "Run through npm");
const temporary = await mkdtemp(join(tmpdir(), "sdk-api-qualification-"));
await writeFile(join(temporary, ".owned-api-consumer"), "api-v1\n", {
  mode: 0o600,
  flag: "wx",
});
let success = false;
try {
  const [archive] = JSON.parse(
    run(["pack", "--ignore-scripts", "--json", "--pack-destination", temporary]),
  );
  assert(archive.files.length > 0);
  assert(
    archive.files.every(
      ({ path }) =>
        path.startsWith("dist/") || ["README.md", "package.json"].includes(path),
    ),
  );
  await writeFile(
    join(temporary, "package.json"),
    '{"private":true,"type":"module"}\n',
  );
  run(
    [
      "install",
      "--ignore-scripts",
      "--omit=dev",
      "--no-audit",
      "--no-fund",
      "--package-lock=false",
      join(temporary, archive.filename),
    ],
    temporary,
  );
  const dependencyTree = JSON.parse(
    run(["ls", "--omit=dev", "--all", "--json"], temporary),
  );
  function reviewTree(tree) {
    for (const [name, dependency] of Object.entries(tree.dependencies ?? {})) {
      if (name === "@resilience-network/sdk") reviewTree(dependency);
      else {
        assert.equal(
          dependency.version,
          config.dependencies[name],
          `Unexpected runtime dependency ${name}`,
        );
        reviewTree(dependency);
      }
    }
  }
  reviewTree(dependencyTree);
  const installed = join(temporary, "node_modules/@resilience-network/sdk");
  const metadata = JSON.parse(await readFile(join(installed, "package.json")));
  assert.deepEqual(metadata.dependencies, config.dependencies);
  assert.equal(metadata.private, true);
  assert.equal(metadata.license, "UNLICENSED");
  const declarations = {};
  for (const path of (await readdir(join(installed, "dist"), { recursive: true }))
    .filter((p) => p.endsWith(".d.ts"))
    .sort()) {
    declarations[path] = hash(await readFile(join(installed, "dist", path)));
  }
  assert.deepEqual(
    declarations,
    config.declarations,
    "Declaration contract changed; review inventory",
  );
  const entryPaths = Object.keys(metadata.exports);
  assert.deepEqual(entryPaths, config.entryPaths);
  const inventory = {},
    bundles = {},
    entries = {};
  for (const entry of entryPaths) {
    const runtime = Object.keys(
      await import(pathToFileURL(join(installed, metadata.exports[entry].import)).href),
    ).sort();
    inventory[entry] = {
      declarationSha256: hash(
        await readFile(join(installed, metadata.exports[entry].types)),
      ),
      runtime,
    };
    assert.deepEqual(
      inventory[entry],
      config.api[entry],
      `API changed: ${entry}; review and version inventory`,
    );
    const entryFile = join(
      temporary,
      entry === "." ? "root.mjs" : entry.slice(2) + ".mjs",
    );
    await writeFile(
      entryFile,
      `export * from "${metadata.name}${entry === "." ? "" : entry.slice(1)}";\n`,
    );
    entries[entry === "." ? "root" : entry.slice(2)] = entryFile;
    const bundle = await build({
      entryPoints: [entryFile],
      bundle: true,
      write: false,
      platform: "browser",
      format: "esm",
      target: "es2022",
      minify: true,
      treeShaking: false,
      metafile: true,
    });
    assert(
      Object.values(bundle.metafile.outputs).every((o) =>
        o.imports.every((i) => !i.external),
      ),
    );
    assert(
      !Object.keys(bundle.metafile.inputs).some(
        (p) => p.includes("simplewebauthn") || p.includes("playwright"),
      ),
    );
    const bytes = bundle.outputFiles[0].contents,
      gzip = gzipSync(bytes);
    assert(bytes.length <= config.budgets.bundleBytes, `Bundle budget ${entry}`);
    assert(gzip.length <= config.budgets.bundleGzipBytes, `Gzip budget ${entry}`);
    bundles[entry] = {
      bytes: bytes.length,
      gzipBytes: gzip.length,
      sha256: hash(bytes),
    };
  }
  // New process prevents cached imports from masking side effects.
  execFileSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `
 globalThis.fetch=()=>{throw Error("Import attempted network access")};
 for(const name of ["window","navigator","document"])Object.defineProperty(globalThis,name,{get(){throw Error("Import accessed browser globals")}});
 for(const entry of ${JSON.stringify(entryPaths)})await import(${JSON.stringify(metadata.name)}+(entry==="."?"":entry.slice(1)));
 `,
    ],
    { cwd: temporary, timeout: 30000, stdio: "pipe" },
  );
  const notices = {};
  for (const [dependency, version] of Object.entries(config.dependencies)) {
    const directory = join(temporary, "node_modules", dependency);
    const pkg = JSON.parse(await readFile(join(directory, "package.json")));
    const license = await readFile(join(directory, "LICENSE"));
    assert.equal(pkg.version, version);
    assert.equal(pkg.license, "MIT");
    assert(license.length > 100);
    notices[dependency] = {
      version,
      license: pkg.license,
      licenseSha256: hash(license),
    };
  }
  const sdk = await import(pathToFileURL(join(installed, "dist/index.js")).href);
  const vectors = JSON.parse(await readFile(join(root, "tests/vectors/chain-v1.json")));
  const intent = sdk.txIntentCodec.decode(
    sdk.hexToBytes(vectors.directTransfer.intentCanonical),
  );
  const context = {
    chainId: BigInt(vectors.chain.chainId),
    genesisHash: sdk.hexToBytes(vectors.chain.genesisHash),
  };
  const key = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.alloc(32, 1),
    ]),
    format: "der",
    type: "pkcs8",
  });
  const ed = {
    keyScheme: 1,
    publicKey: new Uint8Array(
      createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32),
    ),
    async sign({ digest }) {
      return {
        keyScheme: 1,
        publicKey: this.publicKey,
        signature: new Uint8Array(sign(null, digest, key)),
      };
    },
  };
  const privateP = new Uint8Array(32);
  privateP[31] = 1;
  const ec = {
    keyScheme: 2,
    publicKey: p256.getPublicKey(privateP, false).slice(1),
    async sign({ digest }) {
      return {
        keyScheme: 2,
        publicKey: this.publicKey,
        signature: p256.sign(digest, privateP, { prehash: false }),
      };
    },
  };
  const measurements = {};
  async function measure(name, iterations, operation, budget) {
    for (let i = 0; i < 5; i++) await operation();
    const samples = [];
    for (let batch = 0; batch < 5; batch++) {
      const start = performance.now();
      for (let i = 0; i < iterations; i++) await operation();
      samples.push((performance.now() - start) / iterations);
    }
    samples.sort((a, b) => a - b);
    const median = samples[2];
    assert(median <= budget, `Performance budget exceeded: ${name}`);
    measurements[name] = {
      iterationsPerBatch: iterations,
      batches: 5,
      medianMillisecondsPerOperation: median,
      maximumMillisecondsPerOperation: samples.at(-1),
      budget,
    };
  }
  await measure(
    "intentRoundtripAndDigest",
    100,
    () => {
      const bytes = sdk.txIntentCodec.encode(intent);
      assert.equal(sdk.txIntentCodec.decode(bytes).value, intent.value);
      assert.equal(sdk.directDigest(context, intent, 3n).length, 32);
    },
    config.budgets.codecMilliseconds,
  );
  for (const signer of [ed, ec]) {
    const sessionIntent = { ...intent, sender: sdk.keccak256(ed.publicKey).slice(12) };
    await measure(
      signer.keyScheme === 1 ? "ed25519SessionSigning" : "p256SessionSigning",
      10,
      async () => {
        const result = await sdk.signSessionTransaction({
          context,
          intent: sessionIntent,
          credential: {
            grantId: new Uint8Array(32).fill(1),
            authEpoch: 1n,
            policyHash: new Uint8Array(32).fill(2),
            nonce: 5n,
            keyScheme: signer.keyScheme,
            publicKey: signer.publicKey,
          },
          signer,
        });
        assert.equal(result.envelope.mode, 2);
        assert.equal(
          sdk.transactionCodec.decode(sdk.transactionCodec.encode(result)).intent.value,
          intent.value,
        );
      },
      config.budgets.signingMilliseconds,
    );
  }
  privateP.fill(0);
  const revision = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: root,
    encoding: "utf8",
  }).trim();
  const dirty =
    execFileSync("git", ["status", "--porcelain", "--untracked-files=normal"], {
      cwd: root,
      encoding: "utf8",
    }).trim().length > 0;
  const evidence = {
    schema: 1,
    status: "PASS",
    revision,
    dirty,
    node: process.version,
    tooling,
    profileSha256: hash(JSON.stringify(config)),
    platform: platform(),
    architecture: arch(),
    protocolRevision: JSON.parse(await readFile(join(root, "protocol-source.json")))
      .revision,
    archiveSha256: hash(await readFile(join(temporary, archive.filename))),
    inventorySha256: hash(JSON.stringify({ inventory, declarations })),
    sourceSha256: hash(await readFile(fileURLToPath(import.meta.url))),
    bundles,
    measurements,
    notices,
    limitations: [
      "Local measured performance, not network latency or hardware key-provider performance",
      "SDK UNLICENSED/private; third-party MIT notices do not grant SDK distribution rights",
      "Additional engines/platforms/devices require separate qualification",
    ],
  };
  await mkdir(join(root, "artifacts/api-qualification"), { recursive: true });
  await writeFile(
    join(root, "artifacts/api-qualification/latest.json"),
    JSON.stringify(evidence, null, 2) + "\n",
    { mode: 0o600 },
  );
  console.log(
    `API qualification PASS: ${entryPaths.length} entry points, ${inventory["."].runtime.length} runtime exports, reviewed dependency notices, installed bundles and 3 measured paths. Revision ${revision}; dirty=${dirty}`,
  );
  console.log(JSON.stringify({ bundles, measurements }));
  success = true;
} finally {
  if (success) {
    assert.equal(
      await readFile(join(temporary, ".owned-api-consumer"), "utf8"),
      "api-v1\n",
    );
    await rm(temporary, { recursive: true, force: true });
  } else console.error(`Failed public-only consumer retained: ${temporary}`);
}
