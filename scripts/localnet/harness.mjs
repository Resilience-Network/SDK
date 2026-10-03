import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import {
  ChainRpcClient,
  HttpRpcClient,
  AUTHORIZATION_CAPABILITY,
} from "../../dist/rpc/index.js";
import { hexToBytes } from "../../dist/core/index.js";

import { captureOwnedLogs } from "./logs.mjs";

const sdkRoot = fileURLToPath(new URL("../../", import.meta.url));
const sha = (data) => createHash("sha256").update(data).digest("hex");
/** Tracks actual child handles only. Never scans/kills processes by name or stale PID files. */
export class OwnedProcesses {
  #children = [];
  get pids() {
    return this.#children.map((entry) => entry.child.pid).filter(Boolean);
  }
  start(command, args, options = {}) {
    const child = spawn(command, args, {
      ...options,
      shell: false,
      detached: process.platform !== "win32",
    });
    const entry = { child, closed: false, exited: false, error: null };
    entry.done = new Promise((resolve) => {
      child.once("error", (error) => {
        entry.error = error;
        entry.closed = true;
        resolve({ code: null, signal: null });
      });
      child.once("close", (code, signal) => {
        entry.closed = true;
        resolve({ code, signal });
      });
    });
    child.once("exit", () => {
      entry.exited = true;
    });
    this.#children.push(entry);
    return entry;
  }
  // PIDs exposed only in evidence; termination uses the still-owned ChildProcess handle.
  async stop(graceMs = 5000) {
    assert(Number.isSafeInteger(graceMs) && graceMs >= 1 && graceMs <= 10000);
    const terminate = (entry, signal) => {
      if (entry.closed || entry.exited) return;
      try {
        if (process.platform === "win32") entry.child.kill(signal);
        else process.kill(-entry.child.pid, signal);
      } catch (error) {
        if (error.code !== "ESRCH") throw error;
      }
    };
    for (const e of this.#children) terminate(e, "SIGTERM");
    let timer;
    let stopped;
    try {
      stopped = await Promise.race([
        Promise.all(this.#children.map((e) => e.done)).then(() => true),
        new Promise((resolve) => {
          timer = setTimeout(() => resolve(false), graceMs);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
    if (!stopped) {
      for (const e of this.#children) terminate(e, "SIGKILL");
      try {
        await Promise.race([
          Promise.all(this.#children.map((e) => e.done)),
          new Promise((_, reject) => {
            timer = setTimeout(
              () => reject(Error("Owned child did not close after kill")),
              2000,
            );
          }),
        ]);
      } finally {
        clearTimeout(timer);
      }
    }
    assert(
      this.#children.every((e) => e.closed),
      "owned children still active",
    );
  }
}
export async function leaseLoopbackPorts(count) {
  assert(Number.isSafeInteger(count) && count >= 1 && count <= 24);
  const servers = [],
    ports = [];
  try {
    for (let i = 0; i < count; i++) {
      const server = createServer();
      servers.push(server);
      await new Promise((yes, no) => {
        server.once("error", no);
        server.listen(0, "127.0.0.1", yes);
      });
      ports.push(server.address().port);
    }
  } catch (e) {
    await Promise.all(servers.map((s) => new Promise((r) => s.close(() => r()))));
    throw e;
  }
  let released = false;
  return {
    ports,
    async release() {
      if (released) return;
      released = true;
      await Promise.all(servers.map((s) => new Promise((r) => s.close(r))));
    },
  };
}
export async function removeOwnedRuntime(path, ownershipId) {
  const canonical = await realpath(path);
  const info = await lstat(path);
  assert(
    info.isDirectory() && !info.isSymbolicLink(),
    "owned runtime cannot be a symlink",
  );
  assert.equal(
    dirname(canonical),
    await realpath(tmpdir()),
    "runtime must be in the temporary root",
  );
  assert(
    basename(canonical).startsWith("resilience-sdk-native-"),
    "runtime namespace mismatch",
  );
  const marker = JSON.parse(await readFile(join(path, "ownership.json"), "utf8"));
  assert.equal(marker.id, ownershipId, "ownership marker changed; preserve runtime");
  assert.equal(marker.path, canonical, "ownership path changed; preserve runtime");
  assert.equal(marker.disposable, true);
  await rm(path, { recursive: true });
}
function config(data, p2p, rpc, ws, bootstrap) {
  return `data_dir = ${JSON.stringify(data)}
log_level = "info"
[chain]
chain_id = 1337
network_name = "SDK Owned Native Test Network"
slot_duration = "1s"
slots_per_epoch = 32
max_rounds_per_slot = 3
max_validators = 128
min_stake_rsc = 10000
block_reward_rsc = 2.0
unbonding_epochs = 14
slash_double_sign_bps = 500
slash_downtime_bps = 10
max_missed_blocks_before_jail = 100
gas_limit = 30000000
min_gas_price_gwei = 1
shielded_activation_height = 1
name_service_activation_height = 1
liquid_staking_activation_height = 1
[p2p]
listen_addresses = ["/ip4/127.0.0.1/tcp/${p2p}"]
bootstrap_peers = ${JSON.stringify(bootstrap)}
max_peers = 50
enable_mdns = false
node_key_file = ${JSON.stringify(join(data, "node.key"))}
allow_private_subnet_bypass = true
[rpc]
enabled = true
http_addr = "127.0.0.1:${rpc}"
ws_addr = "127.0.0.1:${ws}"
cors_allowed_origins = ["http://127.0.0.1:3000"]
[validator]
enabled = false
key_file = ${JSON.stringify(join(data, "validator.key"))}
`;
}
/** All artifacts are run-owned. On failure/interrupt retain restricted runtime/evidence. */
export async function withNativeLocalnet(options, work) {
  const {
    chainDir = process.env.RSC_CHAIN_DIR,
    validators = 4,
    readyTimeoutMs = 120000,
    workTimeoutMs = 600000,
    signal,
    failureStage,
    overflowRecipient = false,
  } = options ?? {};
  assert(
    typeof overflowRecipient === "boolean",
    "overflowRecipient must be explicit boolean",
  );
  assert(chainDir, "Set RSC_CHAIN_DIR to the immutable clean Chain checkout");
  assert(
    [1, 4].includes(validators),
    "supported explicit profiles: 1 or 4; no automatic fallback",
  );
  assert(
    Number.isSafeInteger(readyTimeoutMs) &&
      readyTimeoutMs >= 1 &&
      readyTimeoutMs <= 300000,
  );
  assert(
    Number.isSafeInteger(workTimeoutMs) &&
      workTimeoutMs >= 1 &&
      workTimeoutMs <= 3600000,
  );
  assert(
    failureStage === undefined ||
      ["before-start", "after-ready"].includes(failureStage),
  );
  const chain = await realpath(chainDir),
    pin = JSON.parse(await readFile(join(sdkRoot, "protocol-source.json"), "utf8"));
  const ownershipId = randomUUID(),
    runtime = await mkdtemp(join(await realpath(tmpdir()), "resilience-sdk-native-"));
  await chmod(runtime, 0o700);
  const artifacts = join(sdkRoot, "test-results", "localnet", ownershipId);
  await mkdir(artifacts, { recursive: true, mode: 0o700 });
  await writeFile(
    join(runtime, "ownership.json"),
    JSON.stringify({
      id: ownershipId,
      path: await realpath(runtime),
      disposable: true,
      pin: pin.revision,
    }),
    { mode: 0o600, flag: "wx" },
  );
  const processes = new OwnedProcesses(),
    files = [],
    secrets = [],
    evidence = {
      version: 1,
      ownershipId,
      testOnly: true,
      chainRevision: pin.revision,
      nodeRuntime: process.version,
      validators,
      overflowRecipient,
      runtime,
      artifacts,
      commands: [],
      status: "starting",
      checks: [],
    };
  let portsLease,
    readinessTimer,
    success = false,
    interrupted = false;
  const controller = new AbortController();
  const cancel = () => {
    interrupted = true;
    controller.abort();
  };
  signal?.addEventListener("abort", cancel, { once: true });
  if (signal?.aborted) cancel();
  const check = () => {
    if (controller.signal.aborted) throw Error("Owned native run aborted");
  };
  const command = async (
    executable,
    args,
    { cwd = chain, env = process.env, timeoutMs = 120000 } = {},
  ) => {
    check();
    evidence.commands.push({
      executable,
      args,
      cwd,
      log: `command-${evidence.commands.length + 1}.log`,
    });
    const logs = join(runtime, `command-${evidence.commands.length}.log`),
      file = await open(logs, "wx", 0o600);
    files.push(file);
    const entry = processes.start(executable, args, {
      cwd,
      env,
      stdio: ["ignore", file.fd, file.fd],
    });
    let timer, onAbort;
    try {
      const result = await Promise.race([
        entry.done,
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(Error("Owned command deadline")), timeoutMs);
          onAbort = () => reject(Error("Owned command aborted"));
          controller.signal.addEventListener("abort", onAbort, { once: true });
          if (controller.signal.aborted) onAbort();
        }),
      ]);
      check();
      assert(!entry.error && result.code === 0, `Owned command failed: ${executable}`);
    } finally {
      clearTimeout(timer);
      controller.signal.removeEventListener("abort", onAbort);
    }
    return readFile(logs, "utf8");
  };
  const clean = async () =>
    assert.equal(
      (await command("git", ["status", "--porcelain", "--untracked-files=all"])).trim(),
      "",
      "pinned Chain checkout must remain clean",
    );
  try {
    assert.equal((await command("git", ["rev-parse", "HEAD"])).trim(), pin.revision);
    await clean();
    evidence.sdkRevision = (
      await command("git", ["rev-parse", "HEAD"], { cwd: sdkRoot })
    ).trim();
    evidence.sdkWorkingTree = (
      await command("git", ["status", "--porcelain", "--untracked-files=all"], {
        cwd: sdkRoot,
      })
    ).trim();
    evidence.harnessSha256 = sha(await readFile(fileURLToPath(import.meta.url)));
    assert.equal(
      (await command("go", ["env", "CGO_ENABLED"])).trim(),
      "1",
      "native CGO=1 required",
    );
    evidence.goVersion = (await command("go", ["version"])).trim();
    evidence.rustVersion = (await command("rustc", ["--version"])).trim();
    evidence.cgo = "1";
    assert.equal(
      sha(await readFile(join(chain, pin.vectorPaths[0]))),
      pin.vectorSha256,
    );
    await command("make", ["build-crypto"]);
    const binaries = {};
    for (const name of ["resilienced", "keygen"]) {
      binaries[name] = join(runtime, name);
      await command("go", [
        "build",
        "-trimpath",
        "-o",
        binaries[name],
        `./cmd/${name}`,
      ]);
    }
    await command("bash", [
      "scripts/check_native_release.sh",
      binaries.resilienced,
      binaries.keygen,
    ]);
    evidence.nativeBinaries = {};
    for (const [name, path] of Object.entries(binaries))
      evidence.nativeBinaries[name] = {
        sha256: sha(await readFile(path)),
        buildInfo: await command("go", ["version", "-m", path]),
      };
    const keys = join(runtime, "keys"),
      genesisPath = join(runtime, "genesis.json");
    await command(binaries.keygen, [
      "--count",
      String(validators),
      "--out-dir",
      keys,
      "--genesis-out",
      genesisPath,
      "--validator-stake-rsc",
      "20000",
    ]);
    const walletPaths = {
      owner: join(keys, "wallet-owner.json"),
      recipient: join(keys, "wallet-recipient.json"),
      ...(overflowRecipient ? { overflow: join(keys, "wallet-overflow.json") } : {}),
    };
    for (const path of Object.values(walletPaths))
      await command(binaries.keygen, ["--out", path]);
    const wallets = {};
    for (const [role, path] of Object.entries(walletPaths))
      wallets[role] = JSON.parse(await readFile(path, "utf8"));
    const genesis = JSON.parse(await readFile(genesisPath, "utf8"));
    for (const [role, wallet] of Object.entries(wallets))
      genesis.allocations.push({
        address: wallet.address,
        balance:
          role === "owner"
            ? "1000000000000000000000"
            : role === "overflow"
              ? ((1n << 256n) - 1n).toString()
              : "0",
      });
    await writeFile(genesisPath, JSON.stringify(genesis), { mode: 0o600 });
    for (const path of [
      ...Object.values(walletPaths),
      ...Array.from({ length: validators }, (_, i) =>
        join(keys, `validator-${i + 1}.key.json`),
      ),
    ]) {
      const k = JSON.parse(await readFile(path, "utf8"));
      secrets.push(k.privateKey);
      await chmod(path, 0o600);
    }
    // Exclusively installed native test uses production genesis assembly; checked teardown.
    const source = await readFile(
      join(sdkRoot, "tests/go-localnet-reference/genesis_test.go"),
    );
    const installed = join(
        chain,
        "internal/blockchain",
        `sdk_genesis_${ownershipId.replaceAll("-", "")}_test.go`,
      ),
      identityPath = join(runtime, "expected-identity.json");
    await writeFile(installed, source, { flag: "wx" });
    try {
      await command(
        "go",
        [
          "test",
          "./internal/blockchain",
          "-run",
          "^TestSDKOwnedGenesisIdentity$",
          "-count=1",
        ],
        {
          env: {
            ...process.env,
            RSC_SDK_GENESIS_INPUT: genesisPath,
            RSC_SDK_GENESIS_OUTPUT: identityPath,
          },
        },
      );
    } finally {
      assert.deepEqual(
        await readFile(installed),
        source,
        "temporary owned native test changed; preserve",
      );
      await rm(installed);
    }
    await clean();
    const expectedNative = JSON.parse(await readFile(identityPath, "utf8"));
    const expected = {
      chainId: BigInt(expectedNative.chainId),
      genesisHash: hexToBytes(expectedNative.genesisHash, 32),
      authorizationCapability: AUTHORIZATION_CAPABILITY,
    };
    await writeFile(join(artifacts, "genesis.json"), JSON.stringify(genesis, null, 2), {
      mode: 0o600,
    });
    evidence.genesis = {
      sha256: sha(await readFile(genesisPath)),
      ...expectedNative,
      publicValidators: genesis.validators,
      wallets: Object.fromEntries(
        Object.entries(wallets).map(([role, k]) => [
          role,
          { address: k.address, publicKey: k.publicKey },
        ]),
      ),
    };
    portsLease = await leaseLoopbackPorts(validators * 3);
    const ports = portsLease.ports;
    await portsLease.release();
    if (failureStage === "before-start") throw Error("Injected owned setup failure");
    readinessTimer = setTimeout(() => controller.abort(), readyTimeoutMs);
    const urls = [],
      http = [],
      clients = [],
      entries = [],
      peerIds = [];
    const endsAt = performance.now() + readyTimeoutMs;
    const wait = async (label, probe) => {
      while (true) {
        check();
        assert(performance.now() < endsAt, `${label} readiness deadline`);
        for (const e of entries)
          assert(!e.closed && !e.error, "owned validator exited during readiness");
        try {
          const result = await probe();
          if (result) return result;
        } catch (error) {
          if (entries.some((e) => e.closed || e.error)) throw error;
        }
        await delay(100, undefined, { signal: controller.signal }).catch(() => check());
      }
    };
    for (let i = 0; i < validators; i++) {
      check();
      const data = join(runtime, `node-${i + 1}`);
      await mkdir(data, { mode: 0o700 });
      const cfg = join(runtime, `node-${i + 1}.toml`);
      const bootstrap = peerIds.map(
        (id, j) => `/ip4/127.0.0.1/tcp/${ports[j * 3]}/p2p/${id}`,
      );
      const publicConfig = config(
        data,
        ports[i * 3],
        ports[i * 3 + 1],
        ports[i * 3 + 2],
        bootstrap,
      );
      await writeFile(cfg, publicConfig, { mode: 0o600 });
      await writeFile(join(artifacts, `node-${i + 1}.toml`), publicConfig, {
        mode: 0o600,
      });
      const log = await open(join(runtime, `node-${i + 1}.log`), "wx", 0o600);
      files.push(log);
      const args = [
        "--config",
        cfg,
        "--data-dir",
        data,
        "--genesis",
        genesisPath,
        "--validator",
        "--validator-key",
        join(keys, `validator-${i + 1}.key.json`),
      ];
      evidence.commands.push({
        executable: binaries.resilienced,
        args,
        cwd: chain,
        log: `node-${i + 1}.log`,
      });
      const entry = processes.start(binaries.resilienced, args, {
        cwd: chain,
        env: {
          ...process.env,
          RESILIENCE_ALLOW_UNVERIFIED_SHIELDED:
            "I-UNDERSTAND-THE-VERIFIER-IS-UNVERIFIED",
        },
        stdio: ["ignore", log.fd, log.fd],
      });
      entries.push(entry);
      const url = `http://127.0.0.1:${ports[i * 3 + 1]}`;
      urls.push(url);
      http.push(new HttpRpcClient({ url, timeoutMs: 2000, maxRetries: 0 }));
      clients.push(
        new ChainRpcClient({ url, expected, timeoutMs: 3000, maxContextRefreshes: 3 }),
      );
      const info = await wait(`validator ${i + 1} RPC`, async () => {
        const info = await http[i].request("rsc_nodeInfo", [], {
          signal: controller.signal,
        });
        assert.equal(typeof info.peerId, "string");
        return info;
      });
      peerIds.push(info.peerId);
      const observed = await clients[i].getAuthorizationFinalityStatus({
        signal: controller.signal,
      });
      assert.equal(observed.chainId, expected.chainId);
    }
    evidence.nodePids = entries.map((e) => e.child.pid);
    evidence.urls = urls;
    await wait("native finalized progress", async () => {
      const heights = await Promise.all(
        http.map((h) =>
          h.request("rsc_blockNumber", [], { signal: controller.signal }),
        ),
      );
      return heights.every((h) => BigInt(h) >= 3n) ? heights : null;
    });
    const target = BigInt(await http[0].request("rsc_blockNumber"));
    const blocks = await wait("validator agreement", async () => {
      const blocks = await Promise.all(
        http.map((h) =>
          h.request("rsc_getBlockByNumber", [`0x${target.toString(16)}`, false], {
            signal: controller.signal,
          }),
        ),
      );
      return blocks.every(
        (b) => b && b.hash === blocks[0].hash && b.stateRoot === blocks[0].stateRoot,
      )
        ? blocks
        : null;
    });
    evidence.checks.push({
      name: "finalized progress and same-height native block/state agreement",
      height: target.toString(),
      hash: blocks[0].hash,
      stateRoot: blocks[0].stateRoot,
    });
    const shielded = {
      pool: await http[0].request("rsc_getShieldedPoolBalance"),
      tree: await http[0].request("rsc_getShieldedTreeState"),
    };
    evidence.checks.push({ name: "native shielded read APIs", ...shielded });
    const ownerBalance = await http[0].request("rsc_getBalance", [
      wallets.owner.address,
      "latest",
    ]);
    assert(BigInt(ownerBalance) >= 1000000000000000000000n);
    evidence.checks.push({
      name: "native genesis-funded owner",
      balance: ownerBalance,
    });
    if (failureStage === "after-ready") throw Error("Injected owned readiness failure");
    check();
    clearTimeout(readinessTimer);
    evidence.status = "ready";
    const handle = {
      runtime,
      artifacts,
      expected,
      urls,
      clients,
      http,
      walletPaths,
      publicWallets: evidence.genesis.wallets,
      signal: controller.signal,
      evidence,
    };
    let workTimer, onWorkAbort;
    let result;
    try {
      result = await Promise.race([
        Promise.resolve().then(() => {
          check();
          return work(handle);
        }),
        new Promise((_, reject) => {
          workTimer = setTimeout(() => {
            controller.abort();
            reject(Error("Owned integration callback deadline"));
          }, workTimeoutMs);
          onWorkAbort = () => reject(Error("Owned integration callback aborted"));
          controller.signal.addEventListener("abort", onWorkAbort, { once: true });
          if (controller.signal.aborted) onWorkAbort();
        }),
      ]);
    } finally {
      clearTimeout(workTimer);
      controller.signal.removeEventListener("abort", onWorkAbort);
    }
    check();
    await clean();
    success = true;
    evidence.status = "passed";
    return result;
  } catch (error) {
    evidence.status = interrupted ? "interrupted" : "failed";
    evidence.failure = { code: "NATIVE_RUN_FAILED", phase: evidence.status };
    throw error;
  } finally {
    signal?.removeEventListener("abort", cancel);
    clearTimeout(readinessTimer);
    controller.abort();
    let teardown = false;
    try {
      await processes.stop();
      teardown = true;
    } finally {
      await portsLease?.release();
      for (const file of files) await file.close().catch(() => {});
      evidence.teardown = { allOwnedChildrenClosed: teardown };
      // Only the explicit log of an owned command/node is required; node starts
      // appear in commands but use node-N.log rather than command-N.log.
      evidence.logCapture = await captureOwnedLogs(
        runtime,
        artifacts,
        evidence.commands.map((entry) => entry.log),
        secrets,
      );
      const captureFailedAfterSuccess =
        success && evidence.logCapture.status !== "passed";
      if (captureFailedAfterSuccess) {
        success = false;
        evidence.status = "failed";
        evidence.failure = { code: "LOG_CAPTURE_FAILED" };
      }
      evidence.runtimeRetained = !(success && teardown);
      let output = JSON.stringify(evidence, null, 2);
      for (const secret of secrets)
        if (secret) output = output.replaceAll(secret, "[REDACTED_TEST_SECRET]");
      await writeFile(join(artifacts, "evidence.json"), output, { mode: 0o600 });
      if (success && teardown) {
        try {
          await removeOwnedRuntime(runtime, ownershipId);
        } catch (error) {
          evidence.status = "failed";
          evidence.runtimeRetained = true;
          evidence.failure = { code: "OWNERSHIP_CLEANUP_REFUSED" };
          await writeFile(
            join(artifacts, "evidence.json"),
            JSON.stringify(evidence, null, 2),
            { mode: 0o600 },
          );
          throw error;
        }
      }
      console.log(
        `Native owned run ${evidence.status}; evidence ${join(artifacts, "evidence.json")}${evidence.runtimeRetained ? `; restricted runtime retained ${runtime}` : ""}`,
      );
      if (captureFailedAfterSuccess) throw Error("Native required log capture failed");
    }
  }
}
