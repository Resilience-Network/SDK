// Owned disposable installed-package browser consumer; no existing user profile.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, writeFile, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { build } from "esbuild";
import { chromium, firefox, webkit } from "playwright";
const root = fileURLToPath(new URL("../", import.meta.url));
export async function createBrowserConsumer() {
  const directory = await mkdtemp(join(tmpdir(), "rsc-sdk-browser-"));
  await writeFile(
    join(directory, ".owned-sdk-browser"),
    "disposable-sdk-consumer-v1\n",
    { flag: "wx", mode: 0o600 },
  );
  let server,
    succeeded = false;
  try {
    const run = (args, options = {}) =>
      execFileSync("npm", args, {
        cwd: root,
        encoding: "utf8",
        maxBuffer: 2 * 1024 * 1024,
        timeout: 90000,
        ...options,
      });
    const [archive] = JSON.parse(run(["pack", "--json", "--pack-dest", directory])),
      archivePath = join(directory, archive.filename),
      consumer = join(directory, "consumer");
    await mkdir(consumer);
    await writeFile(
      join(consumer, "package.json"),
      '{"private":true,"type":"module"}\n',
    );
    run(
      [
        "install",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--omit=dev",
        "--package-lock=false",
        archivePath,
      ],
      { cwd: consumer },
    );
    await writeFile(
      join(consumer, "consumer.mjs"),
      await readFile(join(root, "tests/browser/consumer.mjs")),
    );
    const entryPoints = { consumer: join(consumer, "consumer.mjs") };
    for (const entry of ["root", "core", "session", "rpc", "display", "webauthn"]) {
      const path = join(consumer, entry + ".mjs");
      await writeFile(
        path,
        `export * from "@resilience-network/sdk${entry === "root" ? "" : "/" + entry}";\n`,
      );
      entryPoints[entry] = path;
    }
    const result = await build({
      entryPoints,
      bundle: true,
      format: "esm",
      platform: "browser",
      target: ["es2022"],
      splitting: true,
      write: false,
      outdir: join(consumer, "bundles"),
      metafile: true,
      treeShaking: false,
    });
    assert(
      !Object.keys(result.metafile.inputs).some((path) =>
        path.includes("simplewebauthn/server"),
      ),
      "Server verifier cannot enter browser bundle",
    );
    for (const output of Object.values(result.metafile.outputs))
      assert(
        output.imports.every((value) => !value.external),
        "Unresolved/Node-only browser import",
      );
    const assets = new Map(
      result.outputFiles.map((file) => [
        "/bundles/" + file.path.split("/").at(-1),
        file.contents,
      ]),
    );
    const requests = [];
    server = createServer((request, response) => {
      const path = new URL(request.url, "http://localhost").pathname;
      if (requests.length < 512) requests.push(path);
      response.setHeader("Cache-Control", "no-store");
      if (path === "/") {
        response.setHeader("Content-Type", "text/html; charset=utf-8");
        response.end(
          "<!doctype html><title>Disposable SDK browser qualification</title>",
        );
        return;
      }
      const asset = assets.get(path);
      if (asset) {
        response.setHeader("Content-Type", "text/javascript; charset=utf-8");
        response.end(asset);
        return;
      }
      response.statusCode = 404;
      response.end();
    });
    await new Promise((accept, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", accept);
    });
    const origin = "http://localhost:" + server.address().port,
      sha256 = createHash("sha256")
        .update(await readFile(archivePath))
        .digest("hex");
    const fixture = {
      directory,
      origin,
      archiveSha256: sha256,
      bundleBytes: result.outputFiles.reduce(
        (sum, file) => sum + file.contents.length,
        0,
      ),
      requests,
      async close(success = true) {
        succeeded = success;
        server.closeAllConnections();
        await new Promise((accept) => server.close(accept));
        if (
          succeeded &&
          (await readFile(join(directory, ".owned-sdk-browser"), "utf8")) ===
            "disposable-sdk-consumer-v1\n"
        )
          await rm(directory, { recursive: true });
      },
    };
    return fixture;
  } catch (error) {
    if (server) {
      server.closeAllConnections();
      server.close();
    }
    throw new Error(
      `Owned browser consumer setup failed; retained public fixture ${directory}`,
      { cause: error },
    );
  }
}
export async function withOwnedBrowser(
  fixture,
  engine,
  work,
  { chromiumChannel = process.env.RSC_BROWSER_CHROMIUM_CHANNEL } = {},
) {
  assert(["chromium", "firefox", "webkit"].includes(engine));
  assert(
    chromiumChannel === undefined || ["chrome", "chromium"].includes(chromiumChannel),
  );
  const browser = await { chromium, firefox, webkit }[engine].launch({
    headless: true,
    timeout: 30000,
    ...(engine === "chromium" && chromiumChannel ? { channel: chromiumChannel } : {}),
  });
  let context;
  try {
    context = await browser.newContext();
    const page = await context.newPage();
    page.setDefaultTimeout(15000);
    await page.goto(fixture.origin, { waitUntil: "load", timeout: 15000 });
    return await work({
      browser,
      context,
      page,
      version: browser.version(),
      distribution:
        engine === "chromium"
          ? (chromiumChannel ?? "playwright-chromium")
          : "playwright-" + engine,
    });
  } finally {
    try {
      await context?.close();
    } finally {
      await browser.close();
    }
  }
}
export async function importConsumer(page) {
  return page.evaluate(async () => {
    const calls = { fetch: 0, create: 0, get: 0 },
      originalFetch = globalThis.fetch,
      credentials = navigator.credentials,
      create = credentials?.create,
      get = credentials?.get;
    globalThis.fetch = () => {
      calls.fetch++;
      throw Error("Unsolicited import fetch");
    };
    if (credentials) {
      credentials.create = () => {
        calls.create++;
        throw Error("Unsolicited create");
      };
      credentials.get = () => {
        calls.get++;
        throw Error("Unsolicited get");
      };
    }
    try {
      const names = ["root", "core", "session", "rpc", "display", "webauthn"],
        entries = {};
      for (const name of names)
        entries[name] = Object.keys(await import("/bundles/" + name + ".js")).length;
      globalThis.sdkConsumer = await import("/bundles/consumer.js");
      return { calls, entries, secureContext: isSecureContext };
    } finally {
      globalThis.fetch = originalFetch;
      if (credentials) {
        credentials.create = create;
        credentials.get = get;
      }
    }
  });
}
