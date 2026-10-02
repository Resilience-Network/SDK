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
  const smoke = `import * as sdk from ${JSON.stringify(metadata.name)}; console.log("Package import OK; exports:", Object.keys(sdk).length);`;
  execFileSync(process.execPath, ["--input-type=module", "-e", smoke], {
    cwd: temporary,
    stdio: "inherit",
  });
  await writeFile(
    join(temporary, "consumer.ts"),
    `import * as sdk from ${JSON.stringify(metadata.name)}; void sdk;\n`,
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
    "Package archive and downstream TypeScript resolution OK (scaffold only).",
  );
} finally {
  await rm(temporary, { recursive: true, force: true });
}
