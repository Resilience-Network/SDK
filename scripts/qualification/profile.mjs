// Exact exercised local profile; not a claim about Chain CI Rust 1.88.0.
export const profile = Object.freeze({
  name: "macos-arm64-node24-chrome-local-v1",
  node: "v24.21.0",
  npm: "11.12.1",
  python: "Python 3.14.3",
  platform: "darwin",
  arch: "arm64",
  go: "go version go1.26.8 darwin/arm64",
  rust: "rustc 1.98.1 (48a229cea 2026-09-01) (Homebrew)",
  browser: "154.0.8037.95",
  externalGates: [31, 34, 35, 38, 69],
});
export const stages = Object.freeze([
  { id: "install", args: ["ci"], pattern: /added \d+ packages/, timeout: 180000 },
  {
    id: "sdk",
    script: "check",
    pattern: /ℹ tests (\d+)/,
    minimum: 328,
    timeout: 180000,
  },
  {
    id: "api",
    script: "test:api-qualification",
    pattern: /API qualification PASS: (\d+) entry points/,
    minimum: 6,
    timeout: 180000,
  },
  {
    id: "rp",
    script: "test:webauthn-verifier",
    pattern: /(\d+) tests, zero skips\/todos/,
    minimum: 76,
    timeout: 90000,
  },
  {
    id: "browser",
    script: "test:browser",
    pattern: /\((\d+) checks\)/,
    minimum: 24,
    timeout: 180000,
  },
  {
    id: "rpc",
    script: "test:rpc-native",
    pattern: /fixtures match: (\d+) typed/,
    minimum: 41,
    timeout: 180000,
  },
  {
    id: "differential",
    script: "test:differential",
    pattern: /differential PASS: (\d+) cases/,
    minimum: 1925,
    timeout: 180000,
  },
  {
    id: "signatures",
    script: "test:signatures-native",
    pattern: /signature verification PASS: (\d+) cases/,
    minimum: 607,
    timeout: 180000,
  },
  {
    id: "localnet",
    script: "test:localnet",
    pattern: /Native positive log manifest/,
    nativeRuns: 1,
    timeout: 240000,
  },
  {
    id: "failures",
    script: "test:localnet-failures",
    pattern: /actual SIGINT\/SIGTERM plus injected missing-log/,
    nativeRuns: 8,
    negative: true,
    timeout: 600000,
  },
  {
    id: "lifecycle",
    script: "test:lifecycle-native",
    pattern: /Native owned run passed/,
    nativeRuns: 1,
    minimumChecks: 32,
    timeout: 900000,
  },
  {
    id: "session",
    script: "test:session-e2e",
    pattern: /lost acknowledgment qualification passed/,
    nativeRuns: 1,
    minimumChecks: 67,
    timeout: 1200000,
  },
  {
    id: "example",
    script: "example:session",
    pattern: /finalized ROOT revocation passed/,
    nativeRuns: 1,
    minimumChecks: 10,
    timeout: 600000,
  },
  {
    id: "installed",
    script: "example:session-installed",
    pattern: /Installed tarball native example PASS/,
    nativeRuns: 1,
    minimumChecks: 10,
    timeout: 900000,
  },
  {
    id: "combined",
    script: "example:passkey-session",
    pattern: /example PASS: (\d+) checks/,
    minimum: 17,
    nativeRuns: 1,
    minimumChecks: 11,
    timeout: 900000,
  },
]);
export function verifyOutput(stage, output) {
  const match = stage.pattern.exec(output);
  if (!match || (stage.minimum && Number(match[1]) < stage.minimum))
    throw Error("Required feature evidence missing: " + stage.id);
  if (
    stage.id === "sdk" &&
    (!/ℹ fail 0\b/.test(output) ||
      !/ℹ cancelled 0\b/.test(output) ||
      !/ℹ skipped 0\b/.test(output) ||
      !/ℹ todo 0\b/.test(output))
  )
    throw Error("SDK failed/cancelled/skipped/todo coverage");
  if (
    stage.id === "differential" &&
    !/receipt commitment PASS: 166 independent fixtures, 26294 cases/.test(output)
  )
    throw Error("Receipt differential evidence missing");
  return stage.minimum ? Number(match[1]) : null;
}

export const entryScripts = Object.freeze({
  api: "scripts/check_api_qualification.mjs",
  rp: "scripts/check_webauthn_verifier.mjs",
  browser: "scripts/check_browser.mjs",
  rpc: "scripts/check_rpc_contracts.mjs",
  differential: null,
  signatures: "scripts/check_signatures.mjs",
  localnet: "scripts/check_localnet.mjs",
  failures: "scripts/check_localnet_failures.mjs",
  lifecycle: "scripts/check_lifecycle.mjs",
  session: "scripts/check_session_end_to_end.mjs",
  example: "examples/session-localnet.mjs",
  installed: "scripts/check_installed_session_example.mjs",
  combined: "examples/passkey-session/run.mjs",
});

function passingChecks(checks, minimum, key = "name") {
  return (
    Array.isArray(checks) &&
    checks.length >= minimum &&
    Array.from(checks).every(
      (c) =>
        c !== null &&
        typeof c === "object" &&
        typeof c[key] === "string" &&
        c[key].length > 0 &&
        c.result === "pass",
    ) &&
    new Set(checks.map((c) => c[key])).size === checks.length
  );
}

export function verifyNativeChecks(checks, minimum) {
  if (
    !Number.isSafeInteger(minimum) ||
    minimum < 0 ||
    !Array.isArray(checks) ||
    checks.length < minimum ||
    !Array.from(checks).every(
      (c) =>
        c !== null &&
        typeof c === "object" &&
        typeof c.name === "string" &&
        c.name.length > 0,
    )
  )
    throw Error("Incomplete native checks");
}

export function verifyArtifact(name, evidence, revision, archiveSha256) {
  if (evidence === null || typeof evidence !== "object" || Array.isArray(evidence))
    throw Error("Invalid artifact shape");
  if ((evidence.sdkRevision ?? evidence.revision) !== revision)
    throw Error("Stale artifact revision");
  if (name === "api" ? evidence.dirty !== false : evidence.trackedClean !== true)
    throw Error("Dirty or missing artifact cleanliness");
  if (name === "api") {
    if (evidence.status !== "PASS") throw Error("API artifact failed");
  } else if (name === "rp") {
    if (
      evidence.failures !== 0 ||
      evidence.skipped !== 0 ||
      evidence.todo !== 0 ||
      !Number.isSafeInteger(evidence.tests) ||
      evidence.tests < 76 ||
      !passingChecks(evidence.normativeCases, 67, "id")
    )
      throw Error("Incomplete RP artifact");
  } else {
    if (evidence.result !== "pass") throw Error("Child artifact failed");
    if (
      name === "browser" &&
      (!Array.isArray(evidence.engines) ||
        evidence.engines.length !== 1 ||
        evidence.engines[0]?.version !== profile.browser ||
        !passingChecks(evidence.engines[0]?.checks, 24) ||
        evidence.failures !== 0 ||
        evidence.skipped !== 0 ||
        evidence.todo !== 0)
    )
      throw Error("Unqualified browser artifact");
    if (
      name === "combined" &&
      (evidence.browser?.version !== profile.browser ||
        !passingChecks(evidence.checks, 17))
    )
      throw Error("Incomplete combined artifact");
  }
  if (
    name !== "rp" &&
    (!/^[a-f0-9]{64}$/.test(evidence.archiveSha256 ?? "") ||
      evidence.archiveSha256 !== archiveSha256)
  )
    throw Error("Installed archive digest mismatch");
}
