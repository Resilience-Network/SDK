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
    minimum: 304,
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
    nativeRuns: 7,
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
      !/ℹ skipped 0\b/.test(output) ||
      !/ℹ todo 0\b/.test(output))
  )
    throw Error("SDK failed/skipped/todo coverage");
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
