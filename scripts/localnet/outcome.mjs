/** Teardown is a delivery gate independent of successful integration activity. */
export function recordNativeTeardown(evidence, closed, procedureFailed = false) {
  evidence.teardown = { allOwnedChildrenClosed: closed };
  if (!closed || procedureFailed) {
    evidence.status = "failed";
    evidence.failure = { code: "TEARDOWN_FAILED" };
  }
}
