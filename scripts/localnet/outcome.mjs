/** Teardown is a delivery gate independent of successful integration activity. */
export function recordNativeTeardown(evidence, closed) {
  evidence.teardown = { allOwnedChildrenClosed: closed };
  if (!closed) {
    evidence.status = "failed";
    evidence.failure = { code: "TEARDOWN_FAILED" };
  }
}
