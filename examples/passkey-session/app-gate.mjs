// Disposable application policy only. Not a production session, signer unlock,
// custody provider, or native authorization mechanism.
export class ExampleApplicationGate {
  #permit;
  #clock;
  constructor(clock = () => Math.floor(performance.now())) {
    this.#clock = clock;
  }
  accept(result, expectedAccount, lifetimeMs = 900000) {
    this.clear();
    const now = this.#clock();
    if (
      result?.status !== "authenticated" ||
      result.applicationAuthenticated !== true ||
      result.accountId !== expectedAccount ||
      !Number.isSafeInteger(now) ||
      !Number.isSafeInteger(lifetimeMs) ||
      lifetimeMs < 1 ||
      lifetimeMs > 900000 ||
      !Number.isSafeInteger(now + lifetimeMs)
    )
      throw Error("Example app authentication rejected");
    this.#permit = {
      account: expectedAccount,
      issuedAt: now,
      expiresAt: now + lifetimeMs,
    };
  }
  clear() {
    this.#permit = undefined;
  }
  allowed(expectedAccount, signal) {
    const now = this.#clock();
    return (
      !signal?.aborted &&
      !!this.#permit &&
      this.#permit.account === expectedAccount &&
      Number.isSafeInteger(now) &&
      now >= this.#permit.issuedAt &&
      now < this.#permit.expiresAt
    );
  }
}
