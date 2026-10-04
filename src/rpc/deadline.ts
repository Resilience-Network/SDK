import { createRpcFailure } from "./errors.js";
import type { RpcClock } from "./types.js";

export const systemClock: RpcClock = {
  now: () => performance.now(),
  setTimeout: (callback, delay) => globalThis.setTimeout(callback, delay),
  clearTimeout: (handle) => globalThis.clearTimeout(handle as number),
};

export class Deadline {
  readonly controller = new AbortController();
  attempts = 0;
  #code: "ABORTED" | "TIMEOUT" = "ABORTED";
  readonly #endsAt: number;
  readonly #timer: unknown;
  readonly #onAbort = () => this.#stop("ABORTED");

  constructor(
    readonly clock: RpcClock,
    timeoutMs: number,
    readonly caller: AbortSignal | undefined,
  ) {
    this.#endsAt = clock.now() + timeoutMs;
    this.#timer = clock.setTimeout(() => this.#stop("TIMEOUT"), timeoutMs);
    try {
      caller?.addEventListener("abort", this.#onAbort, { once: true });
      if (caller?.aborted) this.#onAbort();
    } catch (error) {
      // A caller hook can register and then throw; undo both owned resources.
      clock.clearTimeout(this.#timer);
      try {
        caller?.removeEventListener("abort", this.#onAbort);
      } catch {
        /* caller hook */
      }
      throw error;
    }
  }

  #stop(code: "ABORTED" | "TIMEOUT"): void {
    if (!this.controller.signal.aborted) {
      this.#code = code;
      // Never propagate a caller's possibly sensitive abort reason.
      this.controller.abort();
    }
  }

  check(): void {
    if (!this.controller.signal.aborted && this.clock.now() >= this.#endsAt)
      this.#stop("TIMEOUT");
    if (this.controller.signal.aborted)
      throw createRpcFailure(this.#code, this.attempts);
  }

  race<T>(pending: Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const signal = this.controller.signal;
      const abort = () => reject(createRpcFailure(this.#code, this.attempts));
      signal.addEventListener("abort", abort, { once: true });
      // Both handlers stay attached even when abort wins, consuming late failures.
      pending.then(
        (value) => {
          signal.removeEventListener("abort", abort);
          resolve(value);
        },
        (error: unknown) => {
          signal.removeEventListener("abort", abort);
          reject(error);
        },
      );
      if (signal.aborted) abort();
    });
  }

  async delay(delayMs: number): Promise<void> {
    this.check();
    let timer: unknown;
    try {
      await this.race(
        new Promise<void>((resolve) => {
          timer = this.clock.setTimeout(resolve, delayMs);
        }),
      );
      this.check();
    } finally {
      this.clock.clearTimeout(timer);
    }
  }

  dispose(): void {
    this.clock.clearTimeout(this.#timer);
    this.caller?.removeEventListener("abort", this.#onAbort);
  }
}
