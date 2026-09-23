// The API's background work (the anchor check, the retention sweep): each on a
// timer of its own, so one never holds up another, and each step bounded by
// the app's own deadline and ending at once when the API stops. Postgres's own
// limits can be got round by someone who owns the database, and a connection
// can die without a word, so the app keeps its own.

/** The run was stopped while a step was under way. */
export class Stopped extends Error {}

/** The step, or a rejection once the deadline passes or the run is stopped, whichever comes first. */
export async function withinDeadline<T>(
  checking: Promise<T>,
  deadlineMs: number,
  signal: AbortSignal | undefined,
): Promise<T> {
  const { promise: cut, reject: cutOff } = Promise.withResolvers<never>();
  const timer = setTimeout(() => {
    cutOff(new Error(`the check did not finish within ${String(deadlineMs)} ms`));
  }, deadlineMs);
  const stop = (): void => {
    cutOff(new Stopped('the check was stopped'));
  };
  signal?.addEventListener('abort', stop, { once: true });
  try {
    return await Promise.race([checking, cut]);
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', stop);
  }
}

/**
 * Runs the work now and then `intervalMs` after each run ends, so runs never
 * overlap. `stop` ends a run in flight at once and waits for it to end; a
 * statement it had begun is left to the database's own limit, which closing
 * the pool waits for.
 */
export function scheduleRuns(
  work: { run(signal?: AbortSignal): Promise<void> },
  intervalMs: number,
): { stop(): Promise<void> } {
  const stopping = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let running: Promise<void> = Promise.resolve();
  const tick = (): void => {
    running = work.run(stopping.signal).then(() => {
      if (stopping.signal.aborted) return;
      timer = setTimeout(tick, intervalMs);
      // The server keeps the process alive; background work alone shouldn't.
      timer.unref();
    });
  };
  tick();
  return Object.freeze({
    async stop(): Promise<void> {
      stopping.abort();
      clearTimeout(timer);
      await running;
    },
  });
}
