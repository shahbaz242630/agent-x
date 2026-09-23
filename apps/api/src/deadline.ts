// A step of the API's background work (the anchor check, the retention
// sweep), bounded by the app's own deadline and ending at once when the API
// stops. Postgres's own limits can be got round by someone who owns the
// database, and a connection can die without a word, so the app keeps its own.

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
