// How the smoke test asks staging (smoke.ts, auth-door.ts): each request
// again while what answers it wakes from zero, as staging's apps scale to
// none. Node builtins only.
import { setTimeout as sleep } from 'node:timers/promises';

/** A fetch that answers, or throws on a dropped line. */
type Fetch = (
  url: string,
  init: { method?: string; headers: Record<string, string>; body?: string; signal: AbortSignal },
) => Promise<Response>;

/** How the requests reach staging and wait, real by default. */
export interface Ways {
  readonly fetcher: Fetch;
  readonly now: () => Date;
  /** How long a request may keep meeting a waking app. */
  readonly wakeMs: number;
  /** The wait between tries. */
  readonly pause: () => Promise<unknown>;
}

export const REAL: Ways = {
  fetcher: fetch,
  now: () => new Date(),
  wakeMs: 180_000,
  pause: () => sleep(10_000),
};

/**
 * One request, asked again while what answers it wakes from zero (a 502, 503
 * or 504, or no answer) for at most `wakeMs`: the first other answer, or the
 * last status (or `no answer`) and how long it waited.
 */
export async function askAwake(
  url: string,
  init: { method?: string; headers: Record<string, string>; body?: string },
  { fetcher, now, wakeMs, pause }: Ways,
): Promise<{ readonly answer: Response } | { readonly waited: string }> {
  const until = now().getTime() + wakeMs;
  for (;;) {
    let last: string;
    try {
      const answer = await fetcher(url, { ...init, signal: AbortSignal.timeout(30_000) });
      if (![502, 503, 504].includes(answer.status)) return { answer };
      last = String(answer.status);
    } catch {
      last = 'no answer';
    }
    if (now().getTime() >= until) return { waited: `${last} after ${String(wakeMs / 1000)} s` };
    await pause();
  }
}
