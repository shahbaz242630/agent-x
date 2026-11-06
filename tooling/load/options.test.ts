// The k6 options both load scripts build (options.k6.js), loaded as k6 loads
// them: the file imports nothing of k6's, so Vitest can run it as it is.
import { describe, expect, it } from 'vitest';

interface OptionsModule {
  constantRate: (seconds: number, rate: number, run: string, vus: number) => Record<string, unknown>;
  namedOnly: (kinds: readonly string[], metric: string, rule: string) => Record<string, string[]>;
}

/** A plain JavaScript file has no types: named by URL so TypeScript takes it as the interface above. */
const OPTIONS_FILE = new URL('./options.k6.js', import.meta.url).href;
const options = (await import(OPTIONS_FILE)) as OptionsModule;

describe('the k6 options both scripts build', () => {
  it('sends a fixed rate for the seconds given, with five times the ready VUs at most', () => {
    expect(options.constantRate(120, 25, 'steady', 60)).toEqual({
      executor: 'constant-arrival-rate',
      rate: 25,
      timeUnit: '1s',
      duration: '120s',
      preAllocatedVUs: 60,
      maxVUs: 300,
      exec: 'steady',
    });
  });

  it('names a metric for each kind with a rule that never fails, so k6 times and counts each apart', () => {
    expect(options.namedOnly(['calm', 'busy'], 'http_reqs', 'count>=0')).toEqual({
      'http_reqs{kind:calm}': ['count>=0'],
      'http_reqs{kind:busy}': ['count>=0'],
    });
  });
});
