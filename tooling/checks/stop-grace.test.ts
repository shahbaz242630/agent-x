// AZ9 (Azure.md "To confirm": the termination grace against the API's 25 s
// stop): every app Azure runs, and the compose stack's API, is given longer to
// stop than the API's own stop deadline (apps/api/src/boot.ts), so a stop that
// is ending its requests and writing its counts is never cut short. Read from
// the sources, so a change to either side that breaks it goes red here.
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

const boot = readFileSync('apps/api/src/boot.ts', 'utf8');
const apps = readFileSync('deploy/azure/apps.bicep', 'utf8');
const compose = parse(readFileSync('deploy/compose/compose.yaml', 'utf8')) as {
  services: Record<string, { stop_grace_period?: string }>;
};

/** The API's stop deadline in seconds, as boot.ts writes it (`25_000` ms). */
const deadlineSeconds = (): number => {
  const written = /\bconst STOP_DEADLINE_MS = ([\d_]+);/.exec(boot)?.[1];
  if (written === undefined) throw new Error('apps/api/src/boot.ts no longer writes STOP_DEADLINE_MS as a number');
  return Number(written.replaceAll('_', '')) / 1000;
};

describe('AZ9: the API is given longer to stop than its own deadline, wherever it runs', () => {
  it("reads the API's deadline", () => {
    expect(deadlineSeconds()).toBe(25);
  });

  it("gives every Azure app a grace period past it, and each container takes its app's", () => {
    const given = [...apps.matchAll(/^\s*stopSeconds: (\d+)\s*$/gm)].map((match) => Number(match[1]));
    // The API, its jobs app, the login service and Zitadel.
    expect(given.length).toBeGreaterThanOrEqual(4);
    for (const seconds of given) expect(seconds).toBeGreaterThan(deadlineSeconds());
    expect(apps.match(/terminationGracePeriodSeconds: (.+)$/gm)).toEqual([
      'terminationGracePeriodSeconds: app.stopSeconds',
    ]);
  });

  it("gives the compose stack's API a grace period past it", () => {
    const grace = compose.services.api?.stop_grace_period ?? '';
    expect(grace).toMatch(/^\d+s$/);
    expect(Number.parseInt(grace, 10)).toBeGreaterThan(deadlineSeconds());
  });
});
