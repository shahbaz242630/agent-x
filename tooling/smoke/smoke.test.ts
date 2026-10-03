// The post-release smoke test's reads, against a stand-in for staging's door.
import { readdirSync, readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

import { DAY_MS, KEY_WARNING_DAYS, READS, smoke, SMOKE_SCOPES, storedKey } from './smoke.ts';

const ORIGIN = 'https://app.example.test';
const KEY = 'axk_test-key-id_test-key-body';
const NOW = new Date('2026-10-03T09:00:00Z');
const LATER = new Date(NOW.getTime() + 90 * DAY_MS).toISOString();

const BODIES: Record<string, unknown> = {
  '/v1/agent': { agentId: 'a', scopes: [...SMOKE_SCOPES].reverse(), keyExpiresAt: LATER },
  '/v1/agent/funding-sources': { sources: [], next: null },
  '/v1/agent/suppliers': { suppliers: [{ id: 'kept-out-of-the-log' }], next: null },
};

/** A door answering each path from `answers` in turn (the last one repeats), or the healthy body. */
function door(answers: Record<string, (number | 'drop')[]> = {}, bodies = BODIES) {
  const calls: { url: string; authorization: string | undefined }[] = [];
  const fetcher = async (url: string, init: { headers: Record<string, string> }) => {
    calls.push({ url, authorization: init.headers.authorization });
    const path = url.slice(ORIGIN.length);
    const queue = answers[path] ?? [200];
    const next = (queue.length > 1 ? queue.shift() : queue[0]) ?? 200;
    if (next === 'drop') throw new TypeError('fetch failed');
    const body = path in bodies ? bodies[path] : {};
    return Promise.resolve(new Response(typeof body === 'string' ? body : JSON.stringify(body), { status: next }));
  };
  return { calls, fetcher };
}

const run = (fake: ReturnType<typeof door>, wakeMs = 30_000) => {
  let now = NOW.getTime();
  return smoke(ORIGIN, KEY, {
    fetcher: fake.fetcher,
    // Each pause moves the clock on, so the wake allowance runs out without waiting.
    now: () => new Date(now),
    wakeMs,
    pause: () => {
      now += 10_000;
      return Promise.resolve();
    },
  });
};

describe('Security-Handoff §13b: the post-release smoke test', () => {
  it('reads who the key is first, then both lists, with the key as a Bearer token', async () => {
    const fake = door();
    const result = await run(fake);
    expect(result).toEqual({
      lines: READS.map(({ path }) => `${path}: 200`),
      passed: true,
    });
    expect(fake.calls.map(({ url }) => url)).toEqual(READS.map(({ path }) => `${ORIGIN}${path}`));
    expect(fake.calls.every(({ authorization }) => authorization === `Bearer ${KEY}`)).toBe(true);
  });

  it('never logs a body, only paths and statuses', async () => {
    const { lines } = await run(door());
    expect(lines.join('\n')).not.toContain('kept-out-of-the-log');
  });

  it('waits for the API to wake from zero: a 502, 503 or 504, or no answer, is tried again', async () => {
    const fake = door({ '/v1/agent': ['drop', 503, 502, 504, 200] });
    expect((await run(fake, 60_000)).passed).toBe(true);
    expect(fake.calls.filter(({ url }) => url.endsWith('/v1/agent'))).toHaveLength(5);
  });

  it('fails a read still waking when the allowance runs out', async () => {
    const result = await run(door({ '/v1/agent/suppliers': [503] }), 30_000);
    expect(result.passed).toBe(false);
    expect(result.lines[2]).toBe('/v1/agent/suppliers: 503 after 30 s');
  });

  it('takes any other answer as final, without trying again', async () => {
    const fake = door({ '/v1/agent': [401] });
    const result = await run(fake);
    expect(result.passed).toBe(false);
    expect(result.lines[0]).toBe('/v1/agent: 401');
    expect(fake.calls.filter(({ url }) => url.endsWith('/v1/agent'))).toHaveLength(1);
  });

  it('refuses a key with any scope beyond the two reads, or short of them', async () => {
    for (const scopes of [[...SMOKE_SCOPES, 'requests:write'], ['sources:read'], 'sources:read']) {
      const result = await run(door({}, { ...BODIES, '/v1/agent': { scopes, keyExpiresAt: LATER } }));
      expect(result.passed, JSON.stringify(scopes)).toBe(false);
      expect(result.lines[0]).toMatch(/^\/v1\/agent: 200, but the key's scopes must be exactly/);
    }
  });

  it(`turns red ${String(KEY_WARNING_DAYS)} days before the key ends, so it is rotated in time`, async () => {
    const at = (days: number) => new Date(NOW.getTime() + days * DAY_MS).toISOString();
    const expiring = (keyExpiresAt: string) =>
      run(door({}, { ...BODIES, '/v1/agent': { scopes: SMOKE_SCOPES, keyExpiresAt } }));
    expect((await expiring(at(KEY_WARNING_DAYS - 0.01))).lines[0]).toMatch(/the key ends within 14 days: rotate it/);
    expect((await expiring(at(KEY_WARNING_DAYS + 1))).passed).toBe(true);
  });

  it('takes a 200 whose body is not a JSON object as final and wrong, never as the API asleep', async () => {
    for (const [body, said] of [
      ['<html>a page</html>', 'the body is not JSON'],
      [null, 'the body is not an object'],
    ] as const) {
      const fake = door({}, { ...BODIES, '/v1/agent': body });
      const result = await run(fake);
      expect(result.lines[0]).toBe(`/v1/agent: 200, but ${said}`);
      expect(fake.calls.filter(({ url }) => url.endsWith('/v1/agent'))).toHaveLength(1);
    }
  });

  it('says each line as soon as its read is done', async () => {
    const said: string[] = [];
    const fake = door();
    await smoke(ORIGIN, KEY, { fetcher: fake.fetcher, now: () => NOW }, (line) => {
      said.push(`${line} after ${String(fake.calls.length)} calls`);
    });
    expect(said).toEqual(READS.map(({ path }, index) => `${path}: 200 after ${String(index + 1)} calls`));
  });

  it("takes a stored key of an agent key's shape, around any whitespace a paste added, and says what is wrong with any other without showing it", () => {
    const real = `axk_${'0a'.repeat(16)}_${'A'.repeat(43)}`;
    expect(storedKey(real)).toEqual({ key: real });
    expect(storedKey(`${real}\r\n`)).toEqual({ key: real });
    expect(storedKey(undefined)).toEqual({ problem: 'The repository secret STAGING_SMOKE_AGENT_KEY is not set.' });
    expect(storedKey('  ')).toEqual({ problem: 'The repository secret STAGING_SMOKE_AGENT_KEY is not set.' });
    const pasted = 'gh secret set STAGING_SMOKE_AGENT_KEY --repo owner/name';
    expect(storedKey(pasted)).toEqual({
      problem:
        'The repository secret STAGING_SMOKE_AGENT_KEY is not an agent key: 55 characters (a key has 80), not starting with axk_.',
    });
    const longer = JSON.stringify(storedKey(`${real}x`));
    expect(longer).toMatch(/81 characters \(a key has 80\), starting with axk_\./);
    expect(longer).not.toContain(real);
  });

  it('fails a list answer without its list', async () => {
    const result = await run(door({}, { ...BODIES, '/v1/agent/funding-sources': { next: null } }));
    expect(result.lines[1]).toBe('/v1/agent/funding-sources: 200, but no sources list');
  });
});

describe('the smoke workflow', () => {
  const FILE = '.github/workflows/smoke.yml';
  const text = readFileSync(FILE, 'utf8');
  const workflow = parse(text) as {
    on: Record<string, unknown>;
    jobs: Record<
      string,
      { if?: string; environment?: unknown; permissions?: unknown; env?: unknown; steps?: { run?: string }[] }
    >;
  };
  const job = workflow.jobs.smoke;

  it('starts only after a staging deployment of main succeeds, or by hand on main', () => {
    expect(Object.keys(workflow.on).sort()).toEqual(['deployment_status', 'workflow_dispatch']);
    expect(job?.if?.replace(/\s+/g, ' ').trim()).toBe(
      "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' || " +
        "github.event.deployment_status.state == 'success' && github.event.deployment.environment == 'staging' && " +
        "github.event.deployment.ref == 'main'",
    );
  });

  it('may read the code alone, names no environment, and runs our smoke tool', () => {
    expect(job?.permissions).toEqual({ contents: 'read' });
    expect(job?.environment).toBeUndefined();
    expect(job?.steps?.filter((step) => step.run !== undefined).at(-1)?.run).toBe('node tooling/smoke/smoke.ts');
  });

  it('is the only workflow that holds the smoke key', () => {
    const holding = readdirSync('.github/workflows').filter((file) =>
      readFileSync(`.github/workflows/${file}`, 'utf8').includes('STAGING_SMOKE_AGENT_KEY'),
    );
    expect(holding).toEqual(['smoke.yml']);
    // Only the step that reads holds it: the actions before it never see it.
    const holders = (job?.steps ?? []).filter((step) => JSON.stringify(step).includes('STAGING_SMOKE_AGENT_KEY'));
    expect(holders.map((step) => step.run)).toEqual(['node tooling/smoke/smoke.ts']);
    expect(JSON.stringify(job?.env ?? {})).not.toContain('STAGING_SMOKE_AGENT_KEY');
  });
});
