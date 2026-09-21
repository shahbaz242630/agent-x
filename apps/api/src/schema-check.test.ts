// What the live schema check logs, and what it decides. The rules themselves
// are proven against a real database in schema-guard.db.test.ts; these are
// about the two answers the API needs — may it start, and what does it say.
import { LogCapture } from '@agentx/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { createLogger } from '@agentx/platform/observability';

const guard = vi.hoisted(() => ({
  result: (): Promise<string[]> => Promise.resolve([]),
}));

vi.mock('@agentx/platform/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@agentx/platform/db')>();
  return { ...actual, liveSchemaProblems: () => guard.result() };
});

const { checkSchemaOnSchedule, OWNER_ROLE, schemaSoundAtStart } = await import('./schema-check.ts');

function logger(): { capture: LogCapture; logger: ReturnType<typeof createLogger> } {
  const capture = new LogCapture();
  return {
    capture,
    logger: createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: capture,
    }),
  };
}

const options = (log: ReturnType<typeof logger>) => ({
  database: {} as never,
  appRole: 'agentx_app',
  logger: log.logger,
});

beforeEach(() => {
  guard.result = (): Promise<string[]> => Promise.resolve([]);
});

describe('at start-up', () => {
  it('lets the API go on when the live schema matches, and says so', async () => {
    const log = logger();
    expect(await schemaSoundAtStart(options(log))).toBe(true);
    expect(log.capture.lines()).toMatchObject([{ level: 'info', event: 'db.schema_checked', problems: 0 }]);
  });

  it('refuses the start on drift, and raises the integrity alarm the SEV-1 rule already watches', async () => {
    guard.result = (): Promise<string[]> => Promise.resolve(['audit.events carries a rewrite rule']);
    const log = logger();
    expect(await schemaSoundAtStart(options(log))).toBe(false);
    expect(log.capture.lines()).toMatchObject([
      {
        level: 'error',
        event: 'audit.integrity_failed',
        check: 'schema',
        when: 'start',
        problems: ['audit.events carries a rewrite rule'],
      },
    ]);
  });

  it('refuses the start when the catalogue cannot be read at all', async () => {
    // Losing the right to read the catalogue is itself a change worth knowing
    // about, so it is the alarm rather than a warning.
    guard.result = (): Promise<string[]> => Promise.reject(new Error('permission denied for table pg_class'));
    const log = logger();
    expect(await schemaSoundAtStart(options(log))).toBe(false);
    const events = log.capture.lines().map((line) => line.event);
    expect(events).toEqual(['audit.integrity_failed', 'api.schema_unreadable']);
    expect(log.capture.lines()[0]).toMatchObject({ check: 'schema', reason: 'unreadable' });
  });
});

describe('on a scheduled run', () => {
  it('says nothing when the live schema matches, so a quiet run stays quiet', async () => {
    const log = logger();
    await checkSchemaOnSchedule(options(log));
    expect(log.capture.lines()).toEqual([]);
  });

  it('raises the alarm on drift and returns, leaving the API serving', async () => {
    guard.result = (): Promise<string[]> => Promise.resolve(['PUBLIC may SELECT on audit.events']);
    const log = logger();
    await expect(checkSchemaOnSchedule(options(log))).resolves.toBeUndefined();
    expect(log.capture.lines()).toMatchObject([
      { level: 'error', event: 'audit.integrity_failed', check: 'schema', when: 'running' },
    ]);
  });

  it('never throws, whatever the database does, so the schedule cannot be stopped by one bad run', async () => {
    guard.result = (): Promise<string[]> => Promise.reject(new Error('connection reset'));
    const log = logger();
    await expect(checkSchemaOnSchedule(options(log))).resolves.toBeUndefined();
    expect(log.capture.lines().map((line) => line.event)).toEqual(['audit.integrity_failed', 'api.schema_unreadable']);
  });
});

describe('the deadline', () => {
  it('ends a read that never answers, rather than leaving the run pending for ever', async () => {
    // Without this, a database that accepts the read and stalls would hold the
    // scheduled run open: the schedule would never re-arm, the chain checks
    // after it would never run, and no alarm would ever be raised. Found by
    // the A3e-1b review.
    guard.result = (): Promise<string[]> => new Promise(() => undefined);
    const log = logger();
    await expect(checkSchemaOnSchedule({ ...options(log), deadlineMs: 20 })).resolves.toBeUndefined();
    expect(log.capture.lines().map((line) => line.event)).toEqual(['audit.integrity_failed', 'api.schema_unreadable']);
    expect(log.capture.lines()[0]).toMatchObject({ check: 'schema', reason: 'unreadable' });
  });

  it('refuses the start when the read does not finish in time', async () => {
    guard.result = (): Promise<string[]> => new Promise(() => undefined);
    const log = logger();
    expect(await schemaSoundAtStart({ ...options(log), deadlineMs: 20 })).toBe(false);
  });

  it('ends at once when the API is stopping, without waiting for the deadline', async () => {
    guard.result = (): Promise<string[]> => new Promise(() => undefined);
    const log = logger();
    const stopping = new AbortController();
    stopping.abort();
    const started = Date.now();
    await checkSchemaOnSchedule({ ...options(log), deadlineMs: 60_000, signal: stopping.signal });
    expect(Date.now() - started).toBeLessThan(5_000);
    // The stop is the API's own doing, so it raises no alarm: a routine shutdown must not page anyone.
    expect(log.capture.lines()).toEqual([]);
  });

  it('raises no alarm when the stop comes during a read, whatever the read then does', async () => {
    const stopping = new AbortController();
    // As the pool closes under a stopping API: the read fails once the stop has begun.
    guard.result = (): Promise<string[]> => {
      stopping.abort();
      return Promise.reject(new Error('Connection terminated'));
    };
    const log = logger();
    await checkSchemaOnSchedule({ ...options(log), signal: stopping.signal });
    expect(log.capture.lines()).toEqual([]);
  });

  it('declines a start that is stopped mid-check, with no alarm', async () => {
    guard.result = (): Promise<string[]> => new Promise(() => undefined);
    const log = logger();
    const stopping = new AbortController();
    stopping.abort();
    expect(await schemaSoundAtStart({ ...options(log), signal: stopping.signal })).toBe(false);
    expect(log.capture.lines()).toEqual([]);
  });

  it('still raises the alarm for a read that fails with no stop', async () => {
    guard.result = (): Promise<string[]> => Promise.reject(new Error('permission denied for table pg_class'));
    const log = logger();
    await checkSchemaOnSchedule({ ...options(log), signal: new AbortController().signal });
    expect(log.capture.lines().map((line) => line.event)).toEqual(['audit.integrity_failed', 'api.schema_unreadable']);
  });

  it('lets a read that answers in time through untouched', async () => {
    const log = logger();
    await checkSchemaOnSchedule({ ...options(log), deadlineMs: 60_000 });
    expect(log.capture.lines()).toEqual([]);
  });
});

describe('the owner role it compares against', () => {
  it('is the one db/bootstrap/roles.sql creates', () => {
    // Proven against the SQL itself in tooling/checks/database-roles.test.ts.
    expect(OWNER_ROLE).toBe('agentx_owner');
  });
});
