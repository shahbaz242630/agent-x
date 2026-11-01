// What the live schema check logs, and what it decides. The rules themselves
// are proven against a real database in schema-guard.db.test.ts; these are
// about the two answers a process needs (the API, the operator's command): may
// it go on, and what does it say.
import { LogCapture, testLogger } from '@agentx/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const guard = vi.hoisted(() => ({
  result: (): Promise<string[]> => Promise.resolve([]),
  /** The release-shaped drift it finds, beside `result`'s. */
  released: [] as string[],
  /** What the check asked the guard to hold, each time. */
  asked: [] as unknown[],
}));

vi.mock('@agentx/platform/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@agentx/platform/db')>();
  return {
    ...actual,
    // Handed on as a thenable, so a read's failure lands as soon as `result`'s does.
    liveSchemaDrift: (_database: unknown, asked: unknown) => {
      guard.asked.push(asked);
      const atOnce = guard.result();
      return {
        then: (given: (drift: unknown) => unknown, refused: (error: unknown) => unknown) =>
          atOnce.then((problems) => given({ atOnce: problems, releaseShaped: guard.released }), refused),
      };
    },
  };
});

const schemaCheck = await import('./schema-check.ts');
const { createFullServerWatch, createReleaseDriftWatch, OWNER_ROLE, schemaSoundAtStart } = schemaCheck;
/** A watch that has never met a full server, for the runs that don't. */
const checkSchemaOnSchedule = (asked: Parameters<typeof schemaCheck.checkSchemaOnSchedule>[0]) =>
  schemaCheck.checkSchemaOnSchedule(
    asked,
    createFullServerWatch(1_000, () => 0),
    createReleaseDriftWatch(),
  );
const { AUTHORITY_TABLES } = await import('./authority-tables.ts');

function logger(): { capture: LogCapture; logger: ReturnType<typeof testLogger> } {
  const capture = new LogCapture();
  return {
    capture,
    logger: testLogger(capture),
  };
}

const options = (log: ReturnType<typeof logger>) => ({
  database: {} as never,
  appRole: 'agentx_app',
  logger: log.logger,
});

// A spend request's columns fixed when it is made (0039): all but its status.
const SPEND_REQUESTS_FIXED = [
  'agent_id',
  'agent_key_id',
  'mandate_id',
  'organization_policy_version_id',
  'mandate_policy_version_id',
  'supplier_id',
  'supplier_version_id',
  'funding_source_id',
  'amount_minor',
  'currency',
  'purpose',
  'order_reference',
  'idempotency_key',
  'input_hash',
  'input_hash_key_version',
  'decision',
  'reason_codes',
];

beforeEach(() => {
  guard.result = (): Promise<string[]> => Promise.resolve([]);
  guard.released = [];
});

describe('at start-up', () => {
  it('asks the guard to hold every authority table, and a status guard on each with a status (the S68 audit)', async () => {
    await schemaSoundAtStart(options(logger()));

    const statuses = AUTHORITY_TABLES.filter((table) => table.rules !== undefined).map(({ table }) => table);
    expect(statuses).toEqual(
      expect.arrayContaining(['identity.memberships', 'agents.agent_keys', 'funding_sources.sources']),
    );
    expect(guard.asked.at(-1)).toEqual({
      appRole: 'agentx_app',
      ownerRole: OWNER_ROLE,
      authorityTables: AUTHORITY_TABLES,
      statusGuardedTables: statuses,
      // And the made-once guard on each whose rows are made once (E1-1's review).
      madeOnceTables: [
        'mandates.versions',
        'mandates.policy_versions',
        'suppliers.supplier_versions',
        // An agent's month zone (0054, PL-40).
        'limit_reservations.agent_zones',
        // A handed-off request's instruction (0058, Phase 4 B3).
        'instructions.instructions',
      ],
      // And the fixed-at-creation guard on each with columns fixed when made (Phase 2 B1).
      // Phase 2 D1: a spend request's all but its status.
      fixedAtCreation: {
        'mandates.mandates': ['agent_id', 'time_zone', 'split_window_hours'],
        'spend_requests.requests': SPEND_REQUESTS_FIXED,
        // Phase 4 B3: a transaction's instruction and when it was opened.
        'transactions.transactions': ['instruction_id', 'created_at'],
        // Gate H10 (0066): a proposal's payment, reference, proposer and when it was made.
        'transactions.failure_proposals': ['transaction_id', 'evidence_ref', 'proposed_by', 'created_at'],
      },
    });
  });

  it('lets the process go on when the live schema matches, and says so', async () => {
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
    expect(events).toEqual(['audit.integrity_failed', 'db.schema_unreadable']);
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
    expect(log.capture.lines().map((line) => line.event)).toEqual(['audit.integrity_failed', 'db.schema_unreadable']);
  });
});

describe('a server with every connection in use (decision 3)', () => {
  const full = () => Object.assign(new Error('sorry, too many clients already'), { code: '53300' });
  const WAIT = { limitMs: 1_000, retryMs: 1 };
  const events = (log: ReturnType<typeof logger>) => log.capture.lines().map((line) => [line.level, line.event]);
  const WARNED = ['warn', 'db.schema_check_full_server'];
  const onSchedule = (log: ReturnType<typeof logger>, watch: ReturnType<typeof createFullServerWatch>) =>
    schemaCheck.checkSchemaOnSchedule(options(log), watch, createReleaseDriftWatch());
  const ALARM = [
    ['error', 'audit.integrity_failed'],
    ['error', 'db.schema_unreadable'],
  ];

  it('at start, warns and asks again until the server answers: no alarm', async () => {
    let asks = 0;
    guard.result = (): Promise<string[]> => {
      asks += 1;
      return asks < 3 ? Promise.reject(full()) : Promise.resolve([]);
    };
    const log = logger();
    expect(await schemaSoundAtStart(options(log), WAIT)).toBe(true);
    expect(events(log)).toEqual([WARNED, WARNED, ['info', 'db.schema_checked']]);
  });

  it('at start, a server still full past the limit is the alarm, and the start is refused', async () => {
    guard.result = (): Promise<string[]> => Promise.reject(full());
    const log = logger();
    expect(await schemaSoundAtStart(options(log), { limitMs: 0, retryMs: 1 })).toBe(false);
    expect(events(log)).toEqual(ALARM);
    expect(log.capture.lines()[0]).toMatchObject({ check: 'schema', when: 'start', reason: 'unreadable' });
  });

  it('at start, drift found after the wait is the alarm', async () => {
    let asks = 0;
    guard.result = (): Promise<string[]> => {
      asks += 1;
      return asks < 2 ? Promise.reject(full()) : Promise.resolve(['audit.events carries a rewrite rule']);
    };
    const log = logger();
    expect(await schemaSoundAtStart(options(log), WAIT)).toBe(false);
    expect(events(log)).toEqual([WARNED, ['error', 'audit.integrity_failed']]);
  });

  it('at start, a stop during the wait ends it at once, with no alarm', async () => {
    const stopping = new AbortController();
    guard.result = (): Promise<string[]> => {
      setTimeout(() => {
        stopping.abort();
      }, 10);
      return Promise.reject(full());
    };
    const log = logger();
    const started = performance.now();
    const sound = await schemaSoundAtStart(
      { ...options(log), signal: stopping.signal },
      { limitMs: 60_000, retryMs: 60_000 },
    );
    expect(sound).toBe(false);
    expect(performance.now() - started).toBeLessThan(5_000);
    expect(events(log)).toEqual([WARNED]);
  });

  it('at start, a stop just before the wait ends it at once too', async () => {
    const stopping = new AbortController();
    const refusal = {
      then: (_resolve: unknown, reject: (error: Error) => void) => {
        reject(full());
        stopping.abort();
      },
    } as unknown as Promise<string[]>;
    guard.result = (): Promise<string[]> => refusal;
    const log = logger();
    const started = performance.now();
    const sound = await schemaSoundAtStart(
      { ...options(log), signal: stopping.signal },
      { limitMs: 60_000, retryMs: 60_000 },
    );
    expect(sound).toBe(false);
    expect(performance.now() - started).toBeLessThan(5_000);
  });

  it('any other refusal at start is the alarm at once, never a wait', async () => {
    let asks = 0;
    guard.result = (): Promise<string[]> => {
      asks += 1;
      return Promise.reject(Object.assign(new Error('permission denied'), { code: '42501' }));
    };
    const log = logger();
    expect(await schemaSoundAtStart(options(log), WAIT)).toBe(false);
    expect(asks).toBe(1);
    expect(events(log)).toEqual(ALARM);
  });

  it('on the schedule, warns within the limit, then is the alarm, and repeats the alarm while it lasts', async () => {
    guard.result = (): Promise<string[]> => Promise.reject(full());
    let time = 0;
    const watch = createFullServerWatch(100, () => time);
    const log = logger();
    await onSchedule(log, watch);
    time = 99;
    await onSchedule(log, watch);
    expect(events(log)).toEqual([WARNED, WARNED]);
    time = 100;
    await onSchedule(log, watch);
    expect(events(log)).toEqual([WARNED, WARNED, ...ALARM]);
    expect(log.capture.lines()[2]).toMatchObject({ check: 'schema', when: 'running', reason: 'unreadable' });
    time = 500;
    await onSchedule(log, watch);
    expect(events(log)).toEqual([WARNED, WARNED, ...ALARM, ...ALARM]);
  });

  it.each([
    ['a clean check', () => Promise.resolve([])],
    ['another failure', () => Promise.reject(new Error('connection reset'))],
  ])('on the schedule, %s ends the stretch: the limit counts afresh', async (_, between) => {
    let time = 0;
    const watch = createFullServerWatch(100, () => time);
    const log = logger();
    guard.result = (): Promise<string[]> => Promise.reject(full());
    await onSchedule(log, watch);
    time = 90;
    guard.result = between;
    await onSchedule(log, watch);
    time = 150;
    guard.result = (): Promise<string[]> => Promise.reject(full());
    const seen = log.capture.lines().length;
    await onSchedule(log, watch);
    expect(
      log.capture
        .lines()
        .slice(seen)
        .map(({ event }) => event),
    ).toEqual(['db.schema_check_full_server']);
  });

  it('on the schedule, a stop raises nothing and leaves the stretch running', async () => {
    let time = 0;
    const watch = createFullServerWatch(100, () => time);
    const log = logger();
    guard.result = (): Promise<string[]> => Promise.reject(full());
    await onSchedule(log, watch);
    const stopping = new AbortController();
    stopping.abort();
    time = 100;
    await schemaCheck.checkSchemaOnSchedule(
      { ...options(log), signal: stopping.signal },
      watch,
      createReleaseDriftWatch(),
    );
    expect(events(log)).toEqual([WARNED]);
    await onSchedule(log, watch);
    expect(events(log)).toEqual([WARNED, ...ALARM]);
  });
});

describe('drift a release can also make, on the schedule', () => {
  const CHECK_GONE = 'a.b\'s CHECK constraint "c" is not there';
  const FUNCTION_UNKNOWN = 'a.f is a function our schemas should not hold';
  const OTHER = 'PUBLIC may SELECT on audit.events';
  const WARNED = 'db.schema_release_drift_seen';
  const ALARM = 'audit.integrity_failed';

  /** One process's runs, with the watch it keeps between them. */
  const runs = () => {
    const log = logger();
    const fullServer = createFullServerWatch(1_000, () => 0);
    const releaseDrift = createReleaseDriftWatch();
    const run = (released: string[], atOnce: string[] = [], extra: { signal?: AbortSignal } = {}) => {
      guard.released = released;
      guard.result = (): Promise<string[]> => Promise.resolve(atOnce);
      return schemaCheck.checkSchemaOnSchedule({ ...options(log), ...extra }, fullServer, releaseDrift);
    };
    const refused = (error: Error) => {
      guard.result = (): Promise<string[]> => Promise.reject(error);
      return schemaCheck.checkSchemaOnSchedule(options(log), fullServer, releaseDrift);
    };
    const lines = () => log.capture.lines();
    return { run, refused, lines, events: () => lines().map(({ event }) => event) };
  };

  it('warns on its first run, naming it, and raises no alarm', async () => {
    const { run, lines } = runs();
    await run([CHECK_GONE]);
    expect(lines()).toMatchObject([{ level: 'warn', event: WARNED, problems: [CHECK_GONE] }]);
  });

  it('is the alarm on its second run in a row, and on each after it', async () => {
    const { run, lines, events } = runs();
    await run([CHECK_GONE]);
    await run([CHECK_GONE]);
    expect(lines()[1]).toMatchObject({
      level: 'error',
      event: ALARM,
      check: 'schema',
      when: 'running',
      problems: [CHECK_GONE],
    });
    await run([CHECK_GONE]);
    expect(events()).toEqual([WARNED, ALARM, ALARM]);
  });

  it('starts again after a clean run between', async () => {
    const { run, events } = runs();
    await run([CHECK_GONE]);
    await run([]);
    await run([CHECK_GONE]);
    expect(events()).toEqual([WARNED, WARNED]);
  });

  it('is the alarm on the second run though the plant changed: rotating them never starts it again', async () => {
    const { run, lines } = runs();
    await run([CHECK_GONE]);
    await run([FUNCTION_UNKNOWN]);
    expect(lines()[1]).toMatchObject({ event: ALARM, problems: [FUNCTION_UNKNOWN] });
  });

  it('other drift beside it is the alarm at once, alone, and the first sighting is still only warned of', async () => {
    const { run, lines } = runs();
    await run([CHECK_GONE], [OTHER]);
    expect(lines()).toMatchObject([
      { level: 'warn', event: WARNED, problems: [CHECK_GONE] },
      { level: 'error', event: ALARM, problems: [OTHER] },
    ]);
    expect(lines()[1]?.problems).toEqual([OTHER]);
  });

  it('both are in the alarm on the second run, in order', async () => {
    const { run, lines } = runs();
    await run([CHECK_GONE]);
    await run([CHECK_GONE], [OTHER]);
    expect(lines()[1]).toMatchObject({ event: ALARM, problems: [OTHER, CHECK_GONE] });
  });

  it('other drift alone is a run without it: the next sighting is a first', async () => {
    const { run, events } = runs();
    await run([CHECK_GONE]);
    await run([], [OTHER]);
    await run([CHECK_GONE]);
    expect(events()).toEqual([WARNED, ALARM, WARNED]);
  });

  it('a stop leaves the watch alone: the run after it is still the second', async () => {
    const { run, events } = runs();
    await run([CHECK_GONE]);
    const stopping = new AbortController();
    stopping.abort();
    await run([], [], { signal: stopping.signal });
    expect(events()).toEqual([WARNED]);
    await run([CHECK_GONE]);
    expect(events()).toEqual([WARNED, ALARM]);
  });

  it.each([
    ['a read that failed', new Error('connection reset'), [WARNED, ALARM, 'db.schema_unreadable', ALARM]],
    [
      'a full server',
      Object.assign(new Error('sorry, too many clients already'), { code: '53300' }),
      [WARNED, 'db.schema_check_full_server', ALARM],
    ],
  ])('%s says nothing of the drift: the run after it is still the second', async (_what, error, expected) => {
    const { run, refused, events } = runs();
    await run([CHECK_GONE]);
    await refused(error);
    await run([CHECK_GONE]);
    expect(events()).toEqual(expected);
  });

  it('holds each process’s watch apart', async () => {
    const one = runs();
    const other = runs();
    await one.run([CHECK_GONE]);
    await other.run([CHECK_GONE]);
    expect(one.events()).toEqual([WARNED]);
    expect(other.events()).toEqual([WARNED]);
  });

  it('at start it waits for nothing: the first sighting refuses the start, with the whole list', async () => {
    guard.released = [CHECK_GONE];
    guard.result = (): Promise<string[]> => Promise.resolve([OTHER]);
    const log = logger();
    expect(await schemaSoundAtStart(options(log))).toBe(false);
    expect(log.capture.lines()).toMatchObject([
      { level: 'error', event: ALARM, when: 'start', problems: [OTHER, CHECK_GONE] },
    ]);
  });

  it('at start, release-shaped drift alone refuses it too', async () => {
    guard.released = [FUNCTION_UNKNOWN];
    const log = logger();
    expect(await schemaSoundAtStart(options(log))).toBe(false);
    expect(log.capture.lines()).toMatchObject([{ event: ALARM, when: 'start', problems: [FUNCTION_UNKNOWN] }]);
  });
});

describe('asking for the first connection on a full server', () => {
  const full = () => Object.assign(new Error('sorry, too many clients already'), { code: '53300' });

  it('warns and asks again until it answers', async () => {
    let asks = 0;
    const log = logger();
    const answer = await schemaCheck.whileServerFull(
      () => {
        asks += 1;
        return asks < 3 ? Promise.reject(full()) : Promise.resolve('connected');
      },
      log.logger,
      { limitMs: 1_000, retryMs: 1 },
    );
    expect(answer).toBe('connected');
    expect(log.capture.lines()).toMatchObject([
      { level: 'warn', event: 'db.schema_check_full_server', when: 'connecting' },
      { level: 'warn', event: 'db.schema_check_full_server', when: 'connecting' },
    ]);
  });

  it('gives its failure to the caller past the limit', async () => {
    const log = logger();
    await expect(
      schemaCheck.whileServerFull(() => Promise.reject(full()), log.logger, { limitMs: 0, retryMs: 1 }),
    ).rejects.toThrow('too many clients');
    expect(log.capture.lines()).toEqual([]);
  });

  it('gives any other failure to the caller at once', async () => {
    let asks = 0;
    const log = logger();
    await expect(
      schemaCheck.whileServerFull(
        () => {
          asks += 1;
          return Promise.reject(new Error('password authentication failed'));
        },
        log.logger,
        { limitMs: 1_000, retryMs: 1 },
      ),
    ).rejects.toThrow('password');
    expect(asks).toBe(1);
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
    expect(log.capture.lines().map((line) => line.event)).toEqual(['audit.integrity_failed', 'db.schema_unreadable']);
    expect(log.capture.lines()[0]).toMatchObject({ check: 'schema', reason: 'unreadable' });
  });

  it('refuses the start when the read does not finish in time', async () => {
    guard.result = (): Promise<string[]> => new Promise(() => undefined);
    const log = logger();
    expect(await schemaSoundAtStart({ ...options(log), deadlineMs: 20 })).toBe(false);
  });

  it('ends at once when the process is stopping, without waiting for the deadline', async () => {
    guard.result = (): Promise<string[]> => new Promise(() => undefined);
    const log = logger();
    const stopping = new AbortController();
    stopping.abort();
    // A monotonic timer: this measures how long the check took, not what time it is.
    const started = performance.now();
    await checkSchemaOnSchedule({ ...options(log), deadlineMs: 60_000, signal: stopping.signal });
    expect(performance.now() - started).toBeLessThan(5_000);
    // The stop is the process's own doing, so it raises no alarm: a routine shutdown must not page anyone.
    expect(log.capture.lines()).toEqual([]);
  });

  it('raises no alarm when the stop comes during a read', async () => {
    const stopping = new AbortController();
    guard.result = (): Promise<string[]> => {
      stopping.abort();
      return new Promise(() => undefined);
    };
    const log = logger();
    await checkSchemaOnSchedule({ ...options(log), signal: stopping.signal });
    expect(log.capture.lines()).toEqual([]);
  });

  it('still raises the alarm for a read that failed on its own, though the stop came just after', async () => {
    const stopping = new AbortController();
    // The read fails, and the stop lands in the same moment, before the check
    // has handled the failure: the failure, not the stop, is what it met.
    guard.result = (): Promise<string[]> =>
      ({
        then: (_resolve: unknown, reject: (error: Error) => void) => {
          reject(new Error('permission denied for table pg_class'));
          stopping.abort();
        },
      }) as unknown as Promise<string[]>;
    const log = logger();
    await checkSchemaOnSchedule({ ...options(log), signal: stopping.signal });
    expect(stopping.signal.aborted).toBe(true);
    expect(log.capture.lines().map((line) => line.event)).toEqual(['audit.integrity_failed', 'db.schema_unreadable']);
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
    expect(log.capture.lines().map((line) => line.event)).toEqual(['audit.integrity_failed', 'db.schema_unreadable']);
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
