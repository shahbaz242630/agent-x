import { findLeaks, LogCapture, SENSITIVE_SAMPLES as SAMPLES } from '@agentx/testing';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import type { LogLevel } from '../config/index.ts';
import {
  asNoWork,
  createLogger,
  createStartupLogger,
  eventOf,
  type EventName,
  INVALID_EVENT,
  type LogBindings,
  type LogFields,
  SUPPRESSED_EVENT,
  withLogContext,
} from './logger.ts';
import { type ProblemEvent, saysFor } from './plain-words.ts';
import { DECISION_BUDGET_PER_MINUTE, DECISION_EVENT, NEVER_HELD_BACK } from './volume-guard.ts';

/** A catalogued problem, for tests of warnings and errors in general. */
const PROBLEM = 'db.transaction_retried';
/** An ordinary info line, held back past the cap: warnings and errors never are (4D2e F8). */
const BUSY = 'busy.event';
/** A marker value that must never come out. Plain words, so secret scanners ignore it. */
const PLANTED = 'planted value that must not appear';
const START = Date.UTC(2026, 8, 14, 10, 0, 0);
const RUNS = { numRuns: 200, seed: 20_260_914 };

function setup(options: { level?: LogLevel; cap?: number } = {}) {
  let time = START;
  const capture = new LogCapture();
  const logger = createLogger({
    service: 'api',
    config: {
      environment: 'test',
      release: 'r-1',
      log: { level: options.level ?? 'info', eventCapPerMinute: options.cap ?? 100 },
    },
    destination: capture,
    now: () => time,
  });
  return {
    capture,
    logger,
    lines: () => capture.lines(),
    advance: (ms: number) => {
      time += ms;
    },
  };
}

describe('4D2e Stage F the work a line belongs to', () => {
  it('says the correlation ID or run ID of the work under way, through any logger, past an await', async () => {
    const { logger, lines } = setup();
    await withLogContext({ correlationId: 'c-1' }, async () => {
      logger.info('a.before');
      await Promise.resolve();
      logger.child({ module: 'm' }).info('a.after');
    });
    withLogContext({ runId: 'r-1' }, () => {
      logger.info('a.run');
    });
    logger.info('a.none');
    expect(lines()[0]).toMatchObject({ event: 'a.before', correlationId: 'c-1' });
    expect(lines()[1]).toMatchObject({ event: 'a.after', correlationId: 'c-1', module: 'm' });
    expect(lines()[2]).toMatchObject({ event: 'a.run', runId: 'r-1' });
    expect(lines()[3]).not.toHaveProperty('correlationId');
    expect(lines()[3]).not.toHaveProperty('runId');
  });

  it('keeps two pieces of work under way at once apart', async () => {
    const { logger, lines } = setup();
    const work = (id: string) =>
      withLogContext({ correlationId: id }, async () => {
        await Promise.resolve();
        logger.info('a.work', { id });
      });
    await Promise.all([work('c-1'), work('c-2')]);
    for (const line of lines()) expect(line.correlationId).toBe(line.id);
  });

  it('lets a correlation ID a child was given stand, the run ID beside it', () => {
    const { logger, lines } = setup();
    withLogContext({ runId: 'r-1' }, () => {
      logger.child({ correlationId: 'own' }).child({ module: 'm' }).info('a.child');
    });
    withLogContext({ correlationId: 'request' }, () => {
      logger.child({ correlationId: 'own' }).info('a.own');
    });
    expect(lines()[0]).toMatchObject({ correlationId: 'own', runId: 'r-1' });
    expect(lines()[1]).toMatchObject({ correlationId: 'own' });
    expect(lines()[1]).not.toHaveProperty('runId');
  });

  it("can't be forged by a line's own fields", () => {
    const { logger, lines } = setup();
    const forged = { runId: 'forged', correlationId: 'forged' } as unknown as LogFields;
    logger.info('a.none', forged);
    withLogContext({ runId: 'r-1' }, () => {
      logger.info('a.run', forged);
    });
    expect(lines()[0]).not.toHaveProperty('runId');
    expect(lines()[1]).toMatchObject({ runId: 'r-1' });
    expect(lines()[1]).not.toHaveProperty('correlationId');
  });

  it('leaves nothing behind when the work throws, and says the work on the line about it', async () => {
    const { logger, lines } = setup();
    expect(() =>
      withLogContext({ correlationId: 'c-1' }, () => {
        throw new Error('at once');
      }),
    ).toThrow('at once');
    logger.info('a.after_throw');
    await expect(
      withLogContext({ runId: 'r-1' }, async () => {
        await Promise.resolve();
        const error = Object.assign(new Error('later'), { correlationId: 'on-the-error', runId: 'on-the-error' });
        logger.error(PROBLEM, { err: error });
        throw error;
      }),
    ).rejects.toThrow('later');
    logger.info('a.after_rejection');
    const [afterThrow, failed, afterRejection] = lines();
    expect(afterThrow).not.toHaveProperty('correlationId');
    expect(afterRejection).not.toHaveProperty('runId');
    // The work's own ID on the line: an error's fields stay inside `err`.
    expect(failed).toMatchObject({ runId: 'r-1' });
    expect(failed).not.toHaveProperty('correlationId');
  });

  it('keeps the work on a line cut for length, which is still one JSON line', () => {
    const { logger, lines } = setup();
    const huge = Object.fromEntries(Array.from({ length: 40 }, (_, at) => [`f${String(at)}`, 'x'.repeat(2000)]));
    withLogContext({ correlationId: 'c-1', runId: 'r-1' }, () => {
      logger.info('a.huge', huge);
    });
    expect(lines()[0]).toMatchObject({ event: 'a.huge', lineCut: true, correlationId: 'c-1', runId: 'r-1' });
  });

  it('writes only the standard fields on a line outside any work', () => {
    const { logger, lines } = setup();
    logger.info('a.none');
    expect(Object.keys(lines()[0] ?? {}).toSorted()).toEqual(['env', 'event', 'level', 'release', 'service', 'time']);
  });

  it('says no work from a listener that outlasts it, and the work carries on after', async () => {
    const { logger, lines } = setup();
    await withLogContext({ correlationId: 'c-1', runId: 'r-1' }, async () => {
      asNoWork(() => {
        logger.child({ module: 'm' }).info('a.listener');
      });
      await Promise.resolve();
      logger.info('a.work');
    });
    expect(lines()[0]).not.toHaveProperty('correlationId');
    expect(lines()[0]).not.toHaveProperty('runId');
    expect(lines()[1]).toMatchObject({ correlationId: 'c-1', runId: 'r-1' });
  });

  it("carries only a request's or run's ID: an organisation or person stays on the logger given it", async () => {
    const { logger, lines } = setup();
    await withLogContext({ runId: 'r-1' }, async () => {
      for (const org of ['a', 'b']) {
        const own = logger.child({ orgId: org, actor: `actor-${org}`, correlationId: `c-${org}` });
        own.info('a.organisation');
        await Promise.resolve();
        logger.info('a.bare');
        own.info('a.organisation');
      }
    });
    const [a1, bareA, a2, b1, bareB, b2] = lines();
    const ofA = { orgId: 'a', actor: 'actor-a', correlationId: 'c-a', runId: 'r-1' };
    const ofB = { orgId: 'b', actor: 'actor-b', correlationId: 'c-b', runId: 'r-1' };
    expect([a1, a2, b1, b2]).toMatchObject([ofA, ofA, ofB, ofB]);
    for (const line of [bareA, bareB]) {
      expect(line).toMatchObject({ runId: 'r-1' });
      for (const name of ['orgId', 'actor', 'correlationId']) expect(line).not.toHaveProperty(name);
    }
  });

  it('gives no work to the held-back counts: they belong to no request', () => {
    const { logger, lines, advance } = setup({ cap: 1 });
    logger.info('a.flood');
    logger.info('a.flood');
    advance(60_000);
    withLogContext({ correlationId: 'c-1' }, () => {
      logger.info('b.next');
    });
    const summary = lines().find(({ event }) => event === SUPPRESSED_EVENT);
    expect(summary).toBeDefined();
    expect(summary).not.toHaveProperty('correlationId');
  });
});

describe('logging standard §2: one JSON line per event, with the standard fields', () => {
  it('writes the standard fields, the event and its fields, and nothing else', () => {
    const { logger, lines } = setup();
    logger.info('spend_request.decided', { outcome: 'approved', durationMs: 12 });
    expect(lines()).toEqual([
      {
        time: '2026-09-14T10:00:00.000Z',
        level: 'info',
        service: 'api',
        env: 'test',
        release: 'r-1',
        event: 'spend_request.decided',
        outcome: 'approved',
        durationMs: 12,
      },
    ]);
  });

  it('writes lines from before the config is read as unconfigured, at info, redacted like any other', () => {
    const capture = new LogCapture();
    const logger = createStartupLogger({ service: 'api', destination: capture, now: () => START });
    logger.debug('test.hidden');
    logger.error('api.start_refused', { problems: ['AGENTX_ENV: is required'], note: SAMPLES.email });
    expect(capture.lines()).toEqual([
      {
        time: '2026-09-14T10:00:00.000Z',
        level: 'error',
        service: 'api',
        env: 'unconfigured',
        release: 'unconfigured',
        event: 'api.start_refused',
        problems: ['AGENTX_ENV: is required'],
        note: '[email]',
        says: saysFor('api.start_refused'),
      },
    ]);
  });

  it.each(['error', 'warn', 'info', 'debug'] as const)('writes at %s', (level) => {
    const { logger, lines } = setup({ level: 'debug' });
    logger[level](PROBLEM);
    expect(lines()).toEqual([expect.objectContaining({ level, event: PROBLEM })]);
  });

  it('leaves out lines below the configured level', () => {
    const { logger, lines } = setup({ level: 'warn' });
    logger.info('test.info');
    logger.debug('test.debug');
    logger.warn(PROBLEM);
    expect(lines().map((line) => line.event)).toEqual([PROBLEM]);
  });

  it("adds a child logger's fields to each of its lines", () => {
    const { logger, lines } = setup();
    const child = logger.child({ correlationId: 'c-1', orgId: 'o-1', actor: 'agent-1', module: 'mandates' });
    child.info('mandate.accepted');
    child.child({ module: 'policies' }).info('policy.evaluated');
    expect(lines()).toEqual([
      expect.objectContaining({ correlationId: 'c-1', orgId: 'o-1', actor: 'agent-1', module: 'mandates' }),
      expect.objectContaining({ correlationId: 'c-1', module: 'policies', event: 'policy.evaluated' }),
    ]);
  });

  it('takes only the known fields from child bindings, as text', () => {
    const { logger, lines } = setup();
    const bindings = { correlationId: 'c-1', orgId: 7, extra: 'ignored' } as unknown as LogBindings;
    logger.child(bindings).info('test.event');
    expect(lines()[0]).toMatchObject({ correlationId: 'c-1' });
    expect(lines()[0]).not.toHaveProperty('extra');
    expect(lines()[0]).not.toHaveProperty('orgId');
  });

  it('never lets a caller overwrite the fields the logger writes itself, nor a child logger’s fields', () => {
    const { logger, lines } = setup();
    const forged = {
      time: 'x',
      level: 'x',
      service: 'x',
      env: 'x',
      release: 'x',
      event: 'x',
      correlationId: 'forged',
      orgId: 'org-forged',
      actor: 'forged',
      module: 'forged',
      suppressedCount: 0,
      kept: 1,
    } as unknown as LogFields;
    logger.child({ orgId: 'org-real' }).info('test.event', forged);
    expect(lines()).toEqual([
      {
        time: '2026-09-14T10:00:00.000Z',
        level: 'info',
        service: 'api',
        env: 'test',
        release: 'r-1',
        orgId: 'org-real',
        event: 'test.event',
        kept: 1,
      },
    ]);
  });

  it.each(['Bad.Event', 'no_dot', 'trailing.', '.leading', 'spaces in.name', 'log.suppressed', 'log.anything'])(
    'writes the event name %j, which a caller may not use, under log.invalid_event',
    (name) => {
      const { logger, lines } = setup();
      logger.info(name as EventName);
      expect(lines()).toEqual([expect.objectContaining({ event: INVALID_EVENT, invalidEvent: name })]);
    },
  );

  it('cleans an invalid event name before writing it', () => {
    const { logger, lines } = setup();
    logger.info(`Bad ${SAMPLES.email}` as EventName);
    expect(lines()[0]).toMatchObject({ event: INVALID_EVENT, invalidEvent: 'Bad [email]' });
  });

  it('uses the real clock when none is given', () => {
    const capture = new LogCapture();
    const before = Date.now();
    createLogger({
      service: 'api',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 100 } },
      destination: capture,
    }).info('test.event');
    const time = Date.parse(String(capture.lines()[0]?.time));
    expect(time).toBeGreaterThanOrEqual(before);
    expect(time).toBeLessThanOrEqual(Date.now());
  });

  it('writes to stdout when no destination is given (the end-to-end check in tooling/checks reads it)', () => {
    const logger = createLogger({
      service: 'api',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 100 } },
    });
    // Nothing is logged, so the test output stays clean; flush reaches the stdout destination.
    expect(() => {
      logger.flush();
    }).not.toThrow();
  });
});

describe('eventOf: which event a log call counts against in the volume guard', () => {
  it.each([
    ['our own call: fields, then the event name', [{ a: 1 }, 'spend_request.decided'], 'spend_request.decided'],
    ['a message on its own', ['incoming request'], 'incoming request'],
    ['no text at all', [{ a: 1 }], '(no event)'],
    ['a very long message, cut to 200 characters', ['m'.repeat(500)], 'm'.repeat(200)],
  ])('%s', (_what, args, expected) => {
    expect(eventOf(args)).toBe(expected);
  });
});

describe('SEC-DATA-01, SEC-DATA-05: nothing sensitive reaches the output, from any field or logger', () => {
  it('cleans every sensitive sample, wherever it is logged', () => {
    const { logger, capture } = setup();
    const child = logger.child({ correlationId: SAMPLES.email, actor: SAMPLES.agentKey });
    for (const [kind, sample] of Object.entries(SAMPLES)) {
      child.info('test.sample', { kind, note: `seen ${sample} here`, nested: { list: [sample] } });
      child.warn(`test.${kind.toLowerCase()}` as ProblemEvent, { [`${kind}Detail`]: sample });
    }
    expect(capture.lines()).toHaveLength(Object.keys(SAMPLES).length * 2);
    expect(findLeaks(capture.text, Object.values(SAMPLES))).toEqual([]);
  });

  it('never writes a value under a sensitive field name, at any depth', () => {
    const { logger, capture } = setup();
    logger.info('test.event', {
      password: PLANTED,
      request: { headers: { authorization: PLANTED, cookie: PLANTED }, body: { iban: PLANTED } },
      attempts: [{ apiKey: PLANTED }],
    });
    expect(findLeaks(capture.text, [PLANTED])).toEqual([]);
  });

  it('holds for any mix of fields: samples anywhere, and planted values under sensitive names at any depth', () => {
    const sensitiveName = fc.constantFrom('password', 'token', 'email', 'iban', 'secretValue');
    const plainName = fc.constantFrom('note', 'detail', 'context', 'items');
    const leaf = fc.oneof(fc.constantFrom(...Object.values(SAMPLES)), fc.integer(), fc.boolean());
    const { tree } = fc.letrec((tie) => ({
      tree: fc.oneof({ depthSize: 'small' }, leaf, tie('object'), tie('list')),
      object: fc
        .tuple(
          fc.dictionary(plainName, tie('tree'), { maxKeys: 3 }),
          fc.dictionary(sensitiveName, fc.constant(PLANTED), { maxKeys: 2 }),
        )
        .map(([plain, secrets]) => ({ ...plain, ...secrets })),
      list: fc.array(tie('tree'), { maxLength: 3 }),
    }));
    fc.assert(
      fc.property(fc.dictionary(plainName, tree), (fields) => {
        const { logger, capture } = setup();
        logger.info('test.event', fields);
        expect(findLeaks(capture.text, [PLANTED])).toEqual([]);
      }),
      RUNS,
    );
  });

  it('writes binary data as its size, never its bytes', () => {
    const { logger, lines } = setup();
    logger.info('http.request_received', { raw: Buffer.from(`email=${SAMPLES.email}&note=${PLANTED}`) });
    expect(lines()[0]).toMatchObject({ raw: { binaryBytes: expect.any(Number) as unknown } });
    expect(JSON.stringify(lines())).not.toContain(PLANTED);
  });

  it('writes a bigint amount as text, keeping every digit', () => {
    const { logger, lines } = setup();
    logger.info('payment.settled', { amountMinor: 12_345_678_901_234_567_891n });
    expect(lines()[0]).toMatchObject({ amountMinor: '12345678901234567891' });
  });

  it('writes fields it cannot read as a marker, without throwing into the caller', () => {
    const { logger, lines } = setup();
    const hostile = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error('trap');
        },
      },
    );
    expect(() => {
      logger.info('test.event', hostile);
    }).not.toThrow();
    expect(lines()[0]).toMatchObject({ event: 'test.event', fieldsUnreadable: true });
  });
});

describe('SEC-DATA-02: an error is logged as a fixed set of cleaned facts, under any name', () => {
  it('logs the type, cleaned message, safe code and stack, and nothing else from the error', () => {
    const { logger, lines } = setup();
    const error = Object.assign(new Error(`declined for ${SAMPLES.email}`), { code: 'ECONNRESET', detail: PLANTED });
    logger.error(PROBLEM, { err: error });
    const [line] = lines();
    expect(line?.err).toEqual({
      type: 'Error',
      message: 'declined for [email]',
      code: 'ECONNRESET',
      stack: expect.arrayContaining([expect.stringMatching(/^at /)]) as unknown,
    });
    expect(line).not.toHaveProperty('msg');
    expect(JSON.stringify(line)).not.toContain(PLANTED);
  });

  it.each([
    ['under another name', (e: Error) => ({ error: e })],
    ['nested', (e: Error) => ({ context: { failure: e } })],
    ['in a list', (e: Error) => ({ failures: [e] })],
  ])('logs an error %s the same way, leaving out a database driver’s row values', (_where, fields) => {
    const { logger, capture } = setup();
    const driverError = Object.assign(new Error('duplicate key'), { code: '23505', detail: PLANTED, table: 'payees' });
    logger.error(PROBLEM, fields(driverError));
    expect(capture.text).toContain('"code":"23505"');
    expect(findLeaks(capture.text, [PLANTED, 'payees'])).toEqual([]);
  });

  it('cleans every message in the cause chain', () => {
    const { logger, capture } = setup();
    const error = new Error('outer', { cause: new Error(`inner ${SAMPLES.uaeIban} ${SAMPLES.bearer}`) });
    logger.error(PROBLEM, { err: error });
    expect(findLeaks(capture.text)).toEqual([]);
    expect(capture.text).toContain('inner [iban] Bearer [redacted]');
  });

  it('logs something thrown that is not an Error', () => {
    const { logger, lines } = setup();
    logger.error(PROBLEM, { err: `rejected ${SAMPLES.ipv4}` });
    expect(lines()[0]?.err).toBe('rejected [ip]');
  });
});

describe('decision 29: a warning or error says what happened in plain words', () => {
  it.each(['warn', 'error'] as const)('adds the words to a %s line, after the fields', (level) => {
    const { logger, lines } = setup();
    logger[level]('db.transaction_retried', { try: 2 });
    expect(lines()[0]).toMatchObject({
      event: 'db.transaction_retried',
      try: 2,
      says: saysFor('db.transaction_retried'),
    });
  });

  it('adds no words to info or debug lines', () => {
    const { logger, lines } = setup({ level: 'debug' });
    logger.info('test.event');
    logger.debug('test.event');
    expect(lines().filter((line) => 'says' in line)).toEqual([]);
  });

  it('never lets a caller set the words', () => {
    const { logger, lines } = setup();
    logger.warn('db.transaction_retried', { says: 'forged' } as unknown as LogFields);
    expect(lines()[0]?.says).toBe(saysFor('db.transaction_retried'));
  });

  it('gives an invalid name, and a held-back count of decision lines, the logger’s own words', () => {
    const { logger, lines, advance } = setup({ cap: 1 });
    logger.error('Bad.Event' as ProblemEvent);
    // PL-52: the decision line's budget is 20,000 a minute; one more is held back and counted as a warning.
    for (let i = 0; i <= DECISION_BUDGET_PER_MINUTE; i++) logger.info(DECISION_EVENT);
    advance(60_000);
    logger.flush();
    expect(lines()[0]).toMatchObject({ event: INVALID_EVENT, says: saysFor(INVALID_EVENT) });
    expect(lines().filter((line) => line.event === DECISION_EVENT)).toHaveLength(DECISION_BUDGET_PER_MINUTE);
    expect(lines().at(-1)).toMatchObject({
      level: 'warn',
      event: SUPPRESSED_EVENT,
      suppressedEvent: DECISION_EVENT,
      suppressedCount: 1,
      says: saysFor(SUPPRESSED_EVENT),
    });
  });

  it('adds no words to a held-back count of info lines', () => {
    const { logger, lines } = setup({ cap: 1 });
    logger.info('busy.event');
    logger.info('busy.event');
    logger.flush();
    expect(lines().at(-1)).not.toHaveProperty('says');
  });

  it('takes only catalogued events as warnings and errors', () => {
    const { logger } = setup();
    // @ts-expect-error: an event with no plain words can't be a warning.
    logger.warn('not.catalogued');
    // @ts-expect-error: nor an error.
    logger.error('not.catalogued');
    // @ts-expect-error: the logger's own events aren't a caller's.
    logger.warn('log.suppressed');
  });
});

describe('SEC-AV-09: a flood of one event is capped, and the count is always written', () => {
  it('writes up to the cap each minute, then one summary line with the exact count and its minute', () => {
    const { logger, lines, advance } = setup({ cap: 3 });
    for (let i = 0; i < 8; i++) logger.info(BUSY);
    logger.info('other.event');
    expect(lines().map((line) => line.event)).toEqual([BUSY, BUSY, BUSY, 'other.event']);

    advance(60_000);
    logger.info('next.minute');
    expect(lines().slice(4)).toEqual([
      expect.objectContaining({
        level: 'info',
        event: SUPPRESSED_EVENT,
        suppressedEvent: BUSY,
        suppressedCount: 5,
        suppressedFrom: '2026-09-14T10:00:00.000Z',
        suppressedTo: '2026-09-14T10:01:00.000Z',
      }),
      expect.objectContaining({ event: 'next.minute' }),
    ]);
  });

  it('writes the summary through the root logger, without the fields of the child that happened to log next', () => {
    const { logger, lines, advance } = setup({ cap: 1 });
    logger.info('x.y');
    logger.info('x.y');
    advance(60_000);
    logger.child({ correlationId: 'c-9' }).info('z.z');
    const summary = lines().find((line) => line.event === SUPPRESSED_EVENT);
    expect(summary).toBeDefined();
    expect(summary).not.toHaveProperty('correlationId');
  });

  it.each(['info', 'debug'] as const)(
    'writes the summary of %s lines at that level, so the level filter that let them through lets it through',
    (level) => {
      const { logger, lines, advance } = setup({ level, cap: 1 });
      logger[level](BUSY);
      logger[level](BUSY);
      advance(60_000);
      logger.flush();
      expect(lines()).toContainEqual(expect.objectContaining({ level, event: SUPPRESSED_EVENT, suppressedCount: 1 }));
    },
  );

  it('never caps the summary lines themselves', () => {
    const { logger, lines, advance } = setup({ cap: 1 });
    for (const event of ['a.a', 'b.b', 'c.c'] as const) {
      logger.info(event);
      logger.info(event);
    }
    advance(60_000);
    logger.flush();
    expect(lines().filter((line) => line.event === SUPPRESSED_EVENT)).toHaveLength(3);
  });

  it('caps a caller that tries to pass off its own lines as summaries', () => {
    const { logger, lines } = setup({ cap: 2 });
    for (let i = 0; i < 10; i++) logger.info('log.suppressed' as EventName, { note: 'forged' });
    // A warning is never held back (4D2e F8), but is still no summary.
    logger.warn('log.suppressed' as ProblemEvent, { note: 'forged' });
    expect(lines().filter((line) => line.event === SUPPRESSED_EVENT)).toEqual([]);
    expect(lines().filter((line) => line.event === INVALID_EVENT)).toHaveLength(3);
  });

  it.each(['error', 'warn'] as const)('never holds back a line at %s, however many come', (level) => {
    const { logger, lines, advance } = setup({ cap: 10 });
    for (let i = 0; i < 500; i++) logger[level](PROBLEM);
    advance(60_000);
    logger.flush();
    expect(lines().filter((line) => line.event === PROBLEM)).toHaveLength(500);
    expect(lines().filter((line) => line.event === SUPPRESSED_EVENT)).toEqual([]);
  });

  it('never holds back a money or security line, even at info, however many come', () => {
    const { logger, lines, advance } = setup({ cap: 10 });
    const events = NEVER_HELD_BACK.map((family) => `${family}flood` as EventName);
    for (const event of events) for (let i = 0; i < 100; i++) logger.info(event);
    advance(60_000);
    logger.flush();
    for (const event of events) expect(lines().filter((line) => line.event === event)).toHaveLength(100);
    expect(lines().filter((line) => line.event === SUPPRESSED_EVENT)).toEqual([]);
  });

  it('writes the current minute’s count on flush, as at shutdown', () => {
    const { logger, lines } = setup({ cap: 2 });
    for (let i = 0; i < 6; i++) logger.info('busy.event');
    logger.flush();
    expect(lines().at(-1)).toEqual(
      expect.objectContaining({ event: SUPPRESSED_EVENT, suppressedEvent: 'busy.event', suppressedCount: 4 }),
    );
  });
});
