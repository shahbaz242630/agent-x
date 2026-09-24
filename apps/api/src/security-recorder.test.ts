// B2-5b: the security events' recorder, with a stand-in for the write (the
// real one: the security-events module's security-events.db.test.ts).
import { MOST_EVENTS_A_BATCH, type SecurityEvent } from '@agentx/core/modules/security-events';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { createSecurityRecorder, type SecurityEventNote } from './security-recorder.ts';

const MINUTE = 60_000;
/** 10:00:00 on the test's day. */
const TEN = Date.UTC(2026, 8, 24, 10, 0, 0);
const USER_ID = '0199a0f0-0000-7000-8000-000000000011';

const failedSignIn = (ip: string | undefined, reason = 'code_rejected'): SecurityEventNote => ({
  kind: 'sign_in_failed',
  reason,
  ip,
});

function setUp(options: { mostCounts?: number; answers?: (Error | undefined)[] } = {}) {
  const capture = new LogCapture();
  const logger = createLogger({
    service: 'api',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
    destination: capture,
  });
  let now = TEN + 5_000;
  const written: SecurityEvent[][] = [];
  const answers = options.answers ?? [];
  const recorder = createSecurityRecorder({
    write: (events) => {
      written.push([...events]);
      const answer = answers.shift();
      return answer === undefined ? Promise.resolve() : Promise.reject(answer);
    },
    now: () => now,
    logger,
    ...(options.mostCounts === undefined ? {} : { mostCounts: options.mostCounts }),
  });
  const at = (ms: number) => {
    now = ms;
  };
  const events = (name: string) => capture.lines().filter((line) => line.event === name);
  return { recorder, written, at, events };
}

describe('SEC-AV-07 security events are counted in memory and written a minute at a time', () => {
  it('counts the same event in the same minute once, with how many there were', async () => {
    const { recorder, written, at } = setUp();
    for (let i = 0; i < 3; i += 1) recorder.note(failedSignIn('203.0.113.9'));

    at(TEN + MINUTE);
    await recorder.run();

    expect(written).toEqual([
      [
        {
          kind: 'sign_in_failed',
          reason: 'code_rejected',
          ip: '203.0.113.9',
          userId: undefined,
          windowStart: new Date(TEN),
          count: 3,
        },
      ],
    ]);
  });

  it('counts each kind, reason, address, person and minute apart', async () => {
    const { recorder, written, at } = setUp();
    recorder.note(failedSignIn('203.0.113.9'));
    recorder.note(failedSignIn('203.0.113.9', 'token_invalid'));
    recorder.note(failedSignIn('203.0.113.10'));
    recorder.note({ kind: 'rate_limited', reason: 'per_address', ip: '203.0.113.9' });
    recorder.note({ ...failedSignIn('203.0.113.9'), userId: USER_ID });
    at(TEN + MINUTE + 1);
    recorder.note(failedSignIn('203.0.113.9'));

    at(TEN + 2 * MINUTE);
    await recorder.run();

    const rows = written.flat();
    expect(rows).toHaveLength(6);
    expect(rows.every((row) => row.count === 1)).toBe(true);
    expect(rows.map((row) => row.windowStart.getTime() - TEN)).toEqual([0, 0, 0, 0, 0, MINUTE]);
  });

  it("writes only the minutes that have ended, leaving the current one's counts to grow", async () => {
    const { recorder, written, at } = setUp();
    recorder.note(failedSignIn('203.0.113.9'));
    await recorder.run();
    expect(written).toEqual([]);

    at(TEN + MINUTE + 1);
    recorder.note(failedSignIn('203.0.113.9'));
    await recorder.run();
    expect(written.flat().map((row) => row.windowStart.getTime())).toEqual([TEN]);

    at(TEN + 2 * MINUTE);
    await recorder.run();
    expect(written.flat().map((row) => row.windowStart.getTime())).toEqual([TEN, TEN + MINUTE]);
  });

  it("writes everything as the API stops, the current minute's counts too, and nothing twice", async () => {
    const { recorder, written } = setUp();
    recorder.note(failedSignIn('203.0.113.9'));

    await recorder.flush();
    await recorder.flush();
    await recorder.run();

    expect(written).toHaveLength(1);
    expect(written[0]).toMatchObject([{ windowStart: new Date(TEN), count: 1 }]);
  });

  it('writes nothing, and asks nothing of the database, when there is nothing to write', async () => {
    const { recorder, written, events } = setUp();
    await recorder.run();
    await recorder.flush();
    expect(written).toEqual([]);
    expect(events('security.events_written')).toEqual([]);
  });

  it('writes a batch at most MOST_EVENTS_A_BATCH events at a time, and logs each', async () => {
    const { recorder, written, at, events } = setUp();
    for (let i = 0; i < MOST_EVENTS_A_BATCH + 1; i += 1)
      recorder.note(failedSignIn(`10.0.${String(i >> 8)}.${String(i & 255)}`));

    at(TEN + MINUTE);
    await recorder.run();

    expect(written.map((batch) => batch.length)).toEqual([MOST_EVENTS_A_BATCH, 1]);
    expect(events('security.events_written')).toMatchObject([
      { events: MOST_EVENTS_A_BATCH, count: MOST_EVENTS_A_BATCH },
      { events: 1, count: 1 },
    ]);
  });
});

describe("SEC-AV-07 the address kept is the client's own, whole", () => {
  it.each([
    ['an IPv4 address with a port, as some proxies write it', '203.0.113.9:40001', '203.0.113.9'],
    ['a bracketed IPv6 address with a port', '[2001:db8:1:2::7]:443', '2001:db8:1:2::7'],
    ['an IPv6 address, whole, never its /64', '2001:db8:1:2:aaaa:bbbb:cccc:dddd', '2001:db8:1:2:aaaa:bbbb:cccc:dddd'],
    ['text that is no address', 'unknown', undefined],
    ['a request whose connection closed first', undefined, undefined],
  ])('keeps %s as %s', async (_what, ip, expected) => {
    const { recorder, written } = setUp();
    recorder.note(failedSignIn(ip));
    await recorder.flush();
    expect(written.flat().map((row) => row.ip)).toEqual([expected]);
  });

  it('counts a port that changes with every connection under the one address', async () => {
    const { recorder, written } = setUp();
    recorder.note(failedSignIn('203.0.113.9:40001'));
    recorder.note(failedSignIn('203.0.113.9:40002'));
    await recorder.flush();
    expect(written.flat()).toMatchObject([{ ip: '203.0.113.9', count: 2 }]);
  });
});

describe('SEC-AV-09 a flood from many addresses cannot fill the memory', () => {
  it('past the most counts, counts new addresses without their address or person, and says how many', async () => {
    const { recorder, written, events } = setUp({ mostCounts: 2 });
    recorder.note(failedSignIn('203.0.113.1'));
    recorder.note(failedSignIn('203.0.113.2'));
    for (let i = 3; i < 13; i += 1) recorder.note({ ...failedSignIn(`203.0.113.${String(i)}`), userId: USER_ID });
    // An address already held still counts under its own.
    recorder.note(failedSignIn('203.0.113.1'));

    await recorder.flush();

    expect(written.flat().map((row) => [row.ip, row.userId, row.count])).toEqual([
      ['203.0.113.1', undefined, 2],
      ['203.0.113.2', undefined, 1],
      [undefined, undefined, 10],
    ]);
    expect(events('security.events_unaddressed')).toMatchObject([{ count: 10, mostCounts: 2 }]);
  });
});

describe('SEC-AV-07 a failed write loses no count, and a malformed one is never retried', () => {
  it('puts the counts back when the database is away, and writes them at the next run', async () => {
    const { recorder, written, at, events } = setUp({ answers: [new Error('the database is away')] });
    recorder.note(failedSignIn('203.0.113.9'));
    at(TEN + MINUTE);
    await recorder.run();
    expect(events('security.events_write_failed')).toMatchObject([{ events: 1 }]);

    recorder.note(failedSignIn('203.0.113.9'));
    at(TEN + 2 * MINUTE);
    await recorder.run();

    expect(written).toHaveLength(2);
    expect(written[1]).toMatchObject([
      { windowStart: new Date(TEN), count: 1 },
      { windowStart: new Date(TEN + MINUTE), count: 1 },
    ]);
  });

  it('puts back the batches after a failed one too, and stops writing for this run', async () => {
    const { recorder, written, at } = setUp({ answers: [undefined, new Error('the database is away')] });
    for (let i = 0; i < 2 * MOST_EVENTS_A_BATCH + 1; i += 1)
      recorder.note(failedSignIn(`10.0.${String(i >> 8)}.${String(i & 255)}`));
    at(TEN + MINUTE);
    await recorder.run();
    expect(written.map((batch) => batch.length)).toEqual([MOST_EVENTS_A_BATCH, MOST_EVENTS_A_BATCH]);

    await recorder.run();
    expect(written.slice(2).flat()).toHaveLength(MOST_EVENTS_A_BATCH + 1);
  });

  it('drops a batch the module refuses as malformed, logs it as an error, and writes the rest', async () => {
    const { recorder, written, at, events } = setUp({ answers: [new RangeError('a security event can’t be written')] });
    recorder.note(failedSignIn('203.0.113.9', 'Not A Reason'));
    at(TEN + MINUTE);
    await recorder.run();
    expect(events('security.events_refused')).toMatchObject([{ events: 1 }]);

    recorder.note(failedSignIn('203.0.113.9'));
    at(TEN + 2 * MINUTE);
    await recorder.run();
    expect(written[1]).toMatchObject([{ reason: 'code_rejected', windowStart: new Date(TEN + MINUTE) }]);
  });

  it('keeps going when the write throws outright, rather than rejecting', async () => {
    const capture = new LogCapture();
    const logger = createLogger({
      service: 'api',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: capture,
    });
    let calls = 0;
    const recorder = createSecurityRecorder({
      write: () => {
        calls += 1;
        throw new Error('thrown before any promise');
      },
      now: () => TEN,
      logger,
    });
    recorder.note(failedSignIn('203.0.113.9'));
    await expect(recorder.flush()).resolves.toBeUndefined();
    await expect(recorder.flush()).resolves.toBeUndefined();
    expect(calls).toBe(2);
  });
});
