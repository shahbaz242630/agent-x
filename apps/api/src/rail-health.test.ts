// The bank breaker (4D2e Stage F): a lane held by 3 unknowns in a row, then one
// at a time; everyone held by 5 unknowns from 3 organisations in 60 s, until a
// status lookup answers, and never by time alone.
import { type FinancialRailAdapter, RailUnavailable } from '@agentx/core/modules/providers';
import { FixedClock, LogCapture, testLogger } from '@agentx/testing';
import { beforeEach, describe, expect, it } from 'vitest';

import { createRailHealth, type RailHealth, watchedRail } from './rail-health.ts';

let clock: FixedClock;
let capture: LogCapture;
let health: RailHealth;

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** `times` unknowns from the organisation. */
const unknowns = (orgId: string, times: number) => {
  for (let time = 0; time < times; time += 1) health.unknown(orgId);
};

beforeEach(() => {
  clock = new FixedClock(new Date('2026-11-02T10:00:00Z'));
  capture = new LogCapture();
  health = createRailHealth({ clock, logger: testLogger(capture) });
});

describe('a lane', () => {
  it('holds an organisation at its third unknown in a row, not before, and no other', () => {
    unknowns('a', 2);
    expect(health.heldFor('a')).toBeUndefined();
    expect(health.oneAtATime('a')).toBe(false);

    unknowns('a', 1);

    expect(health.heldFor('a')).toBe('lane');
    expect(health.heldFor('b')).toBeUndefined();
    expect(lines('handoff.lane_held')).toEqual([expect.objectContaining({ orgId: 'a', unknowns: 3, level: 'warn' })]);
  });

  it('counts only in a row: an answer breaks it', () => {
    unknowns('a', 2);
    health.answered('a');
    unknowns('a', 2);

    expect(health.heldFor('a')).toBeUndefined();
  });

  it('holds for 5 minutes exactly, then one at a time, not held', () => {
    unknowns('a', 3);

    clock.advanceBy(5 * 60_000 - 1);
    expect(health.heldFor('a')).toBe('lane');

    clock.advanceBy(1);
    expect(health.heldFor('a')).toBeUndefined();
    expect(health.oneAtATime('a')).toBe(true);
  });

  it('holds again at a further unknown past its hold, said again; while held, said only once', () => {
    unknowns('a', 4);
    expect(lines('handoff.lane_held')).toHaveLength(1);

    clock.advanceBy(5 * 60_000);
    unknowns('a', 1);

    expect(health.heldFor('a')).toBe('lane');
    expect(lines('handoff.lane_held')).toHaveLength(2);
  });

  it('is clear of it all at the bank’s next answer', () => {
    unknowns('a', 3);

    health.answered('a');

    expect(health.heldFor('a')).toBeUndefined();
    expect(health.oneAtATime('a')).toBe(false);
  });

  it('takes a different count where a test names one', () => {
    health = createRailHealth({ clock, logger: testLogger(capture), laneUnknowns: 1 });

    unknowns('a', 1);

    expect(health.heldFor('a')).toBe('lane');
  });
});

describe('the platform', () => {
  it('holds everyone at the fifth unknown from at least three organisations', () => {
    unknowns('a', 2);
    unknowns('b', 2);
    expect(health.heldFor('z')).toBeUndefined();

    unknowns('c', 1);

    expect(health.heldFor('z')).toBe('bank');
    expect(health.heldFor('a')).toBe('bank');
    expect(lines('handoff.bank_held')).toEqual([expect.objectContaining({ unknowns: 5, organisations: 3 })]);
  });

  it('holds no one for many unknowns from two organisations: theirs, not the bank’s', () => {
    unknowns('a', 5);
    unknowns('b', 5);

    expect(health.heldFor('z')).toBeUndefined();
    expect(lines('handoff.bank_held')).toEqual([]);
  });

  it('holds no one for three organisations short of five unknowns', () => {
    unknowns('a', 1);
    unknowns('b', 1);
    unknowns('c', 2);

    expect(health.heldFor('z')).toBeUndefined();
  });

  it('counts only the last 60 s: one exactly that old is out, one younger is in', () => {
    unknowns('a', 1);
    clock.advanceBy(1);
    unknowns('b', 2);
    unknowns('d', 1);
    clock.advanceBy(59_999);
    // The first is now 60 s old: out. Three within the window, and this the fourth.
    unknowns('c', 1);
    expect(health.heldFor('z')).toBeUndefined();

    unknowns('c', 1);

    expect(health.heldFor('z')).toBe('bank');
  });

  it('never reopens by time alone: a real payment is never the probe', () => {
    unknowns('a', 2);
    unknowns('b', 2);
    unknowns('c', 1);

    clock.advanceBy(24 * 60 * 60_000);

    expect(health.heldFor('z')).toBe('bank');
  });

  it('stays held by a payment’s answer: only a lookup reopens it', () => {
    unknowns('a', 2);
    unknowns('b', 2);
    unknowns('c', 1);

    health.answered('a');

    expect(health.heldFor('a')).toBe('bank');
  });

  it('reopens at a lookup, said once; the count starts afresh', () => {
    unknowns('a', 2);
    unknowns('b', 2);
    unknowns('c', 1);

    health.looked();
    health.looked();

    expect(health.heldFor('z')).toBeUndefined();
    expect(lines('handoff.bank_back')).toHaveLength(1);
    unknowns('z', 1);
    expect(health.heldFor('y')).toBeUndefined();
  });

  it('says nothing and holds no one for a lookup when nothing is held', () => {
    health.looked();

    expect(lines('handoff.bank_back')).toEqual([]);
    expect(health.heldFor('a')).toBeUndefined();
  });

  it('says a hold once, however many more come while it holds', () => {
    unknowns('a', 2);
    unknowns('b', 2);
    unknowns('c', 3);

    expect(lines('handoff.bank_held')).toHaveLength(1);
  });

  it('keeps a lane’s own hold when the bank comes back: it may be that organisation’s alone', () => {
    unknowns('a', 3);
    unknowns('b', 1);
    unknowns('c', 1);
    expect(health.heldFor('b')).toBe('bank');

    health.looked();

    expect(health.heldFor('a')).toBe('lane');
    expect(health.heldFor('b')).toBeUndefined();
  });
});

describe('the rail, watched', () => {
  const REF = { organizationId: 'a', instructionId: 'i' };
  const railAnswering = (getExecution: FinancialRailAdapter['getExecution']) =>
    ({ identity: { partner: 'fake' }, getExecution }) as unknown as FinancialRailAdapter;
  const looks = () => {
    let count = 0;
    return {
      looked: () => {
        count += 1;
      },
      count: () => count,
    };
  };

  it.each([
    ['not found', { kind: 'not_found' }],
    ['found', { kind: 'found', execution: {} }],
  ] as const)('tells the health a lookup answered: %s', async (_name, answer) => {
    const watch = looks();
    const lookup = () => Promise.resolve(answer) as ReturnType<FinancialRailAdapter['getExecution']>;

    await expect(watchedRail(railAnswering(lookup), watch).getExecution(REF)).resolves.toEqual(answer);

    expect(watch.count()).toBe(1);
  });

  it('tells it nothing for a lookup that didn’t answer', async () => {
    const watch = looks();
    const lookup = () => Promise.reject(new RailUnavailable());

    await expect(watchedRail(railAnswering(lookup), watch).getExecution(REF)).rejects.toThrow(RailUnavailable);

    expect(watch.count()).toBe(0);
  });

  it('keeps everything else of the rail, a class’s methods among them', () => {
    class Adapter {
      readonly name = 'adapter';
      nameOf() {
        return this.name;
      }
      getExecution() {
        return Promise.resolve({ kind: 'not_found' as const });
      }
    }

    const watched = watchedRail(new Adapter() as unknown as FinancialRailAdapter, looks()) as unknown as Adapter;

    expect(watched.nameOf()).toBe('adapter');
  });
});
