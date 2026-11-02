// The bank breaker (4D2e Stage F, as amended after review): a lane held by 3
// unknowns in a row, its hold growing, past it one payment only once a lookup
// for it answered; everyone held by 5 unknowns from 3 organisations in 60 s,
// half-open by a lookup begun since, 3 calls at once until an acceptance, tripped
// again by any unknown with a growing wait; and only a long hold an error.
import { type FinancialRailAdapter, RailUnavailable } from '@agentx/core/modules/providers';
import { FixedClock, LogCapture, testLogger } from '@agentx/testing';
import { beforeEach, describe, expect, it } from 'vitest';

import { createRailHealth, type RailEntry, type RailHealth, watchedRail } from './rail-health.ts';

let clock: FixedClock;
let capture: LogCapture;
let health: RailHealth;

const MINUTE = 60_000;

const lines = (event: string) => capture.lines().filter((line) => line.event === event);

/** The place a payment is let through with; throws where it was held. */
const entered = (orgId: string) => {
  const entry = health.enter(orgId);
  if ('hold' in entry) throw new Error(`held: ${entry.hold}`);
  return entry;
};

/** `times` payments from the organisation sent and left unknown. */
const unknowns = (orgId: string, times: number) => {
  for (let time = 0; time < times; time += 1) entered(orgId).settle('unknown');
};

const accepted = (orgId: string) => {
  entered(orgId).settle('accepted');
};

/** A lookup for the organisation begun and answered now. */
const looked = (orgId = 'anyone') => {
  health.lookupBegun(orgId)();
};

/** Everyone held: 5 unknowns from 3 organisations. */
const tripped = () => {
  unknowns('a', 2);
  unknowns('b', 2);
  unknowns('c', 1);
  expect(health.heldFor('z')).toBe('bank');
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
    expect(lines('handoff.lane_held')).toEqual([
      expect.objectContaining({ orgId: 'a', unknowns: 3, holdMinutes: 5, level: 'warn' }),
    ]);
  });

  it('counts only in a row: an acceptance breaks it', () => {
    unknowns('a', 2);
    accepted('a');
    unknowns('a', 2);

    expect(health.heldFor('a')).toBeUndefined();
  });

  it('takes a refusal as neutral: not an unknown, and it clears nothing', () => {
    unknowns('a', 2);
    entered('a').settle('refused');
    expect(health.heldFor('a')).toBeUndefined();

    unknowns('a', 1);
    expect(health.heldFor('a')).toBe('lane');

    // Past its hold, looked up: a refused one leaves it on its hold's terms, one at a time.
    clock.advanceBy(5 * MINUTE);
    looked('a');
    entered('a').settle('refused');
    expect(health.oneAtATime('a')).toBe(true);
    expect(health.heldFor('a')).toBeUndefined();
  });

  it('counts a payment never sent as nothing, and gives its place back', () => {
    unknowns('a', 3);
    clock.advanceBy(5 * MINUTE);
    looked('a');

    entered('a').settle('not_sent');

    expect(health.heldFor('a')).toBeUndefined();
    expect(health.oneAtATime('a')).toBe(true);
    expect(lines('handoff.lane_held')).toHaveLength(1);
  });

  it('a hung organisation sends nothing past its hold: no lookup for it has answered', () => {
    unknowns('a', 3);

    clock.advanceBy(5 * MINUTE - 1);
    expect(health.heldFor('a')).toBe('lane');
    clock.advanceBy(1);
    expect(health.heldFor('a')).toBe('lane');
    clock.advanceBy(24 * 60 * MINUTE);
    expect(health.heldFor('a')).toBe('lane');
    // Another's lookup says nothing of this one.
    looked('b');
    expect(health.heldFor('a')).toBe('lane');
  });

  it('lets one through past its hold once a lookup for it answered; then one at a time', () => {
    unknowns('a', 3);
    clock.advanceBy(5 * MINUTE);

    looked('a');

    expect(health.heldFor('a')).toBeUndefined();
    const first = entered('a');
    expect(health.heldFor('a')).toBe('lane');
    first.settle('refused');
    expect(health.heldFor('a')).toBeUndefined();
  });

  it('counts no lookup begun before its last unknown', () => {
    unknowns('a', 2);
    const begun = health.lookupBegun('a');
    unknowns('a', 1);
    begun();
    clock.advanceBy(5 * MINUTE);

    expect(health.heldFor('a')).toBe('lane');
  });

  it('counts one begun after its last unknown, though answered during its hold', () => {
    unknowns('a', 3);
    looked('a');
    clock.advanceBy(5 * MINUTE);

    expect(health.heldFor('a')).toBeUndefined();
  });

  it('grows the hold at each further unknown past it: 5, 10, 20, 40, then 60 at most', () => {
    unknowns('a', 3);
    for (const hold of [5, 10, 20, 40, 60, 60]) {
      clock.advanceBy(hold * MINUTE - 1);
      expect(health.heldFor('a')).toBe('lane');
      clock.advanceBy(1);
      looked('a');
      expect(health.heldFor('a')).toBeUndefined();
      entered('a').settle('unknown');
      expect(health.heldFor('a')).toBe('lane');
    }
    expect(lines('handoff.lane_held').map(({ holdMinutes }) => holdMinutes)).toEqual([5, 10, 20, 40, 60, 60, 60]);
  });

  it('extends and grows nothing for an unknown landing inside its hold', () => {
    // Four under way at once; the fourth lands inside the hold the third began.
    const under = [entered('a'), entered('a'), entered('a'), entered('a')];
    for (const call of under) call.settle('unknown');

    expect(lines('handoff.lane_held')).toHaveLength(1);
    clock.advanceBy(5 * MINUTE);
    looked('a');
    expect(health.heldFor('a')).toBeUndefined();
    entered('a').settle('unknown');
    expect(lines('handoff.lane_held').at(-1)).toMatchObject({ holdMinutes: 10 });
  });

  it('is clear of it all at an acceptance, the hold’s growth reset', () => {
    unknowns('a', 3);
    clock.advanceBy(5 * MINUTE);
    looked('a');
    entered('a').settle('unknown');
    clock.advanceBy(10 * MINUTE);
    looked('a');

    accepted('a');

    expect(health.heldFor('a')).toBeUndefined();
    expect(health.oneAtATime('a')).toBe(false);
    unknowns('a', 3);
    expect(lines('handoff.lane_held').at(-1)).toMatchObject({ holdMinutes: 5 });
  });

  it('takes a different count where a test names one', () => {
    health = createRailHealth({ clock, logger: testLogger(capture), laneUnknowns: 1 });

    unknowns('a', 1);

    expect(health.heldFor('a')).toBe('lane');
  });
});

describe('the platform', () => {
  it('holds everyone at the fifth unknown from at least three organisations, an error, one line', () => {
    unknowns('a', 2);
    unknowns('b', 2);
    expect(health.heldFor('z')).toBeUndefined();

    unknowns('c', 1);

    expect(health.heldFor('z')).toBe('bank');
    expect(health.heldFor('a')).toBe('bank');
    expect(lines('handoff.bank_held')).toEqual([
      expect.objectContaining({ level: 'error', unknowns: 5, organisations: 3 }),
    ]);
  });

  it('holds no one for many unknowns from two organisations: theirs, not the bank’s', () => {
    for (let time = 0; time < 3; time += 1) unknowns('a', 1);
    for (let time = 0; time < 3; time += 1) unknowns('b', 1);

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

  it('never reopens by time alone', () => {
    tripped();

    clock.advanceBy(24 * 60 * MINUTE);

    expect(health.heldFor('z')).toBe('bank');
  });

  it('counts no lookup begun before the trip, though it answers after', () => {
    unknowns('a', 2);
    unknowns('b', 2);
    const begun = health.lookupBegun('z');
    unknowns('c', 1);

    begun();

    expect(health.heldFor('z')).toBe('bank');
    expect(lines('handoff.bank_half_open')).toEqual([]);
  });

  it('goes half-open at a lookup begun since the trip, not_found or not: no error, and not yet reopened', () => {
    tripped();

    looked();

    expect(health.heldFor('z')).toBeUndefined();
    expect(lines('handoff.bank_half_open')).toEqual([expect.objectContaining({ level: 'info' })]);
    expect(lines('handoff.bank_back')).toEqual([]);
  });

  it('half-open allows 3 at once, not a fourth, one that ends without an unknown giving its place back', () => {
    tripped();
    looked();

    const three = [entered('x'), entered('y'), entered('z')];

    expect(health.heldFor('w')).toBe('bank');
    expect('hold' in health.enter('w')).toBe(true);
    three[0]?.settle('refused');
    expect(health.heldFor('w')).toBeUndefined();
    entered('w').settle('not_sent');
    expect(health.heldFor('w')).toBeUndefined();
  });

  it('half-open, one acceptance fully reopens it, said, the fourth place no more limited', () => {
    tripped();
    looked();

    accepted('x');

    expect(lines('handoff.bank_back')).toHaveLength(1);
    for (const org of ['p', 'q', 'r', 's', 't']) entered(org);
    expect(health.heldFor('w')).toBeUndefined();
  });

  it('half-open, a refusal doesn’t reopen it', () => {
    tripped();
    looked();

    entered('x').settle('refused');

    expect(lines('handoff.bank_back')).toEqual([]);
    const three = [entered('p'), entered('q'), entered('r')];
    expect(three).toHaveLength(3);
    expect(health.heldFor('w')).toBe('bank');
  });

  it('half-open, one unknown trips it again: the same outage, no new error, a lookup useless for its wait', () => {
    tripped();
    const outageOf = (entry: RailEntry) => ('outage' in entry ? entry.outage : -1);
    const outage = outageOf(health.enter('z'));
    looked();

    entered('x').settle('unknown');

    expect(health.heldFor('z')).toBe('bank');
    expect(outageOf(health.enter('z'))).toBe(outage);
    expect(lines('handoff.bank_held')).toHaveLength(1);
    looked();
    expect(health.heldFor('z')).toBe('bank');
    clock.advanceBy(MINUTE - 1);
    looked();
    expect(health.heldFor('z')).toBe('bank');
    clock.advanceBy(1);
    looked();
    expect(health.heldFor('z')).toBeUndefined();
  });

  it('counts no lookup begun before a trip again, either', () => {
    tripped();
    looked();
    const begun = health.lookupBegun('z');
    entered('x').settle('unknown');

    clock.advanceBy(MINUTE);
    begun();

    expect(health.heldFor('z')).toBe('bank');
  });

  it('grows the wait: 1, 2, 4, 8, 16, then 30 at most', () => {
    tripped();
    looked();
    entered('x').settle('unknown');
    for (const wait of [1, 2, 4, 8, 16, 30, 30]) {
      clock.advanceBy(wait * MINUTE - 1);
      looked();
      expect(health.heldFor('z')).toBe('bank');
      clock.advanceBy(1);
      looked();
      expect(health.heldFor('z')).toBeUndefined();
      entered(`x-${String(wait)}`).settle('unknown');
    }
    expect(lines('handoff.bank_held_again').map(({ waitMinutes }) => waitMinutes)).toEqual([
      1, 2, 4, 8, 16, 30, 30, 30,
    ]);
  });

  it('an acceptance resets the wait; the next outage is a new one, a new error', () => {
    tripped();
    looked();
    entered('x').settle('unknown');
    clock.advanceBy(MINUTE);
    looked();
    accepted('x');
    expect(health.heldFor('z')).toBeUndefined();

    // Fresh organisations' lanes clean: the next outage's trip.
    for (const org of ['p', 'q', 'r', 's', 't']) unknowns(org, 1);
    expect(lines('handoff.bank_held')).toHaveLength(2);
    looked();
    entered('u').settle('unknown');
    expect(lines('handoff.bank_held_again').at(-1)).toMatchObject({ waitMinutes: 1 });
  });

  it('gives nothing back to a later half-open for a call let through in an earlier one', () => {
    tripped();
    looked();
    const earlier = entered('x');
    entered('y').settle('unknown');
    clock.advanceBy(MINUTE);
    looked();
    const three = [entered('p'), entered('q'), entered('r')];

    earlier.settle('refused');

    expect(three).toHaveLength(3);
    expect(health.heldFor('w')).toBe('bank');
  });

  it('keeps an acceptance landing while held from reopening it: only half-open can', () => {
    const before = entered('x');
    tripped();

    before.settle('accepted');

    expect(health.heldFor('z')).toBe('bank');
    expect(lines('handoff.bank_back')).toEqual([]);
  });

  it('a half-down bank: lookups answering, payments hanging, costs few UNKNOWNs an hour', () => {
    tripped();
    let sent = 0;
    // A lookup a minute, as the bank check's own; every place taken, every call lost.
    for (let minute = 0; minute < 60; minute += 1) {
      clock.advanceBy(MINUTE);
      looked();
      const places: Exclude<RailEntry, { hold: unknown }>[] = [];
      for (let call = 0; call < 24; call += 1) {
        const entry = health.enter(`org-${String(call)}`);
        if (!('hold' in entry)) places.push(entry);
      }
      sent += places.length;
      for (const place of places) place.settle('unknown');
    }

    // Waits of 1, 2, 4, 8, 16, 30 fill the hour: at most 7 half-opens, 3 a time: not the 1,200-2,200 at 24 a time.
    expect(sent).toBeLessThanOrEqual(21);
    expect(sent).toBeGreaterThan(0);
    // One outage: one error for the trip, the rest the hold's lasting, once each 15 minutes.
    expect(lines('handoff.bank_held')).toHaveLength(1);
  });
});

describe('only a long hold is an error', () => {
  it('says nothing of a blip: tripped, half-open, reopened inside 15 minutes', () => {
    tripped();
    health.enter('z');
    clock.advanceBy(15 * MINUTE - 1);
    health.enter('z');
    looked();
    accepted('x');

    expect(lines('handoff.hold_lasting')).toEqual([]);
  });

  it('says a platform hold reached by a payment past 15 minutes, once, and again each 15 while it lasts', () => {
    tripped();
    clock.advanceBy(15 * MINUTE);

    health.enter('z');
    health.enter('y');
    expect(lines('handoff.hold_lasting')).toEqual([
      expect.objectContaining({ level: 'error', hold: 'held', minutes: 15 }),
    ]);

    clock.advanceBy(15 * MINUTE - 1);
    health.enter('z');
    expect(lines('handoff.hold_lasting')).toHaveLength(1);
    clock.advanceBy(1);
    health.enter('z');
    expect(lines('handoff.hold_lasting')).toHaveLength(2);
  });

  it('says half-open truly, when half-open is what holds it', () => {
    tripped();
    looked();
    entered('x');
    entered('y');
    entered('v');
    clock.advanceBy(15 * MINUTE);

    health.enter('z');

    expect(lines('handoff.hold_lasting')).toEqual([expect.objectContaining({ hold: 'half_open' })]);
  });

  it('never says a lane’s hold with nothing waiting on it, nor before 15 minutes; then for it alone', () => {
    unknowns('a', 3);
    clock.advanceBy(60 * MINUTE);
    expect(lines('handoff.hold_lasting')).toEqual([]);

    health.enter('a');
    health.enter('a');

    expect(lines('handoff.hold_lasting')).toEqual([
      expect.objectContaining({ level: 'error', hold: 'lane', orgId: 'a', minutes: 60 }),
    ]);
    expect(health.heldFor('a')).toBe('lane');
  });

  it('says a lane’s hold no sooner than 15 minutes from its start', () => {
    unknowns('a', 2);
    clock.advanceBy(60 * MINUTE);
    unknowns('a', 1);
    clock.advanceBy(15 * MINUTE - 1);

    health.enter('a');
    expect(lines('handoff.hold_lasting')).toEqual([]);

    clock.advanceBy(1);
    health.enter('a');
    expect(lines('handoff.hold_lasting')).toHaveLength(1);
  });

  it('says a lane’s lasting from the first hold, through holds that grow', () => {
    unknowns('a', 3);
    clock.advanceBy(5 * MINUTE);
    looked('a');
    entered('a').settle('unknown');
    clock.advanceBy(10 * MINUTE);

    health.enter('a');

    expect(lines('handoff.hold_lasting')).toEqual([expect.objectContaining({ minutes: 15 })]);
  });
});

describe('the rail, watched', () => {
  const REF = { organizationId: 'a', instructionId: 'i' };
  const railAnswering = (getExecution: FinancialRailAdapter['getExecution']) =>
    ({ identity: { partner: 'fake' }, getExecution }) as unknown as FinancialRailAdapter;

  it.each([
    ['not found', { kind: 'not_found' }],
    ['found', { kind: 'found', execution: {} }],
  ] as const)('tells the health a lookup answered, for its organisation: %s', async (_name, answer) => {
    unknowns('a', 3);
    clock.advanceBy(5 * MINUTE);
    const lookup = () => Promise.resolve(answer) as ReturnType<FinancialRailAdapter['getExecution']>;

    await expect(watchedRail(railAnswering(lookup), health).getExecution(REF)).resolves.toEqual(answer);

    expect(health.heldFor('a')).toBeUndefined();
  });

  it('begins it before the call: one under way at a trip proves nothing', async () => {
    unknowns('a', 2);
    unknowns('b', 2);
    const { promise, resolve } = Promise.withResolvers<{ readonly kind: 'not_found' }>();
    const under = watchedRail(
      railAnswering(() => promise),
      health,
    ).getExecution(REF);
    unknowns('c', 1);

    resolve({ kind: 'not_found' });
    await under;

    expect(health.heldFor('z')).toBe('bank');
  });

  it('tells it nothing for a lookup that didn’t answer', async () => {
    tripped();
    const lookup = () => Promise.reject(new RailUnavailable());

    await expect(watchedRail(railAnswering(lookup), health).getExecution(REF)).rejects.toThrow(RailUnavailable);

    expect(health.heldFor('z')).toBe('bank');
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

    const watched = watchedRail(new Adapter() as unknown as FinancialRailAdapter, health) as unknown as Adapter;

    expect(watched.nameOf()).toBe('adapter');
  });
});
