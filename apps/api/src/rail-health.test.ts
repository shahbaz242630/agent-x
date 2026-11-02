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

  /** One step of reopening, every call it lets through accepted. */
  const stepAccepted = (calls: number) => {
    const places = Array.from({ length: calls }, (_, at) => entered(`step-${String(calls)}-${String(at)}`));
    for (const place of places) place.settle('accepted');
  };

  it('reopens in steps of 3, 6, 12, 24, each only when its calls have all ended, one accepted, none unknown', () => {
    tripped();
    looked();

    const first = [entered('p'), entered('q'), entered('r')];
    expect(health.heldFor('w')).toBe('bank');
    first[0]?.settle('accepted');
    first[1]?.settle('accepted');
    // A call of its step still out: the step isn't over, its places aren't refilled.
    expect(health.heldFor('w')).toBe('bank');
    first[2]?.settle('accepted');
    expect(lines('handoff.bank_step').map(({ calls }) => calls)).toEqual([6]);

    stepAccepted(6);
    expect(lines('handoff.bank_step').map(({ calls }) => calls)).toEqual([6, 12]);
    expect(health.heldFor('w')).toBeUndefined();
    stepAccepted(12);
    expect(lines('handoff.bank_step').map(({ calls }) => calls)).toEqual([6, 12, 24]);
    expect(lines('handoff.bank_back')).toEqual([]);
    stepAccepted(24);
    expect(lines('handoff.bank_back')).toHaveLength(1);
    // Open: no step limits it.
    const many = Array.from({ length: 40 }, (_, at) => entered(`open-${String(at)}`));
    expect(many).toHaveLength(40);
    expect(health.heldFor('w')).toBeUndefined();
  });

  it('holds each step to its own number of calls', () => {
    tripped();
    looked();
    stepAccepted(3);

    const six = Array.from({ length: 6 }, (_, at) => entered(`six-${String(at)}`));

    expect(health.heldFor('w')).toBe('bank');
    expect('hold' in health.enter('w')).toBe(true);
    expect(six).toHaveLength(6);
  });

  it('climbs a step on few calls where few are waiting: one accepted, nothing out', () => {
    tripped();
    looked();

    accepted('only');

    expect(lines('handoff.bank_step').map(({ calls }) => calls)).toEqual([6]);
  });

  it('goes back to held at any unknown in a later step, the same outage', () => {
    tripped();
    looked();
    stepAccepted(3);

    entered('x').settle('unknown');

    expect(health.heldFor('w')).toBe('bank');
    expect(lines('handoff.bank_held')).toHaveLength(1);
    expect(lines('handoff.bank_held_again')).toHaveLength(1);
  });

  it('a stale acceptance from before the trip clears its lane, and moves the platform nowhere', () => {
    const stale = entered('s');
    tripped();
    looked();
    const third = [entered('p'), entered('q'), entered('r')];

    stale.settle('accepted');

    expect(health.heldFor('w')).toBe('bank');
    expect(lines('handoff.bank_step')).toEqual([]);
    expect(lines('handoff.bank_back')).toEqual([]);
    expect(third).toHaveLength(3);
  });

  it('clears a lane at an acceptance begun before its hold', () => {
    const under = [entered('s'), entered('s'), entered('s'), entered('s')];
    for (const place of under.slice(0, 3)) place.settle('unknown');
    expect(health.heldFor('s')).toBe('lane');

    under[3]?.settle('accepted');

    expect(health.heldFor('s')).toBeUndefined();
    expect(health.oneAtATime('s')).toBe(false);
  });

  it('keeps a lookup answered during the wait, and goes half-open when the wait ends, with no lookup then', () => {
    tripped();
    looked();
    entered('x').settle('unknown');
    expect(health.heldFor('w')).toBe('bank');

    // Answered within its minute's wait.
    looked();
    expect(health.heldFor('w')).toBe('bank');
    clock.advanceBy(MINUTE - 1);
    expect(health.heldFor('w')).toBe('bank');

    clock.advanceBy(1);
    expect(health.heldFor('w')).toBeUndefined();
    expect(lines('handoff.bank_half_open')).toHaveLength(2);
  });

  it('keeps no lookup heard before a trip for the wait after it', () => {
    tripped();
    looked();
    entered('x').settle('unknown');
    looked();
    clock.advanceBy(MINUTE);
    entered('y').settle('unknown');
    clock.advanceBy(60 * MINUTE);

    expect(health.heldFor('w')).toBe('bank');
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

  /** Reopened all the way, a fresh organisation's calls accepted in each step. */
  const reopened = () => {
    for (const calls of [3, 6, 12, 24]) {
      const places = Array.from({ length: calls }, (_, at) => entered(`back-${String(calls)}-${String(at)}`));
      for (const place of places) place.settle('accepted');
    }
    expect(lines('handoff.bank_back').length).toBeGreaterThan(0);
  };

  const FRESH = ['p', 'q', 'r', 's', 't'];
  const tripAmong = () => {
    for (const org of FRESH) unknowns(org, 1);
  };

  it('a flapping bank stays one outage: a trip within 15 minutes of opening, no new error, its wait going on growing', () => {
    tripped();
    looked();
    entered('x').settle('unknown');
    clock.advanceBy(MINUTE);
    looked();
    reopened();

    clock.advanceBy(15 * MINUTE - 1);
    tripAmong();

    expect(health.heldFor('z')).toBe('bank');
    expect(lines('handoff.bank_held')).toHaveLength(1);
    expect(lines('handoff.bank_held_again').map(({ waitMinutes }) => waitMinutes)).toEqual([1, 2]);
  });

  it('keeps the hold’s lasting going through a flap: the same outage’s hold, said from its first trip', () => {
    tripped();
    looked();
    reopened();
    clock.advanceBy(14 * MINUTE);
    tripAmong();
    clock.advanceBy(MINUTE);

    health.enter('z');

    expect(lines('handoff.hold_lasting')).toEqual([expect.objectContaining({ minutes: 15 })]);
  });

  it('a new outage only after 15 healthy minutes: a new error, its wait started afresh', () => {
    tripped();
    looked();
    entered('x').settle('unknown');
    clock.advanceBy(MINUTE);
    looked();
    reopened();

    clock.advanceBy(15 * MINUTE);
    tripAmong();

    expect(lines('handoff.bank_held')).toHaveLength(2);
    // Open again at once on a lookup, its first wait none; its next trip waits a minute.
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

    // Neither a place given back, nor a step's acceptance.
    earlier.settle('refused');
    expect(health.heldFor('w')).toBe('bank');
    earlier.settle('accepted');

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

    // Waits of 1, 2, 4, 8, 16 and 30 fill the hour: 6 half-opens, 3 calls each, 18: not the 1,200-2,200 at 24 a time.
    expect(sent).toBeLessThanOrEqual(18);
    expect(sent).toBeGreaterThan(0);
    // One outage: one error for the trip, the rest the hold's lasting, once each 15 minutes.
    expect(lines('handoff.bank_held')).toHaveLength(1);
  });

  describe('a partly working bank, an hour of it', () => {
    interface Call {
      readonly at: number;
      readonly org: string;
      readonly place: Exclude<RailEntry, { hold: unknown }>;
      readonly word: 'accepted' | 'unknown';
    }

    /** The calls due by now ended, each told to the breaker: how many were lost. */
    function ended(out: Call[], perOrg: Map<string, number>, second: number): number {
      const due = out.filter(({ at }) => at <= second);
      for (const call of due) {
        out.splice(out.indexOf(call), 1);
        perOrg.set(call.org, (perOrg.get(call.org) ?? 1) - 1);
        call.place.settle(call.word);
      }
      return due.filter(({ word }) => word === 'unknown').length;
    }

    /** 30 organisations, up to 24 calls at once and 4 each; an acceptance in a second, a lost call in 30; lookups each minute. */
    function anHourAt(acceptance: number) {
      let seed = 7;
      const random = () => {
        seed = (seed * 1664525 + 1013904223) % 2 ** 32;
        return seed / 2 ** 32;
      };
      const out: Call[] = [];
      const perOrg = new Map<string, number>();
      let cursor = 0;
      let lost = 0;
      const start = (org: string, second: number) => {
        if ((perOrg.get(org) ?? 0) >= (health.oneAtATime(org) ? 1 : 4)) return;
        const entry = health.enter(org);
        if ('hold' in entry) return;
        const works = random() < acceptance;
        perOrg.set(org, (perOrg.get(org) ?? 0) + 1);
        out.push({ at: second + (works ? 1 : 30), org, place: entry, word: works ? 'accepted' : 'unknown' });
      };
      for (let second = 0; second < 3_600; second += 1) {
        clock.advanceBy(1_000);
        lost += ended(out, perOrg, second);
        if (second % 60 === 0) for (let org = 0; org < 30; org += 1) looked(`o${String(org)}`);
        for (let turn = 0; turn < 30 && out.length < 24; turn += 1) {
          start(`o${String(cursor % 30)}`, second);
          cursor += 1;
        }
      }
      return { lost, errors: lines('handoff.bank_held').length };
    }

    it.each([
      // Simulated (scratchpad sim.mjs): a tenth, a quarter and a half accepted, against 73, 308 and 653 lost before.
      [0.1, 60],
      [0.25, 60],
      [0.5, 100],
    ])('at %s accepted, loses few and raises one error', (acceptance, most) => {
      const { lost, errors } = anHourAt(acceptance);

      expect(lost).toBeLessThanOrEqual(most);
      expect(errors).toBeLessThanOrEqual(1);
    });

    it('a fair bank comes back to 24 in minutes, once it answers', () => {
      tripped();
      looked();
      // Each hand-off run, 10 s apart, its step's calls all accepted.
      for (const calls of [3, 6, 12, 24]) {
        clock.advanceBy(10_000);
        const places = Array.from({ length: calls }, (_, at) => entered(`fair-${String(calls)}-${String(at)}`));
        for (const place of places) place.settle('accepted');
      }

      expect(lines('handoff.bank_back')).toHaveLength(1);
    });
  });
});

describe('a bank that refuses everything', () => {
  /** `times` refusals from each organisation in turn. */
  const refusals = (orgs: readonly string[], times: number) => {
    for (let time = 0; time < times; time += 1) for (const org of orgs) entered(org).settle('refused');
  };

  it('says nothing of many refusals from two organisations: theirs, and real', () => {
    refusals(['a', 'b'], 20);

    expect(lines('handoff.bank_refusing')).toEqual([]);
  });

  it('says nothing of few across many', () => {
    refusals(['a', 'b', 'c'], 3);

    expect(lines('handoff.bank_refusing')).toEqual([]);
  });

  it('warns once of a run across three organisations with no acceptance; an error once it lasts; no hold on anyone', () => {
    refusals(['a', 'b', 'c'], 4);
    refusals(['a', 'b', 'c'], 4);
    expect(lines('handoff.bank_refusing')).toEqual([expect.objectContaining({ level: 'warn', organisations: 3 })]);

    clock.advanceBy(15 * MINUTE - 1);
    refusals(['a'], 1);
    expect(lines('handoff.bank_refusing')).toHaveLength(1);

    clock.advanceBy(1);
    refusals(['a'], 1);
    refusals(['a'], 1);
    expect(lines('handoff.bank_refusing').map(({ level }) => level)).toEqual(['warn', 'error']);
    expect(health.heldFor('a')).toBeUndefined();
  });

  it('starts the count again at any acceptance', () => {
    refusals(['a', 'b', 'c'], 3);
    accepted('d');
    refusals(['a', 'b', 'c'], 3);

    expect(lines('handoff.bank_refusing')).toEqual([]);

    refusals(['a', 'b', 'c'], 1);
    expect(lines('handoff.bank_refusing')).toHaveLength(1);
  });
});

describe('only a long hold is an error', () => {
  it('says no lasting hold of a blip: tripped, half-open, climbing inside 15 minutes', () => {
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
