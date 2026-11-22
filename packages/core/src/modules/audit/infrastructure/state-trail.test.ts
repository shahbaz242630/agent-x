// TR-3 residual 75 (S209): each tracked state event names its object's earlier events, and a history read is held to
// those names (trailGap). Each rule with the read it catches, and its positive control: a read that got them all.
import type { SignedStateTable } from '@agentx/platform/db';
import { describe, expect, it } from 'vitest';

import {
  newestCovered,
  type StateTrail,
  TRACKED_BEFORE,
  type TrackedBefore,
  trackedBeforeIn,
  type TrailEvent,
  trailGap,
  type TrailObject,
  withTracked,
  namedFromStart,
  namesFromHistory,
  NO_NAMES,
  historyNamedOf,
  namedAtOf,
} from './state-trail.ts';

const STOP = 'thing.stopped';
const LIFT = 'thing.lifted';
const TABLE: SignedStateTable = { table: 'things.things', subject: 'thing', fields: [], tracks: [STOP, LIFT] };
const UNTRACKED: SignedStateTable = { table: 'things.others', subject: 'other', fields: [] };
const ID = '0199a0f0-0000-7000-8000-000000000001';

/** The names a state event's details carry, as withTracked writes them. */
function named(start: Parameters<typeof withTracked>[1]): TrackedBefore | undefined {
  const { details } = withTracked(TABLE, start, {});
  const read = trackedBeforeIn(details);
  if (read === 'malformed') throw new Error('withTracked wrote names it cannot read');
  return read;
}

/** An event about the thing, its names as recorded from `start`. */
function eventAt(
  seq: bigint,
  version: number,
  action: string,
  start: Parameters<typeof withTracked>[1],
  id = ID,
): TrailEvent {
  return {
    seq,
    event: { action, subject: { type: 'thing', id, version }, details: withTracked(TABLE, start, {}).details },
  };
}

/** A thing's history: v1 made (seq 1), v2 stopped (seq 5), v3 lifted (seq 9), v4 stopped (seq 12), v5 noted (seq 20). */
function history() {
  const trailOf = (seq: bigint, action: string, tracked: TrackedBefore | undefined): StateTrail => ({
    seq,
    action,
    tracked,
  });
  const t1 = trailOf(1n, 'thing.made', named('new'));
  const t2 = trailOf(5n, STOP, named({ version: 1, trail: t1 }));
  const t3 = trailOf(9n, LIFT, named({ version: 2, trail: t2 }));
  const t4 = trailOf(12n, STOP, named({ version: 3, trail: t3 }));
  const t5 = trailOf(20n, 'thing.noted', named({ version: 4, trail: t4 }));
  const events = {
    stop1: eventAt(5n, 2, STOP, { version: 1, trail: t1 }),
    lift: eventAt(9n, 3, LIFT, { version: 2, trail: t2 }),
    stop2: eventAt(12n, 4, STOP, { version: 3, trail: t3 }),
  };
  const state: TrailObject = { table: TABLE, id: ID, version: 5, trail: t5 };
  return { events, state, t4 };
}

describe('the names a state event carries (withTracked, trackedBeforeIn)', () => {
  it('a table that tracks nothing gets none, its details as they were', () => {
    expect(withTracked(UNTRACKED, 'new', { a: 1 })).toEqual({ details: { a: 1 }, tracked: undefined });
  });

  it('refuses names given by a caller: they are added here alone', () => {
    expect(() => withTracked(TABLE, 'new', { [TRACKED_BEFORE]: '{}' })).toThrow(RangeError);
  });

  it('a new object names nothing earlier, complete from the start', () => {
    expect(named('new')).toEqual({ from: 0n, last: new Map() });
  });

  it('a first move names the event just before it, recorded in the same step (no seq yet), when tracked', () => {
    expect(named({ adjacent: { version: 1, action: STOP } })?.last.get(STOP)).toEqual({ version: 1, seq: null });
    expect(named({ adjacent: { version: 1, action: 'thing.made' } })?.last.size).toBe(0);
  });

  it('a state from before the names starts them at its own event; a state with none to give (a test’s) names none', () => {
    expect(named({ version: 3, trail: { seq: 40n, action: STOP, tracked: undefined } })).toEqual({
      from: 40n,
      last: new Map([[STOP, { version: 3, seq: 40n }]]),
    });
    expect(withTracked(TABLE, { version: 3 }, {}).details).toEqual({});
  });

  it('carries the names on, the state’s own action made the newest of its kind; an untracked action left out', () => {
    const { t4 } = history();
    expect(t4.tracked?.last).toEqual(
      new Map([
        [STOP, { version: 2, seq: 5n }],
        [LIFT, { version: 3, seq: 9n }],
      ]),
    );
    expect(named({ version: 5, trail: { seq: 20n, action: 'thing.noted', tracked: t4.tracked } })).toEqual(t4.tracked);
  });

  it.each([
    ['not text', { [TRACKED_BEFORE]: 7 }],
    ['not JSON', { [TRACKED_BEFORE]: '{' }],
    ['a seq that isn’t one', { [TRACKED_BEFORE]: '{"from":"-1","last":{}}' }],
    ['a version below 1', { [TRACKED_BEFORE]: '{"from":"0","last":{"a.b":[0,"1"]}}' }],
    ['more than the app writes', { [TRACKED_BEFORE]: '{"from":"0","last":{},"x":1}' }],
    ['not an object', { [TRACKED_BEFORE]: '[1,2]' }],
    ['names that aren’t an object', { [TRACKED_BEFORE]: '{"from":"0","last":[]}' }],
    ['a name that isn’t a pair', { [TRACKED_BEFORE]: '{"from":"0","last":{"a.b":[1]}}' }],
    ['a name whose seq isn’t one', { [TRACKED_BEFORE]: '{"from":"0","last":{"a.b":[1,"x"]}}' }],
    ['a name whose version isn’t whole', { [TRACKED_BEFORE]: '{"from":"0","last":{"a.b":[1.5,null]}}' }],
  ])('names that are %s are malformed', (_what, details) => {
    expect(trackedBeforeIn(details)).toBe('malformed');
  });

  it('an event from before the names carries none', () => {
    expect(trackedBeforeIn({})).toBeUndefined();
  });
});

/** Every stop and lift of the thing's history. */
const all = (h: ReturnType<typeof history>) => [h.events.stop1, h.events.lift, h.events.stop2];

describe('a history read held to the names (trailGap)', () => {
  it('the positive control: every stop and lift since the start got, nothing missing', () => {
    const h = history();
    expect(trailGap(all(h), [h.state], [STOP, LIFT], undefined)).toBeUndefined();
  });

  it('the newest stop the state names missing: the gap', () => {
    const h = history();
    expect(trailGap([h.events.stop1, h.events.lift], [h.state], [STOP, LIFT], undefined)).toEqual({
      table: TABLE,
      id: ID,
      action: STOP,
      version: 4,
    });
  });

  it('an older stop the next one names missing (residual 75): the gap; before the read’s start, none', () => {
    const h = history();
    expect(trailGap([h.events.lift, h.events.stop2], [h.state], [STOP, LIFT], undefined)).toMatchObject({
      action: STOP,
      version: 2,
    });
    expect(trailGap([h.events.lift, h.events.stop2], [h.state], [STOP, LIFT], 5n)).toBeUndefined();
  });

  it('the state’s own event, when of an action read, must be got too', () => {
    const h = history();
    const state: TrailObject = { ...h.state, version: 4, trail: h.t4 };
    expect(trailGap([h.events.stop1, h.events.lift], [state], [STOP, LIFT], undefined)).toMatchObject({
      action: STOP,
      version: 4,
    });
    expect(trailGap(all(h), [state], [STOP, LIFT], undefined)).toBeUndefined();
  });

  it('a first move’s name with no seq is the event just before it', () => {
    const first = eventAt(7n, 1, STOP, 'new');
    const moved = eventAt(8n, 2, LIFT, { adjacent: { version: 1, action: STOP } });
    const trail: StateTrail = {
      seq: 8n,
      action: LIFT,
      tracked: named({ adjacent: { version: 1, action: STOP } }),
    };
    const state: TrailObject = { table: TABLE, id: ID, version: 2, trail };
    expect(trailGap([first, moved], [state], [STOP, LIFT], undefined)).toBeUndefined();
    expect(trailGap([moved], [state], [STOP, LIFT], undefined)).toMatchObject({ action: STOP, version: 1 });
  });

  it('an event got that is newer than its object’s state, or whose names are malformed: a gap', () => {
    const h = history();
    const late = eventAt(30n, 6, STOP, { version: 5, trail: h.state.trail });
    expect(trailGap([...all(h), late], [h.state], [STOP, LIFT], undefined)).toMatchObject({ version: 6 });
    const broken: TrailEvent = {
      ...h.events.lift,
      event: { ...h.events.lift.event, details: { [TRACKED_BEFORE]: 'x' } },
    };
    expect(trailGap([h.events.stop1, broken, h.events.stop2], [h.state], [STOP, LIFT], undefined)).toMatchObject({
      action: LIFT,
    });
  });

  it('read as before where nothing is named: a state with no trail, an event from before the names, other objects', () => {
    const h = history();
    expect(trailGap([], [{ ...h.state, trail: undefined }], [STOP, LIFT], undefined)).toBeUndefined();
    const legacy: TrailEvent = { ...h.events.stop2, event: { ...h.events.stop2.event, details: {} } };
    const legacyState: TrailObject = {
      ...h.state,
      trail: {
        seq: 20n,
        action: 'thing.noted',
        tracked: { from: 12n, last: new Map([[STOP, { version: 4, seq: 12n }]]) },
      },
    };
    expect(trailGap([legacy], [legacyState], [STOP], undefined)).toBeUndefined();
    const other = eventAt(3n, 1, STOP, 'new', '0199a0f0-0000-7000-8000-000000000002');
    expect(trailGap([other, ...all(h)], [h.state], [STOP, LIFT], undefined)).toBeUndefined();
  });

  it('an action the table doesn’t track is never asked of it', () => {
    const h = history();
    expect(trailGap(all(h), [h.state], ['thing.noted'], undefined)).toBeUndefined();
    expect(trailGap([h.events.lift], [h.state], [LIFT], undefined)).toBeUndefined();
  });
});

describe('an object named from its whole history (namesFromHistory) and the cut-over (allNamed)', () => {
  it('names the newest of each tracked action, from the start; untracked actions left out', () => {
    const h = history();
    const other = eventAt(15n, 9, 'thing.noted', 'new');
    expect(namesFromHistory(TABLE, [h.events.stop2, h.events.stop1, h.events.lift, other])).toEqual({
      from: 0n,
      last: new Map([
        [STOP, { version: 4, seq: 12n }],
        [LIFT, { version: 3, seq: 9n }],
      ]),
    });
  });

  it('a state recorded again with them names exactly those, reaching its start', () => {
    const names = { from: 0n, last: new Map([[STOP, { version: 4, seq: 12n }]]) };
    expect(named({ rebuilt: names })).toEqual(names);
    expect(namedFromStart({ seq: 1n, action: STOP, tracked: names })).toBe(true);
    expect(namedFromStart({ seq: 1n, action: STOP, tracked: { from: 5n, last: new Map() } })).toBe(false);
    expect(namedFromStart({ seq: 1n, action: STOP, tracked: undefined })).toBe(false);
    expect(namedFromStart(undefined)).toBe(false);
  });

  it('a state with none from before its organisation was named (namedAt) is the gap; one after, or none named, isn’t', () => {
    const h = history();
    const bare: TrailObject = { ...h.state, trail: { seq: 20n, action: 'thing.noted', tracked: undefined } };
    expect(trailGap([], [bare], [], undefined, 21n)).toEqual({ table: TABLE, id: ID, action: NO_NAMES, version: 5 });
    // After the naming: the app's own older code (a copy draining, a rollback), read as before.
    expect(trailGap([], [bare], [], undefined, 20n)).toBeUndefined();
    expect(trailGap([], [bare], [], undefined, undefined)).toBeUndefined();
    expect(trailGap([], [{ ...h.state, trail: undefined }], [], undefined, 21n)).toBeUndefined();
    expect(trailGap(all(h), [h.state], [STOP, LIFT], undefined, 30n)).toBeUndefined();
  });

  it('where an organisation was named: its own history_named event, or the one its names point at; none before', () => {
    const ORG: SignedStateTable = { table: 'o.o', subject: 'org', fields: [], tracks: [historyNamedOf('org')] };
    expect(namedAtOf(ORG, { seq: 40n, action: 'org.history_named', tracked: undefined })).toBe(40n);
    const later = { from: 0n, last: new Map([['org.history_named', { version: 3, seq: 40n }]]) };
    expect(namedAtOf(ORG, { seq: 55n, action: 'org.frozen', tracked: later })).toBe(40n);
    const adjacent = { from: 0n, last: new Map([['org.history_named', { version: 3, seq: null }]]) };
    expect(namedAtOf(ORG, { seq: 55n, action: 'org.frozen', tracked: adjacent })).toBe(54n);
    expect(namedAtOf(ORG, { seq: 55n, action: 'org.frozen', tracked: { from: 0n, last: new Map() } })).toBeUndefined();
    expect(namedAtOf(ORG, undefined)).toBeUndefined();
  });
});

describe('where a newest-first read covers (newestCovered)', () => {
  it('everything when it got fewer than its limit; from its oldest on when full', () => {
    expect(newestCovered([{ seq: 4n }], 2)).toBeUndefined();
    expect(newestCovered([{ seq: 4n }, { seq: 9n }], 2)).toBe(3n);
    expect(newestCovered([], 0)).toBe(-1n);
  });
});
