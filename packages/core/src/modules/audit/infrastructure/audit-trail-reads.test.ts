// SEC-DB-20 TR-3: what a transaction's reads keep for the walk later in it to hold them to: each object's lowest
// signed place found (readBelowWalk), and each history read's filter and what it got (historyMissed). The attacks
// themselves (an event hidden while Tx A read, put back before its walk) are witness-gate.db.test.ts's.
import { subjectKey } from '@agentx/platform/audit-chain';
import { describe, expect, it } from 'vitest';

import {
  historyMissed,
  historyRead,
  type LatestSignedState,
  listRead,
  placeRead,
  readBelowWalk,
  type ReadEvent,
} from './audit-trail.ts';
import type { EventSeen } from './chain-frontier.ts';

const AGENT = '0199a0f0-0000-7000-8000-0000000000a1';
const OTHER = '0199a0f0-0000-7000-8000-0000000000a2';
const signedAt = (seq: bigint) => ({ kind: 'signed', seq }) as unknown as LatestSignedState;
const event = (seq: bigint, over: Partial<EventSeen> = {}): EventSeen => ({
  seq,
  id: `0199a0f0-0000-7000-8000-${seq.toString().padStart(12, '0')}`,
  subjectType: 'agent',
  subjectId: AGENT,
  action: 'agent.suspended',
  ...over,
});
const readOf = (seqs: readonly bigint[]) =>
  ({ kind: 'recorded', events: seqs.map((seq) => ({ seq }) as ReadEvent) }) as const;

describe('SEC-DB-20 TR-3 a transaction’s reads held to its walk', () => {
  it('keeps each object’s lowest place found: a later read that found more never covers one that found less', () => {
    const tx = {};
    placeRead(tx, 'agent', AGENT, signedAt(3n));
    placeRead(tx, 'agent', AGENT, signedAt(9n));
    expect(readBelowWalk(tx, new Map([[subjectKey('agent', AGENT), 9n]]))).toEqual([subjectKey('agent', AGENT), 9n]);
    // The positive control: read once, where the walk found it, stands; an object never read is no read's.
    const clean = {};
    placeRead(clean, 'agent', AGENT, signedAt(9n));
    placeRead(clean, 'agent', OTHER, { kind: 'none' });
    expect(readBelowWalk(clean, new Map([[subjectKey('agent', AGENT), 9n]]))).toBeUndefined();
    expect(readBelowWalk(clean, new Map([[subjectKey('agent', OTHER), 4n]]))).toEqual([subjectKey('agent', OTHER), 4n]);
    expect(readBelowWalk({}, new Map([[subjectKey('agent', AGENT), 9n]]))).toBeUndefined();
    // A read already broken keeps nothing (its own alarm stands).
    const broken = {};
    placeRead(broken, 'agent', AGENT, { kind: 'broken', seq: 2n });
    expect(readBelowWalk(broken, new Map([[subjectKey('agent', AGENT), 9n]]))).toBeUndefined();
  });

  it('holds a history read to the events it asked for: one it didn’t get, within its filter, is missed', () => {
    const tx = {};
    listRead(
      tx,
      {
        subjectTypes: ['agent'],
        subjectId: AGENT,
        actions: ['agent.suspended'],
        afterSeq: 5n,
        limit: 20,
        oldest: true,
      },
      readOf([]),
    );
    expect(historyMissed(tx, [event(7n)])).toEqual(event(7n));
    for (const outside of [
      event(4n),
      event(7n, { action: 'agent.reactivated' }),
      event(7n, { subjectId: OTHER }),
      event(7n, { subjectType: 'mandate' }),
    ]) {
      expect(historyMissed(tx, [outside])).toBeUndefined();
    }
    expect(historyMissed(tx, undefined)).toBeUndefined();
    expect(historyMissed({}, [event(7n)])).toBeUndefined();
    // Got it: not missed.
    const got = {};
    listRead(got, { subjectTypes: ['agent'], subjectIds: [AGENT.toUpperCase()], limit: 20 }, readOf([7n]));
    expect(historyMissed(got, [event(7n)])).toBeUndefined();
    expect(historyMissed(got, [event(8n)])).toEqual(event(8n));
    // A broken read keeps nothing.
    const broken = {};
    listRead(broken, { subjectTypes: ['agent'], limit: 20 }, { kind: 'broken', seq: 3n });
    expect(historyMissed(broken, [event(8n)])).toBeUndefined();
  });

  it('only as far as a partial read reached: the newest few down to the lowest got, the oldest few up to the highest', () => {
    const newest = {};
    listRead(newest, { subjectTypes: ['agent'], subjectId: AGENT, limit: 1, newest: true }, readOf([10n]));
    expect(historyMissed(newest, [event(8n)])).toBeUndefined();
    expect(historyMissed(newest, [event(12n)])).toEqual(event(12n));
    const oldest = {};
    listRead(oldest, { subjectTypes: ['agent'], subjectId: AGENT, limit: 1, oldest: true }, readOf([3n]));
    expect(historyMissed(oldest, [event(5n)])).toBeUndefined();
    expect(historyMissed(oldest, [event(2n)])).toEqual(event(2n));
    // Not full: it got all there were, so any it didn't get is missed.
    const all = {};
    listRead(all, { subjectTypes: ['agent'], subjectId: AGENT, limit: 5, newest: true }, readOf([10n]));
    expect(historyMissed(all, [event(8n)])).toEqual(event(8n));
  });

  it('an event read by its ID: that one alone, missed where it wasn’t got', () => {
    const tx = {};
    historyRead(tx, { eventId: event(9n).id, got: new Set() });
    expect(historyMissed(tx, [event(8n)])).toBeUndefined();
    expect(historyMissed(tx, [event(9n)])).toEqual(event(9n));
  });

  it('an object’s first event: missed where one before the one got (or any, where none was got) was hidden', () => {
    const got = {};
    historyRead(got, { types: new Set(['agent']), ids: new Set([AGENT]), upTo: 5n, got: new Set([5n]) });
    expect(historyMissed(got, [event(5n)])).toBeUndefined();
    expect(historyMissed(got, [event(7n)])).toBeUndefined();
    expect(historyMissed(got, [event(3n)])).toEqual(event(3n));
    const none = {};
    historyRead(none, { types: new Set(['agent']), ids: new Set([AGENT]), got: new Set() });
    expect(historyMissed(none, [event(7n)])).toEqual(event(7n));
  });
});
