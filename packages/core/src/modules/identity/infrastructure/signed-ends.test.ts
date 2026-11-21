// The sessions' signed ends as the signed states' digest keeps them (AT13c): which platform events are an end, the
// object each is, and those that can't be read naming none. The reads held to it are in sessions-tamper.db.test.ts;
// that they give way first under memory is in apps/api's platform-subjects.test.ts.
import { describe, expect, it } from 'vitest';

import {
  EVERYONE,
  SESSION_ENDED,
  SESSION_ROTATED,
  sessionEndedEvent,
  sessionRotatedEvent,
  SESSIONS_ALL_ENDED,
  sessionsAllEndedEvent,
  SESSIONS_ENDED,
  sessionsEndedEvent,
  signedEndKey,
  signedEndSubjectOf,
} from './signed-ends.ts';

const PERSON = '0199A0F0-0000-7000-8000-0000000000A1';
const RECORD = '0199A0F0-0000-7000-8000-0000000000B1';
const AT = new Date('2026-11-21T09:00:00.000Z');
const subjectOf = (event: { readonly action: string; readonly details: unknown }) =>
  signedEndSubjectOf(event.action, JSON.stringify(event.details));

describe('a session’s signed ends as the digest keeps them (AT13c)', () => {
  it('names each end by the facts a session’s read matches it by, in lower case', () => {
    const person = PERSON.toLowerCase();
    const record = RECORD.toLowerCase();
    expect(subjectOf(sessionEndedEvent({ userId: PERSON, sessionId: RECORD }, AT))).toEqual([
      SESSION_ENDED,
      `${person}/${record}`,
    ]);
    const retired = { userId: PERSON, sessionId: RECORD, mac: Buffer.from('ABCD', 'hex') };
    expect(subjectOf(sessionRotatedEvent(retired, AT))).toEqual([SESSION_ROTATED, `${person}/${record}/abcd`]);
    expect(subjectOf(sessionsEndedEvent(PERSON, AT))).toEqual([SESSIONS_ENDED, person]);
    expect(signedEndKey.rotated(PERSON, RECORD, 'ABCD')).toBe(`${person}/${record}/abcd`);
  });

  it('names nothing for another action, details that are not an object, or an end missing a fact it is named by', () => {
    expect(signedEndSubjectOf('platform.handoff_paused', '{"person":"p"}')).toBeUndefined();
    expect(signedEndSubjectOf(SESSION_ENDED, 'not json')).toBeUndefined();
    expect(signedEndSubjectOf(SESSION_ENDED, 'null')).toBeUndefined();
    expect(signedEndSubjectOf(SESSIONS_ENDED, '{"person":5}')).toBeUndefined();
    expect(signedEndSubjectOf(SESSION_ENDED, '{"person":"p"}')).toBeUndefined();
    expect(signedEndSubjectOf(SESSION_ROTATED, '{"person":"p","record":"r"}')).toBeUndefined();
  });

  it('every session ended at once (AT13h) is one object, everyone, its record naming the cut it answers', () => {
    const held = { seq: 41n, hash: Buffer.alloc(32, 0xab) };
    const event = sessionsAllEndedEvent({ held, found: 38n }, AT);
    expect(event).toEqual({
      actor: { type: 'system', id: 'api' },
      action: SESSIONS_ALL_ENDED,
      details: {
        reason: 'platform_chain_cut',
        at: AT.toISOString(),
        seen: '41',
        seenHash: 'ab'.repeat(32),
        found: '38',
      },
    });
    expect(subjectOf(event)).toEqual([SESSIONS_ALL_ENDED, EVERYONE]);
    // No head found (its row gone): said so, never a place.
    expect(sessionsAllEndedEvent({ held, found: null }, AT).details.found).toBe('none');
    // Whatever its details, for the digest it is everyone's.
    expect(signedEndSubjectOf(SESSIONS_ALL_ENDED, 'not json')).toEqual([SESSIONS_ALL_ENDED, EVERYONE]);
  });
});
