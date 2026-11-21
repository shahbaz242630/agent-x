// The sessions' signed ends as the signed states' digest keeps them (AT13c): which platform events are an end, the
// object each is, and those that can't be read naming none. The reads held to it are in sessions-tamper.db.test.ts.
import { createDigestLog, subjectKey } from '@agentx/platform/audit-chain';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import {
  SESSION_ENDED,
  SESSION_ROTATED,
  sessionEndedEvent,
  sessionRotatedEvent,
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

  it('each end grows with use: given way before the authority the digest keeps on the platform chain', () => {
    const keys = createKeyProvider(
      Object.fromEntries(
        PURPOSES.map((purpose, index) => [
          purpose,
          { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) },
        ]),
      ),
    );
    const digest = createDigestLog({
      keys,
      logger: testLogger(),
      now: () => AT,
      epoch: 1,
      alertAfterMs: 1,
      mostBytes: 12_000,
    });
    const platform = { kind: 'platform' } as const;
    digest.record(platform, new Map([[subjectKey('platform.handoff_pause', 'pause'), 1n]]), AT);
    for (const action of [SESSION_ENDED, SESSION_ROTATED, SESSIONS_ENDED]) {
      digest.record(
        platform,
        new Map(Array.from({ length: 150 }, (_, at) => [subjectKey(action, `p/${String(at)}`), BigInt(at + 2)])),
        AT,
      );
    }
    expect(digest.latest(platform, 'platform.handoff_pause', 'pause')).toBe(1n);
    for (const action of [SESSION_ENDED, SESSION_ROTATED, SESSIONS_ENDED]) {
      expect(digest.latest(platform, action, 'p/0')).toBeUndefined();
    }
  });
});
