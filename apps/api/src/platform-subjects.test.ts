// The platform chain's signed states as the anchor check's walks name them for the digest (AT13c): the pause's moves
// and the sessions' signed ends, and nothing else; the ends grow with use, so under memory they give way before the
// pause does. Each read held to them is tested on the real tables (handoff-pause.db.test.ts, sessions-tamper.db.test.ts).
import { createDigestLog, subjectKey } from '@agentx/platform/audit-chain';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { platformSubjectOf } from './platform-subjects.ts';

const PERSON = '0199a0f0-0000-7000-8000-0000000000a1';
const RECORD = '0199a0f0-0000-7000-8000-0000000000b1';
const AT = new Date('2026-11-21T09:00:00.000Z');
const details = (facts: Record<string, string>) => JSON.stringify(facts);

describe('the platform chain’s signed states, as its walks name them (AT13c)', () => {
  it('names the pause’s moves and the sessions’ ends, and nothing else', () => {
    expect(platformSubjectOf('platform.handoff_paused', details({ reason: 'x' }))).toEqual([
      'platform.handoff_pause',
      'pause',
    ]);
    expect(platformSubjectOf('platform.handoff_resumed', details({ reason: 'x' }))).toEqual([
      'platform.handoff_pause',
      'pause',
    ]);
    expect(platformSubjectOf('identity.session_ended', details({ person: PERSON, record: RECORD }))).toEqual([
      'identity.session_ended',
      `${PERSON}/${RECORD}`,
    ]);
    expect(platformSubjectOf('identity.sessions_ended', details({ person: PERSON }))).toEqual([
      'identity.sessions_ended',
      PERSON,
    ]);
    expect(platformSubjectOf('organization.created', details({ orgId: PERSON }))).toBeUndefined();
  });

  it('the sessions’ ends grow with use: under memory they give way before the pause', () => {
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
    const seen = (action: string, facts: (at: number) => Record<string, string>, count: number) =>
      new Map(
        Array.from({ length: count }, (_, at) => {
          const [type, id] = platformSubjectOf(action, details(facts(at))) ?? ['', ''];
          return [subjectKey(type, id), BigInt(at + 2)];
        }),
      );
    digest.record(
      platform,
      seen('platform.handoff_paused', () => ({ reason: 'x' }), 1),
      AT,
    );
    const person = (at: number) => `0199a0f0-0000-7000-8000-${at.toString(16).padStart(12, '0')}`;
    digest.record(
      platform,
      seen('identity.session_ended', (at) => ({ person: PERSON, record: person(at) }), 150),
      AT,
    );
    digest.record(
      platform,
      seen('identity.session_rotated', (at) => ({ person: PERSON, record: person(at), retired: 'ab' }), 150),
      AT,
    );
    digest.record(
      platform,
      seen('identity.sessions_ended', (at) => ({ person: person(at) }), 150),
      AT,
    );
    expect(digest.latest(platform, 'platform.handoff_pause', 'pause')).toBe(2n);
    expect(digest.latest(platform, 'identity.session_ended', `${PERSON}/${person(0)}`)).toBeUndefined();
    expect(digest.latest(platform, 'identity.session_rotated', `${PERSON}/${person(0)}/ab`)).toBeUndefined();
    expect(digest.latest(platform, 'identity.sessions_ended', person(0))).toBeUndefined();
  });
});
