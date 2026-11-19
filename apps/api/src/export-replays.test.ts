// A download's retries and the record they read back (AG10). The count's own cases are my-activity.test.ts's (its
// build gate counts through it); the downloads that use both, the exports' DB tests.
import { describe, expect, it } from 'vitest';

import { createReplayCount, downloaderOf, madeBy } from './export-replays.ts';

const ADMIN = { orgId: '0199A0F0-0000-7000-8000-00000000A710', userId: '0199A0F0-0000-7000-8000-00000000A711' };
const recorded = (action: string, actor: { type: 'user' | 'system'; id: string }) => ({ event: { action, actor } });

describe('a download’s retries (AG10)', () => {
  it('counts an admin in an organisation as one, whatever the case, apart from the same person elsewhere', () => {
    expect(downloaderOf(ADMIN)).toBe(downloaderOf({ orgId: ADMIN.orgId.toLowerCase(), userId: ADMIN.userId }));
    expect(downloaderOf(ADMIN)).not.toBe(downloaderOf({ ...ADMIN, orgId: '0199a0f0-0000-7000-8000-00000000a712' }));
  });

  it('holds each downloader to five retries an hour, the sixth refused and not counted', () => {
    const replays = createReplayCount({ now: () => new Date('2026-11-19T09:00:00Z') });
    for (let made = 0; made < 5; made += 1) expect(replays.spent('a')).toBe(false);
    expect(replays.spent('a')).toBe(true);
    expect(replays.spent('b')).toBe(false);
    expect(replays.kept()).toBe(2);
  });

  it('builds a retry only from the admin’s own record of that download', () => {
    const own = { type: 'user' as const, id: ADMIN.userId.toLowerCase() };
    expect(madeBy(recorded('audit_log.exported', own), ADMIN, 'audit_log.exported')).toBe(true);
    expect(madeBy(undefined, ADMIN, 'audit_log.exported')).toBe(false);
    expect(madeBy(recorded('access_log.exported', own), ADMIN, 'audit_log.exported')).toBe(false);
    expect(madeBy(recorded('audit_log.exported', { ...own, type: 'system' }), ADMIN, 'audit_log.exported')).toBe(false);
    expect(madeBy(recorded('audit_log.exported', { ...own, id: ADMIN.orgId }), ADMIN, 'audit_log.exported')).toBe(
      false,
    );
  });
});
