// Two modules' leavings as one (bothLeaving, AG7): the brakes, the reads and the ends of each, in order. The
// deactivation that runs them is membership-changes.db.test.ts; each leaving's own, its module's.
import type { Transaction } from 'kysely';
import { describe, expect, it } from 'vitest';

import type { SignedStates } from '../../audit/index.ts';
import { bothLeaving, type MemberLeaving } from './membership-changes.ts';

const LEAVING = { orgId: 'org-1', membershipId: 'member-1' };
const ACTOR = { type: 'user' as const, id: 'admin-1' };
const tx = {} as Transaction<never>;
const states = {} as SignedStates;

/** A leaving that notes, in `seen`, each step it is asked for. */
const noting = (
  name: string,
  seen: string[],
  { held = false, tampered = false }: { held?: boolean; tampered?: boolean } = {},
): MemberLeaving<object> => ({
  brakes: (_tx, leaving) => {
    seen.push(`${name} brakes ${leaving.membershipId}`);
    return Promise.resolve(held);
  },
  read: (_tx, _states, leaving) => {
    seen.push(`${name} read ${leaving.membershipId}`);
    if (tampered) return Promise.resolve({ outcome: 'tampered' });
    return Promise.resolve({
      outcome: 'read',
      end: (actor) => {
        seen.push(`${name} end by ${actor.id}`);
        return Promise.resolve();
      },
    });
  },
});

describe('two leavings as one (AG7)', () => {
  it('takes the brakes of each, the first’s first, held if either held any', async () => {
    for (const [first, second, held] of [
      [false, false, false],
      [true, false, true],
      [false, true, true],
    ] as const) {
      const seen: string[] = [];
      const both = bothLeaving(noting('a', seen, { held: first }), noting('b', seen, { held: second }));

      expect(await both.brakes(tx, LEAVING)).toBe(held);
      expect(seen).toEqual(['a brakes member-1', 'b brakes member-1']);
    }
  });

  it('reads both, then ends both in the same order, with the actor', async () => {
    const seen: string[] = [];
    const read = await bothLeaving(noting('a', seen), noting('b', seen)).read(tx, states, LEAVING);
    if (read.outcome !== 'read') throw new Error('not read');
    expect(seen).toEqual(['a read member-1', 'b read member-1']);

    await read.end(ACTOR);

    expect(seen.slice(2)).toEqual(['a end by admin-1', 'b end by admin-1']);
  });

  it('answers tampered when either read is, never reading on past the first', async () => {
    const firstSeen: string[] = [];
    expect(
      await bothLeaving(noting('a', firstSeen, { tampered: true }), noting('b', firstSeen)).read(tx, states, LEAVING),
    ).toEqual({ outcome: 'tampered' });
    expect(firstSeen).toEqual(['a read member-1']);

    const secondSeen: string[] = [];
    expect(
      await bothLeaving(noting('a', secondSeen), noting('b', secondSeen, { tampered: true })).read(tx, states, LEAVING),
    ).toEqual({ outcome: 'tampered' });
    expect(secondSeen).toEqual(['a read member-1', 'b read member-1']);
  });
});
