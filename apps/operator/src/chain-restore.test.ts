// What the chain repair says after it (AT13f): a rebase only for a repair that took rows away or replaced them and
// still holds its anchor. The rows themselves are the DB tests' (chain-restore.db.test.ts); these are the outcomes a
// real copy can't readily give, such as one short of its anchor that also replaced rows.
import { describe, expect, it } from 'vitest';

import { outcomeLine, rebaseAfterLine, type RestoreOutcome } from './chain-restore.ts';

const ORG = '0199a0f0-0000-7000-8000-000000000001';
const REPAIR = '0199a0f0-0000-7000-8000-0000000000f1';
const END = { seq: 9n, hash: Buffer.alloc(32, 9), macKeyVersion: 1 };

/** A repaired outcome with the plan's parts a test names. */
const repaired = (plan: { rows: { action: string }[]; forkDiscarded: boolean; endsShortOf: bigint | null }) =>
  ({
    ok: true,
    plan: { ...plan, endsAt: END, head: undefined, liveHeadReplaced: undefined },
  }) as unknown as RestoreOutcome;

describe('AT13f the rebase a repair says it needs', () => {
  it.each([
    ['a row removed', [{ action: 'remove' }], false, true],
    ['a row replaced', [{ action: 'replace' }], false, true],
    ['a fork discarded', [], true, true],
    ['rows put back alone', [{ action: 'put_back' }], false, false],
  ])('%s, the anchor held: needed %s', (_what, rows, forkDiscarded, needed) => {
    const outcome = repaired({ rows, forkDiscarded, endsShortOf: null });
    expect(outcomeLine(outcome)).toMatchObject({ rebaseNeeded: needed });
    expect(rebaseAfterLine(outcome, { orgId: ORG, restoreId: REPAIR }) !== undefined).toBe(needed);
  });

  it('none for one short of its anchor, whatever it replaced: its own rebase (AT9) gives up the rest', () => {
    const outcome = repaired({ rows: [{ action: 'replace' }], forkDiscarded: true, endsShortOf: 20n });
    expect(outcomeLine(outcome)).toMatchObject({ rebaseNeeded: false, endsShortOf: '20' });
    expect(rebaseAfterLine(outcome, { orgId: ORG, restoreId: REPAIR })).toBeUndefined();
  });

  it('none for a repair refused', () => {
    expect(rebaseAfterLine({ ok: false, reason: 'moved' }, { orgId: ORG, restoreId: REPAIR })).toBeUndefined();
  });
});
