// GM-1b: a request's decision as the holdings check reads it, with the windows the windows' cutover named for one
// decided before GM-1b, from one read of its history (a fake of signed states' historyOf: no database).
import { describe, expect, it } from 'vitest';

import type { SignedStates } from '../../audit/index.ts';
import { decisionsRead } from './holdings-check.ts';

const ORG = '0199a0f0-0000-7000-8000-00000000b001';
const [OLD, NEW, NONE, BARE] = ['a', 'b', 'c', 'd'].map((n) => `0199a0f0-0000-7000-8000-00000000${n}001`) as [
  string,
  string,
  string,
  string,
];
const WINDOW = '0199a0f0-0000-8000-8000-00000000f001';
const SEALED = '0199a0f0-0000-8000-8000-00000000f002';
const AT = new Date('2026-10-08T08:00:00Z');

const event = (seq: number, subjectType: string, id: string, action: string, details: Record<string, unknown>) => ({
  id: `0199a0f0-0000-7000-8000-${String(seq).padStart(12, '0')}`,
  seq: BigInt(seq),
  recordedAt: AT,
  event: { actor: { type: 'system', id: 'api' }, action, subject: { type: subjectType, id, version: 1 }, details },
});
const HELD = { heldMonth: '2026-10', heldAt: AT.toISOString() };

describe("a decision's windows as the holdings check reads them", () => {
  it('takes those the cutover named for a decision before GM-1b, never over those a decision sealed or one holding nothing', async () => {
    const events = [
      event(1, 'spend_request', OLD, 'spend_request.decided', HELD),
      event(2, 'spend_request', NEW, 'spend_request.decided', { ...HELD, payeeWindows: SEALED }),
      event(3, 'spend_request', BARE, 'spend_request.decided', {}),
      event(4, 'spend_request_windows', OLD, 'spend_request.windows_named', { payeeWindows: WINDOW }),
      event(5, 'spend_request_windows', NEW, 'spend_request.windows_named', { payeeWindows: WINDOW }),
      event(6, 'spend_request_windows', NONE, 'spend_request.windows_named', { payeeWindows: WINDOW }),
      event(7, 'spend_request_windows', BARE, 'spend_request.windows_named', { payeeWindows: WINDOW }),
    ];
    const states = { historyOf: () => Promise.resolve({ outcome: 'read', events }) } as unknown as SignedStates;
    const read = await decisionsRead(null as never, states, ORG, [OLD, NEW, NONE, BARE]);
    if (read === 'tampered') throw new Error('read whole');
    expect(read.get(OLD)?.held?.windows).toEqual([WINDOW]);
    expect(read.get(NEW)?.held?.windows).toEqual([SEALED]);
    expect(read.has(NONE)).toBe(false);
    expect(read.get(BARE)?.held).toBeNull();
  });
});
