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

describe("a decision's order slots as the holdings check reads them (TR-2)", () => {
  it('takes those the cutover named for a decision before TR-2, never over those a decision sealed, and none for neither', async () => {
    const events = [
      event(1, 'spend_request', OLD, 'spend_request.decided', HELD),
      event(2, 'spend_request', NEW, 'spend_request.decided', { ...HELD, orderSlots: `${SEALED},${WINDOW}` }),
      event(3, 'spend_request', BARE, 'spend_request.decided', {}),
      event(4, 'spend_request_slots', OLD, 'spend_request.slots_named', { orderSlots: WINDOW }),
      event(5, 'spend_request_slots', NEW, 'spend_request.slots_named', { orderSlots: WINDOW }),
      event(6, 'spend_request_slots', NONE, 'spend_request.slots_named', { orderSlots: WINDOW }),
      // A decision before E1, holding no month, still holds its order: the cutover's naming stands for it.
      event(7, 'spend_request_slots', BARE, 'spend_request.slots_named', { orderSlots: WINDOW }),
    ];
    const states = { historyOf: () => Promise.resolve({ outcome: 'read', events }) } as unknown as SignedStates;
    const read = await decisionsRead(null as never, states, ORG, [OLD, NEW, NONE, BARE]);
    if (read === 'tampered') throw new Error('read whole');
    expect(read.get(OLD)?.slots).toEqual([WINDOW]);
    expect(read.get(NEW)?.slots).toEqual([SEALED, WINDOW]);
    expect(read.get(BARE)?.slots).toEqual([WINDOW]);
    // A naming with no decision read stands for nothing.
    expect(read.has(NONE)).toBe(false);
  });

  it('names none for a decision sealing text that is no list of slots, nor one never named', async () => {
    const events = [
      event(1, 'spend_request', OLD, 'spend_request.decided', { ...HELD, orderSlots: 'not,slots' }),
      event(2, 'spend_request', NEW, 'spend_request.decided', HELD),
    ];
    const states = { historyOf: () => Promise.resolve({ outcome: 'read', events }) } as unknown as SignedStates;
    const read = await decisionsRead(null as never, states, ORG, [OLD, NEW]);
    if (read === 'tampered') throw new Error('read whole');
    expect(read.get(OLD)?.slots).toBeNull();
    expect(read.get(NEW)?.slots).toBeNull();
  });
});

describe('when a request was approved, as its decision is read (AT13d)', () => {
  const at = (hours: number) => new Date(AT.getTime() + hours * 3_600_000);
  const timed = (seq: number, hours: number, id: string, action: string, subjectType = 'spend_request') => ({
    ...event(seq, subjectType, id, action, HELD),
    recordedAt: at(hours),
  });

  it('is its decision’s time, or a person’s approval after it; nothing else signed since (a carry) moves it', async () => {
    const asked: { actions?: readonly string[]; limit?: number }[] = [];
    const events = [
      timed(1, 0, OLD, 'spend_request.decided'),
      timed(2, 0, NEW, 'spend_request.decided'),
      timed(3, 5, NEW, 'spend_request.approved'),
      timed(4, 9, NEW, 'spend_request.carried'),
      // An approval of another object's, and one of a request with no decision read: neither dates anything.
      timed(5, 20, OLD, 'spend_request.approved', 'spend_request_windows'),
      timed(6, 30, NONE, 'spend_request.approved'),
    ];
    const states = {
      historyOf: (_tx: unknown, _org: string, find: { actions: readonly string[]; limit: number }) => {
        asked.push(find);
        return Promise.resolve({ outcome: 'read', events });
      },
    } as unknown as SignedStates;
    const read = await decisionsRead(null as never, states, ORG, [OLD, NEW, NONE]);
    if (read === 'tampered') throw new Error('read whole');
    expect(read.get(OLD)?.approvedAt).toEqual(at(0));
    expect(read.get(NEW)).toMatchObject({ decidedAt: at(0), approvedAt: at(5) });
    expect(read.has(NONE)).toBe(false);
    // Read on the decision's own trip: its approvals asked with it, room for one each.
    expect(asked).toEqual([
      expect.objectContaining({
        actions: [
          'spend_request.decided',
          'spend_request.approved',
          'spend_request.voided',
          'spend_request.expired',
          'spend_request.cancelled',
          'spend_request.rejected',
          'spend_request.windows_named',
          'spend_request.slots_named',
        ],
        limit: 8 * 3,
      }),
    ]);
  });

  it('reads a signed ending that kept its capacity, and only that: from the request’s own ending events', async () => {
    const ending = (
      seq: number,
      id: string,
      action: string,
      details: Record<string, unknown>,
      type = 'spend_request',
    ) => event(seq, type, id, action, details);
    const events = [
      ...[OLD, NEW, NONE, BARE].map((id, at) => timed(at + 1, 0, id, 'spend_request.decided')),
      ending(5, OLD, 'spend_request.voided', { causes: 'APPROVAL_LAPSED', capacityKept: true, keptAmountMinor: '1' }),
      ending(6, NEW, 'spend_request.expired', { capacityKept: 'true' }),
      ending(7, NONE, 'spend_request.carried', { capacityKept: true }),
      ending(8, BARE, 'spend_request.cancelled', { capacityKept: true }, 'spend_request_windows'),
    ];
    const states = { historyOf: () => Promise.resolve({ outcome: 'read', events }) } as unknown as SignedStates;
    const read = await decisionsRead(null as never, states, ORG, [OLD, NEW, NONE, BARE]);
    if (read === 'tampered') throw new Error('read whole');
    expect([OLD, NEW, NONE, BARE].map((id) => read.get(id)?.capacityKept)).toEqual([true, false, false, false]);
  });

  it.each(['spend_request.expired', 'spend_request.cancelled', 'spend_request.rejected'])(
    'reads it on %s too',
    async (action) => {
      const events = [
        timed(1, 0, OLD, 'spend_request.decided'),
        event(2, 'spend_request', OLD, action, { capacityKept: true }),
      ];
      const states = { historyOf: () => Promise.resolve({ outcome: 'read', events }) } as unknown as SignedStates;
      const read = await decisionsRead(null as never, states, ORG, [OLD]);
      if (read === 'tampered') throw new Error('read whole');
      expect(read.get(OLD)?.capacityKept).toBe(true);
    },
  );

  it('never moves back for an approval read before a later one', async () => {
    const events = [
      timed(1, 0, OLD, 'spend_request.decided'),
      timed(2, 8, OLD, 'spend_request.approved'),
      timed(3, 4, OLD, 'spend_request.approved'),
    ];
    const states = { historyOf: () => Promise.resolve({ outcome: 'read', events }) } as unknown as SignedStates;
    const read = await decisionsRead(null as never, states, ORG, [OLD]);
    if (read === 'tampered') throw new Error('read whole');
    expect(read.get(OLD)?.approvedAt).toEqual(at(8));
  });
});
