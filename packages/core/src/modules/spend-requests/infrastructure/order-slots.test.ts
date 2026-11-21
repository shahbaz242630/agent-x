// TR-2: an order slot as its signed read gives it, held to its own ID (no slot read under another's), and an order's
// slots as a decision names them (no database).
import { describe, expect, it, vi } from 'vitest';

import type { SignedStates, StateCheck } from '../../audit/index.ts';
import {
  checkOrderSlots,
  keyHashOf,
  MOST_SLOTS_CHECKED_A_PAGE,
  orderHashOf,
  orderSlotFrom,
  orderSlotId,
  type OrderSlotKey,
  orderSlotKeys,
  slotTakesOf,
} from './order-slots.ts';

const ORG = '0199a0f0-0000-7000-8000-00000000b001';
const SUPPLIER = '0199a0f0-0000-7000-8000-00000000a001';
const REQUEST = '0199a0f0-0000-7000-8000-00000000c001';
const KEY: OrderSlotKey = { kind: 'supplier_order', supplierId: SUPPLIER, payeeKey: null, keyHash: keyHashOf('inv-7') };

/** A verified read of a slot holding `fields`, as signed states give one. */
const verified = (fields: Record<string, string | null>): StateCheck => ({
  outcome: 'verified',
  version: 1,
  eventId: '0199a0f0-0000-7000-8000-00000000e001',
  recordedAt: new Date('2026-10-08T08:00:00Z'),
  fields: new Map(Object.entries(fields)),
});
const fieldsOf = (key: OrderSlotKey, holders: string) => ({
  kind: key.kind,
  supplier_id: key.supplierId,
  payee_key: key.payeeKey,
  key_hash: key.keyHash,
  holders,
  created_at: '2026-10-08T08:00:00.000000Z',
});
const statesWatching = () => {
  const mismatch = vi.fn();
  return { states: { mismatch } as unknown as SignedStates, mismatch };
};

describe('an order slot as read', () => {
  it('is held by who its seal says, under its own ID', () => {
    const { states, mismatch } = statesWatching();
    const read = orderSlotFrom(states, ORG, orderSlotId(ORG, KEY).toUpperCase(), verified(fieldsOf(KEY, REQUEST)));
    expect(read).toMatchObject({ outcome: 'held', key: KEY, holders: { kind: 'order', holder: REQUEST } });
    expect(mismatch).not.toHaveBeenCalled();
  });

  it("is refused and alarmed under another slot's ID, though its seal holds", () => {
    const { states, mismatch } = statesWatching();
    const other = { ...KEY, keyHash: keyHashOf('inv-8') };
    const id = orderSlotId(ORG, other);
    expect(orderSlotFrom(states, ORG, id, verified(fieldsOf(KEY, '')))).toEqual({ outcome: 'tampered', sign: 'row' });
    expect(mismatch).toHaveBeenCalledWith('order_slot', { orgId: ORG, id });
  });

  it('is none for no row and nothing signed, and tampered as its read said', () => {
    const { states } = statesWatching();
    expect(orderSlotFrom(states, ORG, orderSlotId(ORG, KEY), { outcome: 'missing' })).toEqual({ outcome: 'none' });
    expect(orderSlotFrom(states, ORG, orderSlotId(ORG, KEY), { outcome: 'tampered', sign: 'seal' })).toEqual({
      outcome: 'tampered',
      sign: 'seal',
    });
  });

  it('throws for a verified read naming no slot or holding text the app never writes (a bug, never data)', () => {
    const { states } = statesWatching();
    const id = orderSlotId(ORG, KEY);
    expect(() => orderSlotFrom(states, ORG, id, verified({ ...fieldsOf(KEY, ''), kind: 'nothing' }))).toThrow(
      'names no slot',
    );
    expect(() => orderSlotFrom(states, ORG, id, verified(fieldsOf(KEY, 'someone')))).toThrow('holds no holders');
  });
});

describe("an order's slots", () => {
  it("are its supplier's and its key's, by canonical form, then by bank key, each named by a hash", () => {
    const keys = orderSlotKeys({
      supplierId: SUPPLIER.toUpperCase(),
      payeeKey: 'payee-1',
      orderKey: 'inv-7',
      bankKey: 'inv7',
    });
    expect(keys).toEqual([
      { kind: 'supplier_order', supplierId: SUPPLIER, payeeKey: null, keyHash: keyHashOf('inv-7') },
      { kind: 'payee_order', supplierId: null, payeeKey: 'payee-1', keyHash: keyHashOf('inv-7') },
      { kind: 'supplier_bank', supplierId: SUPPLIER, payeeKey: null, keyHash: keyHashOf('inv7') },
      { kind: 'payee_bank', supplierId: null, payeeKey: 'payee-1', keyHash: keyHashOf('inv7') },
    ]);
    expect(keyHashOf('inv-7')).toMatch(/^[0-9a-f]{64}$/);
    expect(orderHashOf('inv-7')).toBe(keyHashOf('inv-7').slice(0, 16));
  });

  it('are its supplier and bank key alone with no payee key', () => {
    const keys = orderSlotKeys({ supplierId: SUPPLIER, payeeKey: null, orderKey: 'inv-7', bankKey: 'inv7' });
    expect(keys.map(({ kind }) => kind)).toEqual(['supplier_order', 'supplier_bank']);
  });

  it('are let go of as its decision named them, none for none', () => {
    expect(slotTakesOf(REQUEST.toUpperCase(), [orderSlotId(ORG, KEY).toUpperCase()])).toEqual([
      { id: orderSlotId(ORG, KEY), requestId: REQUEST },
    ]);
    expect(slotTakesOf(REQUEST, null)).toEqual([]);
  });
});

describe("the holdings check's page", () => {
  it('is 1 to its most slots, refused before any SQL runs', async () => {
    const { states } = statesWatching();
    for (const limit of [0, MOST_SLOTS_CHECKED_A_PAGE + 1, 1.5]) {
      await expect(checkOrderSlots(null as never, states, ORG, { after: null, limit })).rejects.toThrow(RangeError);
    }
  });
});
