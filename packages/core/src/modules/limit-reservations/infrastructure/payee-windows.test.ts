// GM-1b: a payee window as its signed read gives it, the split read from a payee's rows, and the give-back's own
// refusals, none of which touch the database.
import { describe, expect, it } from 'vitest';

import type { SignedStates, VerifiedState } from '../../audit/index.ts';
import {
  checkPayeeWindows,
  heldWindowsGivenBack,
  type PayeeWindowCheck,
  payeeWindowFrom,
  splitHeldIn,
  splitHeldLess,
  windowsGivenBack,
} from './payee-windows.ts';

const SUPPLIER = '0199a0f0-0000-7000-8000-00000000a001';
const ID = '0199a0f0-0000-8000-8000-00000000c001';
const AT = new Date('2026-10-08T08:30:00Z');
const HOUR = Math.floor(AT.getTime() / 3_600_000);

const verified = (fields: Record<string, string | null>): VerifiedState => ({
  outcome: 'verified',
  version: 1,
  eventId: '0199a0f0-0000-7000-8000-00000000e001',
  recordedAt: AT,
  fields: new Map(Object.entries(fields)),
});
const held = (byHour: ReadonlyMap<number, bigint>): PayeeWindowCheck => ({
  outcome: 'held',
  held: byHour,
  key: { supplierId: SUPPLIER, payeeKey: null, currency: 'AED' },
  state: verified({}),
});
/** Never reached: these paths touch neither. */
const UNUSED = null as never;
const RECORDED = {
  at: AT,
  change: { actor: { type: 'system', id: 'api' }, action: 'payee_window.released', details: {} },
} as const;

describe('a payee window as read', () => {
  it('is what its sealed fields hold, none where there is no row, and a tamper sign as it came', () => {
    const read = payeeWindowFrom(
      verified({ supplier_id: SUPPLIER, payee_key: null, currency: 'AED', held_by_hour: `${String(HOUR)}:5` }),
    );
    expect(read).toMatchObject({
      outcome: 'held',
      held: new Map([[HOUR, 5n]]),
      key: { supplierId: SUPPLIER, payeeKey: null, currency: 'AED' },
    });
    expect(payeeWindowFrom({ outcome: 'missing' })).toEqual({ outcome: 'none' });
    expect(payeeWindowFrom({ outcome: 'tampered', sign: 'seal' })).toEqual({ outcome: 'tampered', sign: 'seal' });
  });

  it('refuses sealed hours the app never writes', () => {
    expect(() =>
      payeeWindowFrom(verified({ supplier_id: SUPPLIER, payee_key: null, currency: 'AED', held_by_hour: '2:1,1:1' })),
    ).toThrow('holds no hours');
  });
});

describe("a payee's split from its rows", () => {
  const rows = [
    held(new Map([[HOUR, 50n]])),
    held(
      new Map([
        [HOUR, 30n],
        [HOUR - 30, 7n],
      ]),
    ),
    held(new Map([[HOUR, 20n]])),
  ];

  it("is the supplier's and the key's, less the pair's, from the window's first hour; nothing for no row", () => {
    expect(splitHeldIn(rows, HOUR - 24)).toBe(60n);
    expect(splitHeldIn(rows, HOUR - 30)).toBe(67n);
    expect(splitHeldIn([rows[0] ?? held(new Map())], HOUR)).toBe(50n);
    expect(splitHeldIn([{ outcome: 'none' }], HOUR)).toBe(0n);
    expect(splitHeldIn([], HOUR)).toBe(0n);
  });

  it("leaves out the requests' own shares, in their windows and hours alone, short where a row holds less", () => {
    const ids = ['a', 'b', 'c'].map((letter) => ID.replace('c001', `${letter}001`));
    const named = rows.map((read, index) => ({ id: ids[index] ?? '', read }));
    const take = (id: string, hour: number, amount: bigint) => ({ id, requestId: ID, hour, amount });
    // A request in all three of the payee's rows: the union down by its amount.
    expect(
      splitHeldLess(
        named,
        HOUR - 24,
        ['a', 'b', 'c'].map((_, i) => take(ids[i] ?? '', HOUR, 10n)),
      ),
    ).toBe(50n);
    // One before the window, or in another row, takes nothing.
    expect(
      splitHeldLess(named, HOUR - 24, [
        take(ids[0] ?? '', HOUR - 30, 10n),
        take('0199a0f0-0000-8000-8000-00000000f001', HOUR, 10n),
      ]),
    ).toBe(60n);
    expect(splitHeldLess(named, HOUR - 24, [take(ids[0] ?? '', HOUR, 51n)])).toBe('short');
    expect(splitHeldLess([{ id: ID, read: { outcome: 'none' } }], HOUR, [])).toBe(0n);
    expect(splitHeldLess([], HOUR, [])).toBe(0n);
  });
});

describe('a give-back refused before the database is touched', () => {
  it('gives nothing back for a request holding none', async () => {
    await expect(heldWindowsGivenBack(UNUSED, UNUSED, ID, null, RECORDED)).resolves.toBeUndefined();
    await expect(heldWindowsGivenBack(UNUSED, UNUSED, ID, undefined, RECORDED)).resolves.toBeUndefined();
  });

  it('refuses a window not read for change, and leaves one tampered with (its read raised the alarm)', async () => {
    const take = [{ id: ID, requestId: ID, hour: HOUR, amount: 5n }];
    await expect(windowsGivenBack(UNUSED, UNUSED, ID, new Map(), take, RECORDED)).rejects.toThrow(
      'not read for change',
    );
    const tampered = new Map<string, PayeeWindowCheck>([[ID, { outcome: 'tampered', sign: 'seal' }]]);
    await expect(windowsGivenBack(UNUSED, UNUSED, ID, tampered, take, RECORDED)).resolves.toBeUndefined();
  });

  it('refuses a holdings-check page out of bounds before any SQL runs', async () => {
    for (const limit of [0, 201, 1.5]) {
      await expect(
        checkPayeeWindows(UNUSED, UNUSED as SignedStates, ID, { after: null, limit, at: AT }),
      ).rejects.toThrow(RangeError);
    }
  });
});
