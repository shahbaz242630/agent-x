// TR-2: who holds an order's slot, as its sealed text writes it, and what a request's slots say of its order.
import { describe, expect, it } from 'vitest';

import {
  type BankEntry,
  heldBy,
  holderIds,
  holdersFrom,
  holdersText,
  isOrderKind,
  letGo,
  MOST_BANK_ENTRIES,
  noHolders,
  SLOT_KINDS,
  slotsLook,
} from './order-slots.ts';

const A = '0199a0f0-0000-7000-8000-00000000000a';
const B = '0199a0f0-0000-7000-8000-00000000000b';
const C = '0199a0f0-0000-7000-8000-00000000000c';
const ONE = '1111111111111111';
const TWO = '2222222222222222';

/** The nth request's ID, for a bank slot filled to its limit. */
const nth = (n: number) => `0199a0f0-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;

const bank = (...entries: BankEntry[]) => ({ kind: 'bank' as const, entries });
const order = (holder: string | null) => ({ kind: 'order' as const, holder });

describe("a slot's holders", () => {
  it('names an order kind by one request or none, a bank kind by its entries', () => {
    expect(SLOT_KINDS.filter(isOrderKind)).toEqual(['supplier_order', 'payee_order']);
    expect(noHolders('supplier_order')).toEqual(order(null));
    expect(noHolders('payee_bank')).toEqual(bank());
  });

  it('reads back as written, and reads nothing the app never writes', () => {
    for (const holders of [order(null), order(A), bank(), bank({ orderHash: ONE, requestId: A })]) {
      const kind = holders.kind === 'order' ? 'payee_order' : 'supplier_bank';
      expect(holdersFrom(kind, holdersText(holders))).toEqual(holders);
    }
    expect(holdersFrom('supplier_order', 'not-a-request')).toBeUndefined();
    expect(holdersFrom('supplier_bank', `${ONE}:${A}:x`)).toBeUndefined();
    expect(holdersFrom('supplier_bank', `${ONE.slice(1)}:${A}`)).toBeUndefined();
    expect(holdersFrom('supplier_bank', `${ONE}:nobody`)).toBeUndefined();
    const full = Array.from({ length: MOST_BANK_ENTRIES + 1 }, (_, n) => `${ONE}:${nth(n)}`).join(',');
    expect(holdersFrom('payee_bank', full)).toBeUndefined();
  });

  it('takes an order slot for its first request alone; a second is told it is taken, the first again it holds', () => {
    const held = heldBy(order(null), { orderHash: ONE, requestId: A.toUpperCase() });
    expect(held).toEqual({ outcome: 'held', holders: order(A) });
    expect(heldBy(order(A), { orderHash: ONE, requestId: B })).toEqual({ outcome: 'taken' });
    expect(heldBy(order(A), { orderHash: ONE, requestId: A })).toEqual({ outcome: 'held', holders: order(A) });
  });

  it('lists a bank slot in one order whoever came first, each request once, and none past its limit', () => {
    const first = heldBy(bank(), { orderHash: TWO, requestId: B });
    const second = first.outcome === 'held' ? heldBy(first.holders, { orderHash: ONE, requestId: A }) : first;
    expect(second).toEqual({
      outcome: 'held',
      holders: bank({ orderHash: ONE, requestId: A }, { orderHash: TWO, requestId: B }),
    });
    const sameHash = heldBy(bank({ orderHash: ONE, requestId: C }), { orderHash: ONE, requestId: A });
    expect(sameHash).toEqual({
      outcome: 'held',
      holders: bank({ orderHash: ONE, requestId: A }, { orderHash: ONE, requestId: C }),
    });
    const listed = bank({ orderHash: ONE, requestId: A });
    expect(heldBy(listed, { orderHash: ONE, requestId: A })).toEqual({ outcome: 'held', holders: listed });
    const full = bank(...Array.from({ length: MOST_BANK_ENTRIES }, (_, n) => ({ orderHash: ONE, requestId: nth(n) })));
    expect(heldBy(full, { orderHash: TWO, requestId: nth(MOST_BANK_ENTRIES) })).toEqual({ outcome: 'full' });
  });

  it('lets go of the requests named, short where one let go did not hold it', () => {
    expect(letGo(order(A), [A])).toEqual({ holders: order(null), short: false });
    expect(letGo(order(A), [B])).toEqual({ holders: order(A), short: true });
    expect(letGo(order(null), [A])).toEqual({ holders: order(null), short: true });
    expect(letGo(order(A), [A, B])).toEqual({ holders: order(null), short: true });
    const two = bank({ orderHash: ONE, requestId: A }, { orderHash: TWO, requestId: B });
    expect(letGo(two, [B.toUpperCase()])).toEqual({ holders: bank({ orderHash: ONE, requestId: A }), short: false });
    expect(letGo(two, [A, B])).toEqual({ holders: bank(), short: false });
    expect(letGo(two, [C])).toEqual({ holders: two, short: true });
  });

  it('names every request it holds', () => {
    expect(holderIds(order(null))).toEqual([]);
    expect(holderIds(order(A))).toEqual([A]);
    expect(holderIds(bank({ orderHash: ONE, requestId: A }, { orderHash: TWO, requestId: B }))).toEqual([A, B]);
  });
});

describe("what a request's slots say of its order", () => {
  it('a duplicate where another holds the order; never its own, nor one left out', () => {
    expect(slotsLook([order(A)], { orderHash: ONE, except: [] })).toEqual({ duplicate: true, possible: false });
    expect(slotsLook([order(A)], { orderHash: ONE, except: [A.toUpperCase()] })).toEqual({
      duplicate: false,
      possible: false,
    });
    expect(slotsLook([order(null), order(B)], { orderHash: ONE, except: [A] })).toMatchObject({ duplicate: true });
  });

  it('a possible duplicate where a bank slot lists another order; never the same order, nor one left out', () => {
    expect(slotsLook([bank({ orderHash: TWO, requestId: B })], { orderHash: ONE, except: [] })).toEqual({
      duplicate: false,
      possible: true,
    });
    expect(slotsLook([bank({ orderHash: ONE, requestId: B })], { orderHash: ONE, except: [] })).toEqual({
      duplicate: false,
      possible: false,
    });
    expect(slotsLook([bank({ orderHash: TWO, requestId: B })], { orderHash: ONE, except: [B] })).toMatchObject({
      possible: false,
    });
  });

  it('a possible duplicate wherever a bank slot is full, a lookalike maybe past its list', () => {
    const full = bank(...Array.from({ length: MOST_BANK_ENTRIES }, (_, n) => ({ orderHash: ONE, requestId: nth(n) })));
    expect(slotsLook([full], { orderHash: ONE, except: [] })).toEqual({ duplicate: false, possible: true });
  });

  it('nothing for slots no one holds', () => {
    expect(slotsLook([order(null), bank()], { orderHash: ONE, except: [] })).toEqual({
      duplicate: false,
      possible: false,
    });
  });
});
