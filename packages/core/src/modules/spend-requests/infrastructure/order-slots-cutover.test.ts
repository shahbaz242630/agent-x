// TR-2 review (R-15): the payee key the order slots' cutover counts a request under, settled from its decision's payee
// seal, never taken from a claim row on trust (no database).
import { createKeyProvider } from '@agentx/platform/keys';
import { describe, expect, it, vi } from 'vitest';

import type { SignedStates } from '../../audit/index.ts';
import { MOST_BANK_ENTRIES } from '../domain/order-slots.ts';

import type { Decided } from './holdings-check.ts';
import { sealedPayeeKey, slotsFilled, versionKeyOf } from './order-slots-cutover.ts';
import { sealPayee } from './payee-seal.ts';

const keys = createKeyProvider({ 'decision-hash': { current: 1, versions: new Map([[1, Buffer.alloc(32, 1)]]) } }, [
  'decision-hash',
]);
const ORG = '0199a0f0-0000-7000-8000-00000000e1b1';
const REQUEST = '0199a0f0-0000-7000-8000-00000000e1b2';
const AT = new Date('2026-10-08T08:00:00Z');

/** A holding request whose decision sealed `payee` (none: decided before E1b; null held: before E1). */
const holding = (payee: 'none' | 'unreadable' | { readonly key: string | null } | 'before E1') => {
  const seal =
    typeof payee === 'object' ? sealPayee(keys, { orgId: ORG, requestId: REQUEST, payeeKey: payee.key }) : payee;
  const decided = {
    held:
      payee === 'before E1' ? null : { month: '2026-10', reservedAt: AT, payee: seal, bankKeyed: true, windows: null },
  } as unknown as Decided;
  return { request: { id: REQUEST } as never, decided };
};
const settled = (
  payee: Parameters<typeof holding>[0],
  claims: (string | null)[],
  others: (string | null)[],
  versionKey?: string | null,
) => sealedPayeeKey(keys, ORG, holding(payee), { claims, others, versionKey });

describe('SEC-DB-21 a payee key sealed by its decision (E1b)', () => {
  it('is the key that holds to the seal, its claim the same or gone', () => {
    expect(settled({ key: 'payee-1' }, ['payee-1'], ['payee-1', 'payee-1'])).toBe('payee-1');
    // The claim deleted: its reservation's or its supplier's signed key stands for it.
    expect(settled({ key: 'payee-1' }, [], [null, 'payee-1'])).toBe('payee-1');
    expect(settled({ key: 'payee-1' }, [], ['payee-1', 'payee-2'])).toBe('payee-1');
  });

  it('is none for a seal of no key, its claim keyless too', () => {
    expect(settled({ key: null }, [null], [null, 'payee-2'])).toBeNull();
    expect(settled({ key: null }, [], [])).toBeNull();
  });

  it('is settled nowhere (the cutover stops) for a key found nowhere, a claim naming another, or a seal unreadable', () => {
    expect(settled({ key: 'payee-1' }, [], [null, null])).toBeUndefined();
    expect(settled({ key: 'payee-1' }, ['planted'], ['payee-1', 'payee-1'])).toBeUndefined();
    expect(settled({ key: null }, ['planted'], [null, null])).toBeUndefined();
    expect(settled('unreadable', ['payee-1'], ['payee-1', 'payee-1'])).toBeUndefined();
  });
});

describe('SEC-DB-21 a payee key decided before E1b (no seal)', () => {
  it('is the key its sealed supplier version paid, its claim the same, gone or keyless with it', () => {
    expect(settled('none', ['payee-1'], ['payee-2', 'payee-3'], 'payee-1')).toBe('payee-1');
    expect(settled('none', [], ['payee-2', 'payee-3'], 'payee-1')).toBe('payee-1');
    expect(settled('none', [null], ['payee-2', 'payee-3'], null)).toBeNull();
    expect(settled('before E1', [], [], null)).toBeNull();
  });

  it('is settled nowhere (the cutover stops) where its claim names another key than its version paid', () => {
    expect(settled('none', ['planted'], [], 'payee-1')).toBeUndefined();
    expect(settled('none', ['payee-1'], [], null)).toBeUndefined();
    expect(settled('before E1', [null], [], 'payee-1')).toBeUndefined();
  });

  it('is settled nowhere (the cutover stops) where no signed record keys its version, never by its claim', () => {
    expect(settled('none', ['payee-1'], ['payee-2', 'payee-3'])).toBeUndefined();
    expect(settled('none', [], [])).toBeUndefined();
    expect(settled('before E1', [null], [])).toBeUndefined();
  });
});

describe('SEC-DB-21 a sealed payee key held to its supplier version', () => {
  it('is found in the version it paid where its claim and reservation are gone', () => {
    expect(settled({ key: 'payee-1' }, [], [null, null], 'payee-1')).toBe('payee-1');
  });
});

describe('SEC-DB-21 the slots the requests fill at the cutover', () => {
  const SUPPLIER = '0199a0f0-0000-7000-8000-00000000a001';
  const requestOf = (n: number) => ({ id: `0199a0f0-0000-7000-8000-${n.toString(16).padStart(12, '0')}` }) as never;
  const order = (orderKey: string) => ({ supplierId: SUPPLIER, payeeKey: null, orderKey, bankKey: 'inv7' });
  const watching = () => {
    const mismatch = vi.fn();
    return { states: { mismatch } as unknown as SignedStates, mismatch };
  };

  it('stops, alarmed, where two requests hold one order', () => {
    const { states, mismatch } = watching();
    const filled = slotsFilled(states, ORG, [
      { request: requestOf(1), order: order('inv-7') },
      { request: requestOf(2), order: order('inv-7') },
    ]);
    expect(filled).toBe('tampered');
    expect(mismatch).toHaveBeenCalledTimes(1);
  });

  it('lists no more in a full bank slot, naming none past it there', () => {
    const { states } = watching();
    const many = Array.from({ length: MOST_BANK_ENTRIES + 1 }, (_, n) => ({
      request: requestOf(n + 1),
      order: order(`inv-${String(n)}`),
    }));
    const filled = slotsFilled(states, ORG, many);
    if (filled === 'tampered') throw new Error('filled whole');
    const last = requestOf(MOST_BANK_ENTRIES + 1) as unknown as { readonly id: string };
    // Its own order slot alone: the bank slot it shares was full.
    expect(filled.named.get(last.id)).toHaveLength(1);
    expect(filled.opening.size).toBe(MOST_BANK_ENTRIES + 2);
  });
});

describe("SEC-DB-21 a request's payee key by its supplier version", () => {
  const known = { now: new Map(), byVersion: new Map([['0199a0f0-0000-7000-8000-00000000f001', 'payee-1']]) };

  it('is the key its sealed version paid, undefined where no signed record says or it names none', () => {
    const at = (supplierVersionId: string | null) => ({ ...holding('none'), supplierVersionId });
    expect(versionKeyOf(known, at('0199A0F0-0000-7000-8000-00000000F001'))).toBe('payee-1');
    expect(versionKeyOf(known, at('0199a0f0-0000-7000-8000-00000000f002'))).toBeUndefined();
    expect(versionKeyOf(known, at(null))).toBeUndefined();
  });
});
