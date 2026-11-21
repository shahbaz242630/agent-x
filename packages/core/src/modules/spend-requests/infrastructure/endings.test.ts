// AT13d (review of #756): a request's capacity kept at its end once its sealed approval (or decision) is past what the
// signed states' digest remembers, an hour short of the digest's own margin so the two clocks never let one through.
import { describe, expect, it } from 'vitest';

import { DIGEST_FORGET_MARGIN_MS } from '../../audit/index.ts';
import { APPROVAL_HORIZON_MS } from '../domain/voids.ts';
import { money } from '../../../shared-kernel/index.ts';
import { capacityKept, capacityOf, heldIn, sealedAtOf } from './endings.ts';

const SEALED = new Date('2026-11-21T08:00:00.000Z');
const HOUR = 3_600_000;
/** When it is kept from: the horizon and the digest's margin, less an hour for the clocks. */
const FROM = APPROVAL_HORIZON_MS + DIGEST_FORGET_MARGIN_MS - HOUR;
const after = (ms: number) => new Date(SEALED.getTime() + ms);

describe('capacityKept', () => {
  it('is 7 days, a day and less an hour from the seal: as wide as the digest forgets, erring on keeping', () => {
    expect(FROM).toBe(7 * 24 * HOUR + 23 * HOUR);
    expect(DIGEST_FORGET_MARGIN_MS).toBe(24 * HOUR);
  });

  it.each([
    ['at its seal', 0, false],
    ['within the horizon', 6 * 24 * HOUR, false],
    ['past the horizon, the digest still remembering', APPROVAL_HORIZON_MS + HOUR, false],
    ['a millisecond short', FROM - 1, false],
    ['at the boundary', FROM, true],
    ['past it', FROM + 1, true],
    ['a month on', 30 * 24 * HOUR, true],
  ])('%s: %s', (_what, ms, kept) => {
    expect(capacityKept(SEALED, after(ms))).toBe(kept);
  });

  it('ages from the seal it is given, never the other way about', () => {
    expect(capacityKept(after(FROM), SEALED)).toBe(false);
  });
});

describe('heldIn and capacityOf: aged by the sealed times given, never the wall clock', () => {
  // In 2020, so a time taken from the wall clock anywhere would read years later, and nothing kept.
  const DECIDED = new Date('2020-03-01T08:00:00.000Z');
  const ENDED = new Date(DECIDED.getTime() + 8 * 24 * HOUR);
  const request = {
    id: '0199a0f0-0000-7000-8000-0000000000a1',
    agentId: '0199a0f0-0000-7000-8000-0000000000a2',
    supplierId: '0199a0f0-0000-7000-8000-0000000000a3',
    amount: money(60_000n, 'AED'),
    status: 'APPROVED' as const,
  };
  const decision = {
    held: { month: '2020-03', reservedAt: DECIDED, payee: 'none' as const, bankKeyed: true, windows: null },
    decidedAt: DECIDED,
    approvedAt: DECIDED,
  };
  const said: unknown[] = [];
  const states = { logger: { warn: (event: string, fields: unknown) => said.push([event, fields]) } } as never;

  it('keeps one sealed 8 days before its ending, and says so', () => {
    const held = heldIn('0199a0f0-0000-7000-8000-0000000000a0', request, decision);
    expect(held).toEqual([expect.objectContaining({ requestId: request.id, amount: 60_000n, sealedAt: DECIDED })]);
    const { giving, kept } = capacityOf(states, held, ENDED);
    expect(giving).toEqual([]);
    expect(kept).toEqual(held);
    expect(said).toEqual([['spend_request.capacity_kept', { requestId: request.id, sealedAt: DECIDED.toISOString() }]]);
  });

  it('gives back one sealed a day before its ending', () => {
    const held = heldIn('0199a0f0-0000-7000-8000-0000000000a0', request, decision);
    const { giving, kept } = capacityOf(states, held, new Date(DECIDED.getTime() + 24 * HOUR));
    expect(giving).toEqual(held);
    expect(kept).toEqual([]);
  });

  it('holds nothing for no decision, or one that sealed nothing', () => {
    expect(heldIn('0199a0f0-0000-7000-8000-0000000000a0', request, undefined)).toEqual([]);
    expect(heldIn('0199a0f0-0000-7000-8000-0000000000a0', request, { ...decision, held: null })).toEqual([]);
  });
});

describe('sealedAtOf', () => {
  const decision = { decidedAt: SEALED, approvedAt: after(5 * HOUR) };

  it('ages an approved or ready request by its sealed approval', () => {
    expect(sealedAtOf('APPROVED', decision)).toEqual(after(5 * HOUR));
    expect(sealedAtOf('INSTRUCTION_READY', decision)).toEqual(after(5 * HOUR));
  });

  it('ages one waiting for approval by its sealed decision, though an approval it was rolled back from was signed', () => {
    expect(sealedAtOf('APPROVAL_REQUIRED', decision)).toEqual(SEALED);
  });
});
