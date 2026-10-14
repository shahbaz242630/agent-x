// Why a pending spend request is void (Phase 3 C1, decision 7): none while
// everything it was decided under stands; each brake its own cause, in the
// engine's order; several at once all kept; a supplier not found unverified,
// with no version to compare; a suspension that pauses voids nothing, and
// pauses only a suspension; the bank's own suspension never voids.
import { describe, expect, it } from 'vitest';

import { type AuthorityNow, type DecidedUnder, type Pausable, voidCauses } from './voids.ts';

const DECIDED: DecidedUnder = { mandateId: 'm', mandateVersionId: 'mv1', supplierVersionId: 'sv1' };

const STANDING: AuthorityNow = {
  agentStatus: 'ACTIVE',
  mandate: { status: 'ACTIVE', currentVersionId: 'mv1' },
  source: { status: 'ACTIVE', consentPast: false },
  supplier: { status: 'VERIFIED', currentVersionId: 'sv1' },
  paused: new Set(),
};

const EVERY_PAUSED: ReadonlySet<Pausable> = new Set(['agent', 'mandate', 'source', 'supplier']);

describe('voidCauses', () => {
  it('finds none while everything it was decided under stands', () => {
    expect(voidCauses(DECIDED, STANDING)).toEqual([]);
  });

  it.each([
    ['the agent suspended', { agentStatus: 'SUSPENDED' }, 'AGENT_SUSPENDED'],
    ['the mandate suspended', { mandate: { status: 'SUSPENDED', currentVersionId: 'mv1' } }, 'MANDATE_NOT_IN_FORCE'],
    ['the mandate revoked', { mandate: { status: 'REVOKED', currentVersionId: 'mv1' } }, 'MANDATE_NOT_IN_FORCE'],
    ['the mandate superseded', { mandate: { status: 'ACTIVE', currentVersionId: 'mv2' } }, 'MANDATE_NOT_IN_FORCE'],
    ['the mandate not found', { mandate: null }, 'MANDATE_NOT_IN_FORCE'],
    ['the source suspended', { source: { status: 'SUSPENDED', consentPast: false } }, 'SOURCE_NOT_USABLE'],
    ['the source ended', { source: { status: 'ENDED', consentPast: false } }, 'SOURCE_NOT_USABLE'],
    ['the source’s consent past', { source: { status: 'ACTIVE', consentPast: true } }, 'SOURCE_NOT_USABLE'],
    ['the supplier suspended', { supplier: { status: 'SUSPENDED', currentVersionId: 'sv1' } }, 'SUPPLIER_NOT_VERIFIED'],
    [
      'the supplier unverified',
      { supplier: { status: 'UNVERIFIED', currentVersionId: 'sv1' } },
      'SUPPLIER_NOT_VERIFIED',
    ],
    [
      'the supplier’s details changed',
      { supplier: { status: 'VERIFIED', currentVersionId: 'sv2' } },
      'SUPPLIER_CHANGED',
    ],
    ['the supplier not found', { supplier: null }, 'SUPPLIER_NOT_VERIFIED'],
  ] as const)('finds %s', (_what, change: Partial<AuthorityNow>, cause) => {
    expect(voidCauses(DECIDED, { ...STANDING, ...change })).toEqual([cause]);
  });

  it('finds one decided under no mandate never in force', () => {
    expect(voidCauses({ ...DECIDED, mandateId: null }, STANDING)).toEqual(['MANDATE_NOT_IN_FORCE']);
  });

  it('keeps every cause at once, in the engine’s order', () => {
    expect(
      voidCauses(DECIDED, {
        agentStatus: 'SUSPENDED',
        mandate: null,
        source: { status: 'SUSPENDED', consentPast: false },
        supplier: { status: 'UNVERIFIED', currentVersionId: 'sv2' },
        paused: new Set(),
      }),
    ).toEqual([
      'AGENT_SUSPENDED',
      'MANDATE_NOT_IN_FORCE',
      'SOURCE_NOT_USABLE',
      'SUPPLIER_NOT_VERIFIED',
      'SUPPLIER_CHANGED',
    ]);
  });

  it.each([
    ['the agent', 'agent', { agentStatus: 'SUSPENDED' }],
    ['the mandate', 'mandate', { mandate: { status: 'SUSPENDED', currentVersionId: 'mv1' } }],
    ['the source', 'source', { source: { status: 'SUSPENDED', consentPast: false } }],
    ['the supplier', 'supplier', { supplier: { status: 'SUSPENDED', currentVersionId: 'sv1' } }],
  ] as const)(
    'finds none for %s suspended with its requests paused, and only its own pause counts',
    (_what, which, change: Partial<AuthorityNow>) => {
      expect(voidCauses(DECIDED, { ...STANDING, ...change, paused: new Set([which]) })).toEqual([]);
      const others = new Set([...EVERY_PAUSED].filter((each) => each !== which));
      expect(voidCauses(DECIDED, { ...STANDING, ...change, paused: others })).toHaveLength(1);
    },
  );

  it.each([
    ['the mandate revoked', { mandate: { status: 'REVOKED', currentVersionId: 'mv1' } }, 'MANDATE_NOT_IN_FORCE'],
    ['the mandate expired', { mandate: { status: 'EXPIRED', currentVersionId: 'mv1' } }, 'MANDATE_NOT_IN_FORCE'],
    [
      'the mandate superseded while paused',
      { mandate: { status: 'SUSPENDED', currentVersionId: 'mv2' } },
      'MANDATE_NOT_IN_FORCE',
    ],
    ['the source ended', { source: { status: 'ENDED', consentPast: false } }, 'SOURCE_NOT_USABLE'],
    [
      'the source’s consent past while paused',
      { source: { status: 'SUSPENDED', consentPast: true } },
      'SOURCE_NOT_USABLE',
    ],
    [
      'the supplier unverified',
      { supplier: { status: 'UNVERIFIED', currentVersionId: 'sv1' } },
      'SUPPLIER_NOT_VERIFIED',
    ],
    [
      'the supplier’s details changed while paused',
      { supplier: { status: 'SUSPENDED', currentVersionId: 'sv2' } },
      'SUPPLIER_CHANGED',
    ],
  ] as const)(
    'still finds %s, whatever is paused: a pause holds only a suspension',
    (_what, change: Partial<AuthorityNow>, cause) => {
      expect(voidCauses(DECIDED, { ...STANDING, ...change, paused: EVERY_PAUSED })).toEqual([cause]);
    },
  );
});
