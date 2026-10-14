// Why a pending spend request is void (Phase 3 C1): none while everything it
// was decided under stands; each brake its own cause, in the engine's order;
// several at once all kept; a supplier not found unverified, with no version
// to compare.
import { describe, expect, it } from 'vitest';

import { type AuthorityNow, type DecidedUnder, voidCauses } from './voids.ts';

const DECIDED: DecidedUnder = { mandateId: 'm', mandateVersionId: 'mv1', supplierVersionId: 'sv1' };

const STANDING: AuthorityNow = {
  agentStatus: 'ACTIVE',
  mandate: { status: 'ACTIVE', currentVersionId: 'mv1' },
  sourceMayFund: true,
  supplier: { status: 'VERIFIED', currentVersionId: 'sv1' },
};

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
    ['the source unable to fund', { sourceMayFund: false }, 'SOURCE_NOT_USABLE'],
    ['the supplier suspended', { supplier: { status: 'SUSPENDED', currentVersionId: 'sv1' } }, 'SUPPLIER_NOT_VERIFIED'],
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
        sourceMayFund: false,
        supplier: { status: 'UNVERIFIED', currentVersionId: 'sv2' },
      }),
    ).toEqual([
      'AGENT_SUSPENDED',
      'MANDATE_NOT_IN_FORCE',
      'SOURCE_NOT_USABLE',
      'SUPPLIER_NOT_VERIFIED',
      'SUPPLIER_CHANGED',
    ]);
  });
});
