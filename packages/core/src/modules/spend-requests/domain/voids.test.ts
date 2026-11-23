// Why a pending spend request is void (Phase 3 C1, decisions 7 and 10): none while
// everything it was decided under stands; each brake its own cause, in the
// engine's order; several at once all kept; a supplier not found unverified,
// with no version to compare; a suspension that pauses voids nothing, and
// pauses only a suspension; the bank's own suspension never voids, consent
// it ended always does; new details a pause carries it through void nothing
// for themselves (E3); a stop chosen to cancel since its decision voids for
// good, whatever it is now, a pause in force too (decision 32a, F1 G1); an
// approval sealed APPROVAL_HORIZON_MS ago or more voids, one waiting never (AT13d).
import { describe, expect, it } from 'vitest';

import {
  APPROVAL_HORIZON_MS,
  approvalLapsed,
  type AuthorityNow,
  type DecidedUnder,
  isPending,
  isPendingChoice,
  type Pausable,
  VOID_CAUSES,
  voidCauses,
} from './voids.ts';

/** When each is judged. */
const AT = new Date('2026-11-21T08:00:00.000Z');

/** A request still waiting for approval: no approval to age. */
const DECIDED: DecidedUnder = { mandateId: 'm', mandateVersionId: 'mv1', supplierVersionId: 'sv1', approvedAt: null };

/** Approved `ms` before AT. */
const approvedAgo = (ms: number): DecidedUnder => ({ ...DECIDED, approvedAt: new Date(AT.getTime() - ms) });

const STANDING: AuthorityNow = {
  organizationStatus: 'ACTIVE',
  agentStatus: 'ACTIVE',
  mandate: { status: 'ACTIVE', currentVersionId: 'mv1', ended: false },
  source: { status: 'ACTIVE', availability: 'ACTIVE', consentPast: false, consentHeld: false },
  supplier: { status: 'VERIFIED', currentVersionId: 'sv1', pausedFrom: [] },
  paused: new Set(),
  cancelledBy: new Set(),
  at: AT,
};

const EVERY_PAUSED: ReadonlySet<Pausable> = new Set(['organization', 'agent', 'mandate', 'source', 'supplier']);

describe('voidCauses', () => {
  it('finds none while everything it was decided under stands', () => {
    expect(voidCauses(DECIDED, STANDING)).toEqual([]);
  });

  it('finds none for a request its mandate’s version in force still carries (PL-47), but one with no version', () => {
    const carrying = {
      ...STANDING,
      mandate: { status: 'ACTIVE', currentVersionId: 'mv2', carriesRest: true, ended: false },
    };
    expect(voidCauses(DECIDED, carrying)).toEqual([]);
    expect(voidCauses({ ...DECIDED, mandateVersionId: null }, carrying)).toEqual(['MANDATE_NOT_IN_FORCE']);
    // Still judged by everything else.
    expect(voidCauses(DECIDED, { ...carrying, agentStatus: 'SUSPENDED' })).toEqual(['AGENT_SUSPENDED']);
  });

  it.each([
    ['the organisation frozen', { organizationStatus: 'FROZEN' }, 'ORG_FROZEN'],
    ['the agent suspended', { agentStatus: 'SUSPENDED' }, 'AGENT_SUSPENDED'],
    [
      'the mandate suspended',
      { mandate: { status: 'SUSPENDED', currentVersionId: 'mv1', ended: false } },
      'MANDATE_NOT_IN_FORCE',
    ],
    [
      'the mandate revoked',
      { mandate: { status: 'REVOKED', currentVersionId: 'mv1', ended: false } },
      'MANDATE_NOT_IN_FORCE',
    ],
    [
      'the mandate superseded',
      { mandate: { status: 'ACTIVE', currentVersionId: 'mv2', ended: false } },
      'MANDATE_NOT_IN_FORCE',
    ],
    [
      'the mandate superseded, its version in force carrying no rest (PL-47)',
      { mandate: { status: 'ACTIVE', currentVersionId: 'mv2', carriesRest: false, ended: false } },
      'MANDATE_NOT_IN_FORCE',
    ],
    ['the mandate not found', { mandate: null }, 'MANDATE_NOT_IN_FORCE'],
    // Its version's end reached, still ACTIVE until the expiry job records it (SEC-AG-12, 6F1 G3).
    [
      'the mandate’s version in force past its end',
      { mandate: { status: 'ACTIVE', currentVersionId: 'mv1', ended: true } },
      'MANDATE_NOT_IN_FORCE',
    ],
    [
      'the source suspended',
      { source: { status: 'SUSPENDED', availability: 'ACTIVE', consentPast: false, consentHeld: false } },
      'SOURCE_NOT_USABLE',
    ],
    [
      'the source ended',
      { source: { status: 'ENDED', availability: 'ACTIVE', consentPast: false, consentHeld: false } },
      'SOURCE_NOT_USABLE',
    ],
    [
      'the source’s consent past',
      { source: { status: 'ACTIVE', availability: 'ACTIVE', consentPast: true, consentHeld: false } },
      'SOURCE_NOT_USABLE',
    ],
    [
      'the source’s consent ended by the bank',
      { source: { status: 'ACTIVE', availability: 'UNAVAILABLE', consentPast: false, consentHeld: false } },
      'SOURCE_NOT_USABLE',
    ],
    [
      'the supplier suspended',
      { supplier: { status: 'SUSPENDED', currentVersionId: 'sv1', pausedFrom: [] } },
      'SUPPLIER_SUSPENDED',
    ],
    [
      'the supplier unverified',
      { supplier: { status: 'UNVERIFIED', currentVersionId: 'sv1', pausedFrom: [] } },
      'SUPPLIER_NOT_VERIFIED',
    ],
    [
      'the supplier’s details changed',
      { supplier: { status: 'VERIFIED', currentVersionId: 'sv2', pausedFrom: [] } },
      'SUPPLIER_CHANGED',
    ],
    ['the supplier not found', { supplier: null }, 'SUPPLIER_NOT_VERIFIED'],
  ] as const)('finds %s', (_what, change: Partial<AuthorityNow>, cause) => {
    expect(voidCauses(DECIDED, { ...STANDING, ...change })).toEqual([cause]);
  });

  it.each([
    ['organization', 'ORG_FROZEN'],
    ['agent', 'AGENT_SUSPENDED'],
    ['mandate', 'MANDATE_NOT_IN_FORCE'],
    ['source', 'SOURCE_NOT_USABLE'],
    ['supplier', 'SUPPLIER_NOT_VERIFIED'],
  ] as const)('finds the %s cancelled since its decision, standing again now: %s (F1 G1)', (which, cause) => {
    expect(voidCauses(DECIDED, { ...STANDING, cancelledBy: new Set([which]) })).toEqual([cause]);
  });

  it('finds one cancelled since its decision though a pause is in force now (F1 G1)', () => {
    const frozen = { ...STANDING, organizationStatus: 'FROZEN', paused: EVERY_PAUSED };
    expect(voidCauses(DECIDED, frozen)).toEqual([]);
    expect(voidCauses(DECIDED, { ...frozen, cancelledBy: new Set(['organization'] as const) })).toEqual(['ORG_FROZEN']);
  });

  it('finds one whose mandate’s version ended though a pause or a carry would leave it standing (SEC-AG-12)', () => {
    const ended = { status: 'SUSPENDED', currentVersionId: 'mv1', ended: true };
    expect(voidCauses(DECIDED, { ...STANDING, mandate: ended, paused: EVERY_PAUSED })).toEqual([
      'MANDATE_NOT_IN_FORCE',
    ]);
    const carrying = { status: 'ACTIVE', currentVersionId: 'mv2', carriesRest: true, ended: true };
    expect(voidCauses(DECIDED, { ...STANDING, mandate: carrying })).toEqual(['MANDATE_NOT_IN_FORCE']);
  });

  it('finds one decided under no mandate never in force', () => {
    expect(voidCauses({ ...DECIDED, mandateId: null }, STANDING)).toEqual(['MANDATE_NOT_IN_FORCE']);
  });

  it('keeps every cause at once, in the engine’s order', () => {
    expect(
      voidCauses(approvedAgo(APPROVAL_HORIZON_MS), {
        organizationStatus: 'FROZEN',
        agentStatus: 'SUSPENDED',
        mandate: null,
        source: { status: 'SUSPENDED', availability: 'ACTIVE', consentPast: false, consentHeld: false },
        supplier: { status: 'UNVERIFIED', currentVersionId: 'sv2', pausedFrom: [] },
        paused: new Set(),
        cancelledBy: new Set(),
        at: AT,
      }),
    ).toEqual([
      'ORG_FROZEN',
      'AGENT_SUSPENDED',
      'MANDATE_NOT_IN_FORCE',
      'SOURCE_NOT_USABLE',
      'SUPPLIER_NOT_VERIFIED',
      'SUPPLIER_CHANGED',
      'APPROVAL_LAPSED',
    ]);
  });

  it('finds none for the bank’s own suspension of the source, and one once the bank ends its consent, paused or not', () => {
    const bank = (availability: string) => ({
      ...STANDING,
      source: { status: 'ACTIVE', availability, consentPast: false, consentHeld: false },
    });
    expect(voidCauses(DECIDED, bank('SUSPENDED'))).toEqual([]);
    expect(voidCauses(DECIDED, { ...bank('UNAVAILABLE'), paused: EVERY_PAUSED })).toEqual(['SOURCE_NOT_USABLE']);
  });

  it('finds none for consent run out on a source holding its requests until renewed (decision 21, E7)', () => {
    const source = (availability: string, consentPast: boolean, consentHeld: boolean, status = 'ACTIVE') => ({
      ...STANDING,
      source: { status, availability, consentPast, consentHeld },
    });
    // Past its end, by time alone or the bank's word on it (an expiry kept, updateFromPartner).
    expect(voidCauses(DECIDED, source('ACTIVE', true, true))).toEqual([]);
    expect(voidCauses(DECIDED, source('UNAVAILABLE', true, true))).toEqual([]);
    // Not held, or the consent gone before its end (revoked, consumed): void.
    expect(voidCauses(DECIDED, source('ACTIVE', true, false))).toEqual(['SOURCE_NOT_USABLE']);
    expect(voidCauses(DECIDED, source('UNAVAILABLE', false, true))).toEqual(['SOURCE_NOT_USABLE']);
    // A hold excuses the expiry only: the source ended, or suspended to cancel, still voids.
    expect(voidCauses(DECIDED, source('ACTIVE', true, true, 'ENDED'))).toEqual(['SOURCE_NOT_USABLE']);
    expect(voidCauses(DECIDED, source('ACTIVE', true, true, 'SUSPENDED'))).toEqual(['SOURCE_NOT_USABLE']);
    expect(voidCauses(DECIDED, { ...source('ACTIVE', true, true, 'SUSPENDED'), paused: new Set(['source']) })).toEqual(
      [],
    );
  });

  it.each([
    ['the organisation', 'organization', { organizationStatus: 'FROZEN' }],
    ['the agent', 'agent', { agentStatus: 'SUSPENDED' }],
    ['the mandate', 'mandate', { mandate: { status: 'SUSPENDED', currentVersionId: 'mv1', ended: false } }],
    [
      'the source',
      'source',
      { source: { status: 'SUSPENDED', availability: 'ACTIVE', consentPast: false, consentHeld: false } },
    ],
    ['the supplier', 'supplier', { supplier: { status: 'SUSPENDED', currentVersionId: 'sv1', pausedFrom: [] } }],
    // Decision 8: a payee registration's unverify, its requests paused by the registering admin.
    [
      'the supplier unverified',
      'supplier',
      { supplier: { status: 'UNVERIFIED', currentVersionId: 'sv1', pausedFrom: [] } },
    ],
  ] as const)(
    'finds none for %s suspended with its requests paused, and only its own pause counts',
    (_what, which, change: Partial<AuthorityNow>) => {
      expect(voidCauses(DECIDED, { ...STANDING, ...change, paused: new Set([which]) })).toEqual([]);
      const others = new Set([...EVERY_PAUSED].filter((each) => each !== which));
      expect(voidCauses(DECIDED, { ...STANDING, ...change, paused: others })).toHaveLength(1);
    },
  );

  it.each([
    [
      'the mandate revoked',
      { mandate: { status: 'REVOKED', currentVersionId: 'mv1', ended: false } },
      'MANDATE_NOT_IN_FORCE',
    ],
    [
      'the mandate expired',
      { mandate: { status: 'EXPIRED', currentVersionId: 'mv1', ended: false } },
      'MANDATE_NOT_IN_FORCE',
    ],
    [
      'the mandate superseded while paused',
      { mandate: { status: 'SUSPENDED', currentVersionId: 'mv2', ended: false } },
      'MANDATE_NOT_IN_FORCE',
    ],
    [
      'the source ended',
      { source: { status: 'ENDED', availability: 'ACTIVE', consentPast: false, consentHeld: false } },
      'SOURCE_NOT_USABLE',
    ],
    [
      'the source’s consent past while paused',
      { source: { status: 'SUSPENDED', availability: 'ACTIVE', consentPast: true, consentHeld: false } },
      'SOURCE_NOT_USABLE',
    ],
    [
      'the supplier’s details changed while paused',
      { supplier: { status: 'SUSPENDED', currentVersionId: 'sv2', pausedFrom: [] } },
      'SUPPLIER_CHANGED',
    ],
    [
      'the supplier’s new payee made current while paused unverified',
      { supplier: { status: 'UNVERIFIED', currentVersionId: 'sv2', pausedFrom: [] } },
      'SUPPLIER_CHANGED',
    ],
  ] as const)(
    'still finds %s, whatever is paused: a pause holds only its own stop',
    (_what, change: Partial<AuthorityNow>, cause) => {
      expect(voidCauses(DECIDED, { ...STANDING, ...change, paused: EVERY_PAUSED })).toEqual([cause]);
    },
  );

  describe('a supplier’s new details chosen to pause (E3)', () => {
    const carried = (status: string, pausedFrom: readonly string[]) => ({
      ...STANDING,
      supplier: { status, currentVersionId: 'sv3', pausedFrom },
    });

    it('finds none once it is verified again, its version carried through every change', () => {
      expect(voidCauses(DECIDED, carried('VERIFIED', ['sv2', 'sv1']))).toEqual([]);
    });

    it('finds its changed details for a version the current one doesn’t carry from', () => {
      expect(voidCauses(DECIDED, carried('VERIFIED', ['sv2']))).toEqual(['SUPPLIER_CHANGED']);
      expect(voidCauses(DECIDED, carried('VERIFIED', []))).toEqual(['SUPPLIER_CHANGED']);
    });

    it('still judges its status: unverified, only its own pause holds it', () => {
      expect(voidCauses(DECIDED, carried('UNVERIFIED', ['sv1']))).toEqual(['SUPPLIER_NOT_VERIFIED']);
      expect(voidCauses(DECIDED, { ...carried('UNVERIFIED', ['sv1']), paused: new Set(['supplier']) })).toEqual([]);
    });

    it('carries none decided under no supplier version', () => {
      expect(voidCauses({ ...DECIDED, supplierVersionId: null }, carried('VERIFIED', ['sv1']))).toEqual([
        'SUPPLIER_CHANGED',
      ]);
    });
  });
});

describe('VOID_CAUSES and the choice', () => {
  it('names every cause, each found when its own brake alone has stopped what a request was decided under', () => {
    const each = [
      voidCauses(DECIDED, { ...STANDING, organizationStatus: 'FROZEN' }),
      voidCauses(DECIDED, { ...STANDING, agentStatus: 'SUSPENDED' }),
      voidCauses(DECIDED, { ...STANDING, mandate: { status: 'REVOKED', currentVersionId: 'mv1', ended: false } }),
      voidCauses(DECIDED, { ...STANDING, source: { ...STANDING.source, status: 'SUSPENDED' } }),
      voidCauses(DECIDED, { ...STANDING, supplier: { status: 'UNVERIFIED', currentVersionId: 'sv1', pausedFrom: [] } }),
      voidCauses(DECIDED, { ...STANDING, supplier: { status: 'SUSPENDED', currentVersionId: 'sv1', pausedFrom: [] } }),
      voidCauses(DECIDED, { ...STANDING, supplier: { status: 'VERIFIED', currentVersionId: 'sv2', pausedFrom: [] } }),
      voidCauses(approvedAgo(APPROVAL_HORIZON_MS), STANDING),
    ];
    expect(each).toEqual(VOID_CAUSES.map((cause) => [cause]));
  });

  it('holds a request pending only before hand-off: waiting, approved or ready', () => {
    expect(
      (['APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY', 'HANDED_OFF', 'DENIED'] as const).map((status) =>
        isPending(status),
      ),
    ).toEqual([true, true, true, false, false]);
  });

  it('takes cancel or pause as a choice, and nothing else', () => {
    expect([
      isPendingChoice('cancel'),
      isPendingChoice('pause'),
      isPendingChoice('hold'),
      isPendingChoice(null),
    ]).toEqual([true, true, false, false]);
  });
});

describe('an approval past its horizon (AT13d)', () => {
  it('is seven days', () => {
    expect(APPROVAL_HORIZON_MS).toBe(7 * 24 * 3_600_000);
  });

  it.each([
    ['a moment old', 0, []],
    ['six days old', 6 * 24 * 3_600_000, []],
    ['a millisecond short of seven days', APPROVAL_HORIZON_MS - 1, []],
    ['seven days old exactly: lapsed, erring on refusing', APPROVAL_HORIZON_MS, ['APPROVAL_LAPSED']],
    ['a millisecond past', APPROVAL_HORIZON_MS + 1, ['APPROVAL_LAPSED']],
    ['eight days old', 8 * 24 * 3_600_000, ['APPROVAL_LAPSED']],
  ])('approved %s: %j', (_what, ago, causes) => {
    expect(voidCauses(approvedAgo(ago), STANDING)).toEqual(causes);
  });

  it('ages it to when it is judged, never a clock of its own', () => {
    const lapsed = approvedAgo(APPROVAL_HORIZON_MS);
    expect(voidCauses(lapsed, { ...STANDING, at: new Date(AT.getTime() - 1) })).toEqual([]);
    expect(approvalLapsed(new Date(0), new Date(APPROVAL_HORIZON_MS))).toBe(true);
    expect(approvalLapsed(new Date(1), new Date(APPROVAL_HORIZON_MS))).toBe(false);
  });

  it('never voids one waiting for approval, however old its decision: it expires by its own wait', () => {
    expect(voidCauses(DECIDED, { ...STANDING, at: new Date(AT.getTime() + 30 * APPROVAL_HORIZON_MS) })).toEqual([]);
  });

  it('is kept last, beside any other cause, in the engine’s order', () => {
    expect(voidCauses(approvedAgo(APPROVAL_HORIZON_MS), { ...STANDING, agentStatus: 'SUSPENDED' })).toEqual([
      'AGENT_SUSPENDED',
      'APPROVAL_LAPSED',
    ]);
  });
});
