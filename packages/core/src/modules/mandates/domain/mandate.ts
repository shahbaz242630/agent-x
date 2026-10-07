// A mandate (PRD §3 `Mandate`, §4.1; ADR-006 §4; BR-05, BR-06): the spending
// authority an organisation gives one of its agents, across all the versions
// of its terms.
//
// Its status is PENDING_ACCEPTANCE until an admin accepts its first version
// with a passkey (B3), then ACTIVE. SUSPENDED is the brake, and back (B4).
// REVOKED ends it, a draft never accepted included; EXPIRED ends it when its
// version in force runs out. Superseding is not a move: a mandate stays ACTIVE
// with a new version in force, and the one it replaces is SUPERSEDED by being
// no longer current (PRD §4.1). The database's status guard holds the same
// moves (0035).
//
// The time zone its months are counted in and the split check's window are
// fixed when it is made (ADR-006 §4), so a later version can't move a period
// boundary.
import { defineStateMachine } from '../../../shared-kernel/index.ts';

export const MANDATE = defineStateMachine({
  name: 'mandate',
  states: ['PENDING_ACCEPTANCE', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED'],
  initial: 'PENDING_ACCEPTANCE',
  events: {
    accept: { from: ['PENDING_ACCEPTANCE'], to: 'ACTIVE' },
    suspend: { from: ['ACTIVE'], to: 'SUSPENDED' },
    resume: { from: ['SUSPENDED'], to: 'ACTIVE' },
    revoke: { from: ['PENDING_ACCEPTANCE', 'ACTIVE', 'SUSPENDED'], to: 'REVOKED' },
    expire: { from: ['ACTIVE', 'SUSPENDED'], to: 'EXPIRED' },
  },
});

export type MandateStatus = (typeof MANDATE.states)[number];

/** A draft waiting or a version in force: an agent has at most one mandate open (0035's `one_open_mandate_an_agent`). */
export const OPEN_STATES = ['PENDING_ACCEPTANCE', 'ACTIVE', 'SUSPENDED'] as const satisfies readonly MandateStatus[];

/** Revoked or expired: ended for good, it takes no new version. */
export const isEnded = (status: MandateStatus): boolean => !(OPEN_STATES as readonly MandateStatus[]).includes(status);

/** The split check's rolling window unless its owner sets another (ADR-006 §9): a day, so midnight can't be gamed. */
export const DEFAULT_SPLIT_WINDOW_HOURS = 24;

/** How long a split window may be: from an hour to 31 days (`windowStart`'s own bounds, A1). */
export const SPLIT_WINDOW_HOURS = { least: 1, most: 744 } as const;

/** The most suppliers one version's allow-list may name (B2). */
export const MOST_ALLOWED_SUPPLIERS = 100;

/** Whether a limit above the bank consent's is refused or allowed with a warning (partner, S86); strict unless chosen (S87). */
export const CONSENT_LIMITS = ['strict', 'flexible'] as const;
export type ConsentLimits = (typeof CONSENT_LIMITS)[number];
export const DEFAULT_CONSENT_LIMITS: ConsentLimits = 'strict';
