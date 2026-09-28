// The reset of a lost second factor (ADR-003 §4, ADR-012 §8; SEC-OPS-04):
// an admin asks, with a step-up, for another member whose second factor is
// lost (DRAFT, the pending change the step-up binds to; then
// AWAITING_CONTACT, once stepped up). One of the organisation's registered
// contacts that counts confirms it out of band, by the link it is sent
// (COOLING_OFF), and the factor is removed only once the cooling-off has
// passed (COMPLETED), so the people told have time to stop it: any admin may
// cancel until then (CANCELLED). A reset no contact confirms in time lapses
// (EXPIRED). The database's status guard holds the same moves (0025).
import { defineStateMachine } from '../../../shared-kernel/index.ts';

export const FACTOR_RESET = defineStateMachine({
  name: 'factor_reset',
  states: ['DRAFT', 'AWAITING_CONTACT', 'COOLING_OFF', 'COMPLETED', 'CANCELLED', 'EXPIRED'],
  initial: 'DRAFT',
  events: {
    ask_contacts: { from: ['DRAFT'], to: 'AWAITING_CONTACT' },
    confirm: { from: ['AWAITING_CONTACT'], to: 'COOLING_OFF' },
    complete: { from: ['COOLING_OFF'], to: 'COMPLETED' },
    cancel: { from: ['DRAFT', 'AWAITING_CONTACT', 'COOLING_OFF'], to: 'CANCELLED' },
    expire: { from: ['DRAFT', 'AWAITING_CONTACT'], to: 'EXPIRED' },
  },
});

export type FactorResetStatus = (typeof FACTOR_RESET.states)[number];

/** The statuses a reset is open in: a person has at most one reset in these at a time (B6-3b holds it). */
export const OPEN_RESET_STATUSES = [
  'DRAFT',
  'AWAITING_CONTACT',
  'COOLING_OFF',
] as const satisfies readonly FactorResetStatus[];

export const isOpenReset = (status: FactorResetStatus): boolean => OPEN_RESET_STATUSES.some((open) => open === status);

/** How long the contacts have to confirm, from the admin's ask. */
export const RESET_CONFIRM_HOURS = 72;

/** How long after a contact confirms the factor is removed: time for the people told to stop it. */
export const RESET_COOLING_OFF_HOURS = 24;

/**
 * The most resets an organisation's admins may ask for in any 24 hours,
 * drafts included (B8-2, S61). Every reset asked stays a record, and a check
 * reads a bounded number, so without this one admin asking and cancelling
 * could fill it in a minute and leave the organisation's resets unaskable
 * for good.
 */
export const MOST_RESETS_ASKED_A_DAY = 20;

const HOUR_MS = 3_600_000;

/** When a reset asked at `askedAt` lapses, if no contact has confirmed it. */
export const resetExpiresAt = (askedAt: Date): Date => new Date(askedAt.getTime() + RESET_CONFIRM_HOURS * HOUR_MS);

/** When the cooling-off of a reset confirmed at `confirmedAt` ends. */
export const resetCoolingOffUntil = (confirmedAt: Date): Date =>
  new Date(confirmedAt.getTime() + RESET_COOLING_OFF_HOURS * HOUR_MS);

/** Whether a reset that lapses at `expiresAt` may still be confirmed at `now`: strictly before it. */
export const confirmableAt = (expiresAt: Date, now: Date): boolean => now.getTime() < expiresAt.getTime();

/** Whether a reset has lapsed at `now`: still waiting for its admin or a contact, and past its lapse (B6-3b). */
export const hasLapsed = (
  reset: { readonly status: FactorResetStatus; readonly expiresAt: Date },
  now: Date,
): boolean => (reset.status === 'DRAFT' || reset.status === 'AWAITING_CONTACT') && !confirmableAt(reset.expiresAt, now);

/** Whether a reset is due to be carried out at `now`: cooling off, and its cooling-off passed. */
export const isDue = (
  reset: { readonly status: FactorResetStatus; readonly coolingOffUntil: Date | null },
  now: Date,
): boolean =>
  reset.status === 'COOLING_OFF' && reset.coolingOffUntil !== null && reset.coolingOffUntil.getTime() <= now.getTime();
