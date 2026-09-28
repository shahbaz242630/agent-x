// A registered contact (ADR-012 §1, §8; SEC-OPS-06): an email address an
// organisation names as its trust anchor. Its contacts are told of the
// changes that matter, and they confirm a lost second factor's reset (B6-3).
//
// An admin adds one with step-up: it starts as a DRAFT, the pending change
// the step-up binds to (ADR-003 §9), and becomes ACTIVE once the step-up is
// consumed. It counts, for a reset's confirmation, only a cooling-off after
// that (default 7 days, ADR-012 §1), so contacts put in by someone who took
// over an admin's session count for nothing until the old ones have been told
// and had time to act. Removing one needs step-up too (ACTIVE>REMOVED); an
// address is never changed in place. The database's status guard holds the
// same moves (0022).
import { defineStateMachine } from '../../../shared-kernel/index.ts';

export const REGISTERED_CONTACT = defineStateMachine({
  name: 'registered_contact',
  states: ['DRAFT', 'ACTIVE', 'REMOVED'],
  initial: 'DRAFT',
  events: {
    activate: { from: ['DRAFT'], to: 'ACTIVE' },
    remove: { from: ['ACTIVE'], to: 'REMOVED' },
  },
});

/** How long a new contact waits before it counts (ADR-012 §1). */
export const CONTACT_COOLING_OFF_DAYS = 7;

/**
 * The most ACTIVE contacts an organisation may have at once: a short list of
 * people it trusts. A draft counts for nothing, so it isn't counted here;
 * MOST_CONTACTS_STARTED_A_DAY bounds how many are started.
 */
export const MOST_CONTACTS = 5;

/**
 * The most contacts an organisation may start adding in any 24 hours, drafts
 * included (B8-2, S61). Every contact started stays a record, and the list
 * reads a bounded number, so without this one admin could fill it in a
 * minute and leave the organisation's resets unaskable for good.
 */
export const MOST_CONTACTS_STARTED_A_DAY = 10;

/** When a contact made ACTIVE at `activatedAt` starts to count. */
export const contactCountsFrom = (activatedAt: Date): Date =>
  new Date(activatedAt.getTime() + CONTACT_COOLING_OFF_DAYS * 86_400_000);

/** Whether an ACTIVE contact that starts to count at `countsFrom` counts at `now`. */
export const counts = (countsFrom: Date, now: Date): boolean => countsFrom.getTime() <= now.getTime();

/**
 * Whether a contact counts at `now`, for confirming a reset (B6-3): ACTIVE,
 * with its start, and past it. A draft or a removed contact never does.
 */
export const countsNow = (contact: { readonly status: string; readonly countsFrom: Date | null }, now: Date): boolean =>
  contact.status === 'ACTIVE' && contact.countsFrom !== null && counts(contact.countsFrom, now);
