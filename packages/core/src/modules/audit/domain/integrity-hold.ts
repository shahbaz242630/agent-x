// The integrity hold (ADR-012 §2): once anything of an organisation's is found
// tampered with, its hand-offs stop until its admin clears the hold with
// step-up, after the investigation is recorded (the clearing step is B3's).
// Tx A treats a hold like a freeze (ADR-007 §7).
//
// The hold is a signed state kept in the organisation's audit log alone, with
// no row: its status is its newest signed event, found in the log as every
// signed state is (latestSignedState). A row can be deleted or rolled back by
// someone past the app; an event only by breaking the chain, which the chain
// check and the anchor find. And the hold can be set whatever else has been
// tampered with, the organisation's own row included, because setting it only
// adds an event to the chain.
//
// It starts CLEAR, recorded when the organisation is created, so a log with no
// state for it is tampering too (its events deleted, or their seals
// stripped). Nothing but a verified CLEAR lets a hand-off through.
import { defineStateMachine } from '../../../shared-kernel/index.ts';

export const INTEGRITY_HOLD = defineStateMachine({
  name: 'integrity_hold',
  states: ['CLEAR', 'HELD'],
  initial: 'CLEAR',
  events: {
    hold: { from: ['CLEAR'], to: 'HELD' },
    clear: { from: ['HELD'], to: 'CLEAR' },
  },
});

/** The hold's subject type in the audit trail: one hold per organisation, under the organisation's own ID. */
export const HOLD_SUBJECT = 'integrity_hold';

/**
 * An investigation of a hold (B3+-2b): recorded by the organisation's admin
 * while it is HELD, as an event of its own, before the hold can be cleared.
 * Audit rows are kept for years and never changed, so it holds short facts
 * alone (event-facts.ts, ADR-014 §3): what the investigation concluded, and
 * the incident's reference where the full account is kept, outside Agent X.
 * Only the audit module records one, as it does the hold's own events.
 */
export const INVESTIGATION_SUBJECT = 'hold_investigation';

/**
 * What an investigation concluded: the cause was found and taken away (the
 * access that tampered revoked, say), or there was no tampering (a fault
 * raised the alarm). Either way clearing still checks every record first.
 */
export const INVESTIGATION_CONCLUSIONS = ['CAUSE_REMOVED', 'NO_TAMPERING'] as const;
export type InvestigationConclusion = (typeof INVESTIGATION_CONCLUSIONS)[number];

/** An incident's reference: a ticket's ID, never prose. */
const REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
export const INVESTIGATION_REFERENCE_MAX = 64;

/** Whether the text is an incident's reference: a letter or digit, then letters, digits, `.`, `_` or `-`, 64 at most. */
export const isIncidentReference = (text: unknown): text is string => typeof text === 'string' && REFERENCE.test(text);

/** Whether the text is one of the conclusions. */
export const isInvestigationConclusion = (text: unknown): text is InvestigationConclusion =>
  (INVESTIGATION_CONCLUSIONS as readonly unknown[]).includes(text);
