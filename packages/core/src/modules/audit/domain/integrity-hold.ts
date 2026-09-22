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
