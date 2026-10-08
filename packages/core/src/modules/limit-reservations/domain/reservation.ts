// A reservation's state (ADR-006 §8, §10; Phase 2 D2): HELD when reserved,
// BLOCKED_UNKNOWN while its payment's result is unknown (still holding the
// capacity), FINALISED on success and RELEASED on a deny, reject, expiry,
// cancel or verified failure. The database's `reservation_moves` holds the
// same moves (0040).
import { defineStateMachine } from '../../../shared-kernel/index.ts';

export const RESERVATION = defineStateMachine({
  name: 'reservation',
  states: ['HELD', 'FINALISED', 'RELEASED', 'BLOCKED_UNKNOWN'],
  initial: 'HELD',
  events: {
    finalise: { from: ['HELD', 'BLOCKED_UNKNOWN'], to: 'FINALISED' },
    release: { from: ['HELD', 'BLOCKED_UNKNOWN'], to: 'RELEASED' },
    block: { from: ['HELD'], to: 'BLOCKED_UNKNOWN' },
  },
});

export type ReservationState = (typeof RESERVATION.states)[number];
