// A spend request (PRD §3 `SpendRequest`, §4.2, §5.2; BR-09; Phase 2 D1):
// what an agent asked to pay, and the decision made on it.
//
// The decision is made before the row is added (ADR-006 §7), so a request is
// born VALIDATING with its decision in it and moved by that decision in the
// same transaction: DENIED (DENY or REQUIRE_NEW_MANDATE), APPROVAL_REQUIRED or
// APPROVED. PRD's CREATED is the API's receipt, before any row. An approval
// waiting is approved, rejected, expired or cancelled; an approved request is
// made ready and handed off, or denied by the re-check before hand-off, or
// cancelled. After hand-off the outcome is its transaction's (PRD §4.2). The
// database's status guard holds the same moves (0039).
import { defineStateMachine } from '../../../shared-kernel/index.ts';

export const SPEND_REQUEST = defineStateMachine({
  name: 'spend_request',
  states: [
    'VALIDATING',
    'DENIED',
    'APPROVAL_REQUIRED',
    'APPROVED',
    'INSTRUCTION_READY',
    'HANDED_OFF',
    'EXPIRED',
    'CANCELLED',
  ],
  initial: 'VALIDATING',
  events: {
    deny: { from: ['VALIDATING', 'APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY'], to: 'DENIED' },
    require_approval: { from: ['VALIDATING'], to: 'APPROVAL_REQUIRED' },
    approve: { from: ['VALIDATING', 'APPROVAL_REQUIRED'], to: 'APPROVED' },
    expire: { from: ['APPROVAL_REQUIRED'], to: 'EXPIRED' },
    cancel: { from: ['APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY'], to: 'CANCELLED' },
    make_ready: { from: ['APPROVED'], to: 'INSTRUCTION_READY' },
    hand_off: { from: ['INSTRUCTION_READY'], to: 'HANDED_OFF' },
  },
});

export type SpendRequestStatus = (typeof SPEND_REQUEST.states)[number];
