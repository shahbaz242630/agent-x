// A spend request's status (PRD §4.2; BR-09; Phase 2 D1): born VALIDATING
// with its decision and moved by it in the same transaction (`allow`,
// `require_approval` or `deny`); `approve` is the approver's alone. The
// database's status guard holds the same moves, and `decided_move` holds each
// request to its own decision (0039).
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
    allow: { from: ['VALIDATING'], to: 'APPROVED' },
    approve: { from: ['APPROVAL_REQUIRED'], to: 'APPROVED' },
    expire: { from: ['APPROVAL_REQUIRED'], to: 'EXPIRED' },
    cancel: { from: ['APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY'], to: 'CANCELLED' },
    make_ready: { from: ['APPROVED'], to: 'INSTRUCTION_READY' },
    hand_off: { from: ['INSTRUCTION_READY'], to: 'HANDED_OFF' },
  },
});

export type SpendRequestStatus = (typeof SPEND_REQUEST.states)[number];
