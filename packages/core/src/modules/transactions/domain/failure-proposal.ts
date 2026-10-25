// An admin's proposal to mark an UNKNOWN payment failed (Phase 4 gate H10;
// partner decision 38 and its S145 heads-up: Agent X can't check the bank's
// reference an admin types, so a second admin confirms it). The database's
// status guard holds the same moves (0066).
//
// - `withdraw`: an admin, the proposer among them, takes it back.
// - `confirm`: a second admin (or a lone admin a day on) confirms it, and the
//   payment moves to FAILED in the same transaction.
// - `end`: the bank's answer settled the payment first (partner S145): closed
//   with that move, every admin told.
import { defineStateMachine } from '../../../shared-kernel/index.ts';

export const FAILURE_PROPOSAL = defineStateMachine({
  name: 'failure_proposal',
  states: ['OPEN', 'WITHDRAWN', 'CONFIRMED', 'ENDED'],
  initial: 'OPEN',
  events: {
    withdraw: { from: ['OPEN'], to: 'WITHDRAWN' },
    confirm: { from: ['OPEN'], to: 'CONFIRMED' },
    end: { from: ['OPEN'], to: 'ENDED' },
  },
});

export type FailureProposalStatus = (typeof FAILURE_PROPOSAL.states)[number];
export type FailureProposalEvent = Parameters<typeof FAILURE_PROPOSAL.transition>[1];
