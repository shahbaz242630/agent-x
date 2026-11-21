// How soon a committed write's chain head goes to the witness log (TR-1, @agentx/platform/audit-chain's witness-log.ts):
// `now`, before anyone is told the write succeeded, or `soon`, with the next flush a few seconds on.
//
// `now` is the default for every action, so an action added later is witnessed before its answer unless someone puts
// it here on purpose. `soon` is an explicit list of additive actions whose removal takes their effects with them: the
// agent's decision (the request made and decided, the month's total and payee windows held or opened with it, Section
// 2's order slot), and a payment's outcome moved by Tx B and the sweep. A cut of their events is a cut of the request
// or payment move itself, so no money or authority follows from it, and the decision path keeps no new trip (a stop's
// answer waits one Put; a decision's never does). Every stop, approval, rejection, member or policy change, hold,
// step-up, sign-out and platform write is `now`. A transaction is `now` if any of its events is.
import type { WitnessClass } from '@agentx/platform/audit-chain';

/**
 * The actions witnessed with the next flush. Never a stop, an approval or anything an admin relies on being kept: a
 * missing one is `now`, the safe side.
 */
export const WITNESSED_SOON: ReadonlySet<string> = new Set([
  // The agent's decision transaction (spend-request-decisions.ts, decisions.ts).
  'spend_request.received',
  'spend_request.decided',
  'month_total.opened',
  'month_total.held',
  'payee_window.opened',
  'payee_window.held',
  'order_slot.held',
  // A payment's outcome as Tx B and the sweep record it (handoff.ts, outcomes): cut, the payment reads as before the
  // move (SUBMISSION_PENDING, UNKNOWN), which the bank check settles; never resent.
  'transaction.submitted',
  'transaction.processing',
  'transaction.succeed',
  'transaction.lose_track',
  'transaction.provider_noted',
  'month_total.released',
  'payee_window.released',
]);

/** The class of a transaction's events on one chain: `soon` only where every one of them is on the list. */
export const witnessClassOf = (actions: readonly string[]): WitnessClass =>
  actions.length > 0 && actions.every((action) => WITNESSED_SOON.has(action)) ? 'soon' : 'now';

/** The stronger of two classes: a transaction is `now` if any of its writes is. */
export const strongerClass = (one: WitnessClass | undefined, other: WitnessClass): WitnessClass =>
  one === 'now' || other === 'now' ? 'now' : 'soon';
