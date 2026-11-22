import { describe, expect, it } from 'vitest';

import { strongerClass, WITNESSED_SOON, witnessClassOf } from './witness-class.ts';

describe('SEC-DB-20 TR-1 how soon a write’s chain head is witnessed', () => {
  it('the agent’s decision transaction and a payment’s outcome moves go with the next flush', () => {
    expect(witnessClassOf(['spend_request.received', 'spend_request.decided'])).toBe('soon');
    expect(witnessClassOf(['month_total.held', 'payee_window.held', 'order_slot.held'])).toBe('soon');
    expect(witnessClassOf(['agent_zone.kept', 'spend_request.received', 'spend_request.decided'])).toBe('soon');
    expect(witnessClassOf(['transaction.submitted'])).toBe('soon');
    expect(witnessClassOf(['transaction.lose_track', 'month_total.released'])).toBe('soon');
  });

  it.each([
    'spend_request.approved',
    'spend_request.rejected',
    'supplier.suspended',
    'agent_key.revoked',
    'mandate.suspended',
    'agent.suspended',
    'organization.frozen',
    'spend_request.cancelled',
    'member.removed',
    'policy.changed',
    'integrity.hold_set',
    'handoff.paused',
    'instruction.made',
    'transaction.opened',
    'spend_request.made_ready',
    'transaction.fail',
    // A cutover opens a month or a window from signed requests: rare, and witnessed before it answers.
    'month_total.opened',
    'payee_window.opened',
  ])('%s, a stop, an approval or a hand-off’s own, is witnessed before its answer', (action) => {
    expect(witnessClassOf([action])).toBe('now');
  });

  it('an action no one listed is `now`, the safe side; a transaction is `now` if any of its events is', () => {
    expect(witnessClassOf(['something.new'])).toBe('now');
    expect(witnessClassOf(['spend_request.decided', 'supplier.suspended'])).toBe('now');
    // Nothing to judge: never taken for the decision path's.
    expect(witnessClassOf([])).toBe('now');
    expect(strongerClass(undefined, 'soon')).toBe('soon');
    expect(strongerClass('soon', 'now')).toBe('now');
    expect(strongerClass('now', 'soon')).toBe('now');
  });

  it('lists no stop: every listed action is additive, a decision’s or a payment move’s', () => {
    for (const action of WITNESSED_SOON) {
      expect(action).toMatch(
        /^(spend_request\.(received|decided)|agent_zone\.kept|month_total\.(held|released)|payee_window\.(held|released)|order_slot\.held|transaction\.)/,
      );
    }
  });
});
