// Decision 18 (E5b): which refusals at approval reject the request (rules the
// team set) and which stay REQUEST_CHANGED (stops, perhaps a chosen pause),
// and the note the rejection keeps.
import { rejectReason } from '@agentx/core/modules/spend-requests';
import { describe, expect, it } from 'vitest';

import { rejectedFor, rejectionNote, WHAT_TO_DO, whatToDoFor } from './approval-rejections.ts';

const RULES = Object.keys(WHAT_TO_DO) as (keyof typeof WHAT_TO_DO)[];

describe('rejectedFor: what a refusal at approval rejects it for', () => {
  it.each(['ALLOW', 'REQUIRE_APPROVAL'] as const)('rejects nothing the engine still lets through: %s', (decision) => {
    expect(rejectedFor(decision, ['APPROVAL_THRESHOLD'])).toBeNull();
  });

  it('rejects it for a rule the team set', () => {
    expect(rejectedFor('DENY', ['POLICY_MONTHLY_CAP'])).toEqual(['POLICY_MONTHLY_CAP']);
  });

  it('names only the rules that refused it, not one that only asked for an approval', () => {
    expect(rejectedFor('REQUIRE_NEW_MANDATE', ['MANDATE_MONTHLY_LIMIT', 'APPROVAL_THRESHOLD'])).toEqual([
      'MANDATE_MONTHLY_LIMIT',
    ]);
  });

  it('rejects for a policy’s order cap when nothing else could have refused it', () => {
    expect(rejectedFor('DENY', ['POLICY_ORDER_CAP'])).toEqual(['POLICY_ORDER_CAP']);
  });

  it.each(['AGENT_SUSPENDED', 'SUPPLIER_NOT_VERIFIED', 'SOURCE_NOT_USABLE', 'MANDATE_NOT_IN_FORCE'] as const)(
    'never rejects for a stop, even beside a rule: %s (perhaps a pause the team chose)',
    (stop) => {
      expect(rejectedFor('DENY', [stop])).toBeNull();
      expect(rejectedFor('DENY', ['POLICY_MONTHLY_CAP', stop])).toBeNull();
    },
  );

  it('gives what to do for each rule, and nothing for any other reason', () => {
    for (const rule of RULES) expect(whatToDoFor(rule)).toBe(WHAT_TO_DO[rule]);
    expect(whatToDoFor('AGENT_SUSPENDED')).toBeNull();
  });
});

describe('rejectionNote: what the rejection keeps', () => {
  it('names the rules and what to do, as a reason a person could have given', () => {
    const note = rejectionNote(['POLICY_MONTHLY_CAP']);
    expect(note).toBe(
      'Rejected on approval: today’s check denies it under your team’s rules (POLICY_MONTHLY_CAP). Change them in settings, then the agent asks again.',
    );
    expect(rejectReason(note)).toEqual({ note, problems: [] });
  });

  it('leaves the codes out once they would make it too long, its event keeping them whole', () => {
    const note = rejectionNote(RULES);
    expect(note).not.toContain('POLICY');
    expect(rejectReason(note).problems).toEqual([]);
  });
});
