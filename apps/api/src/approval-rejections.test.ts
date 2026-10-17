// Decision 18 (E5b): which refusals at approval reject the request (rules the
// team set) and which stay REQUEST_CHANGED (stops, perhaps a chosen pause),
// and the note the rejection keeps.
import { rejectReason } from '@agentx/core/modules/spend-requests';
import { describe, expect, it } from 'vitest';

import { rejectedFor, rejectionNote } from './approval-rejections.ts';

const RULES = [
  'MANDATE_ORDER_LIMIT',
  'MANDATE_MONTHLY_LIMIT',
  'POLICY_ORDER_CAP',
  'POLICY_MONTHLY_CAP',
  'ORG_MONTHLY_CAP_NOT_SET',
  'POLICY_SUPPLIER_NOT_ALLOWED',
  'CURRENCY_NOT_ALLOWED',
  'DUPLICATE_ORDER_REFERENCE',
] as const;

describe('rejectedFor: what a refusal at approval rejects it for', () => {
  it.each(['ALLOW', 'REQUIRE_APPROVAL'] as const)('rejects nothing the engine still lets through: %s', (decision) => {
    expect(rejectedFor(decision, ['APPROVAL_THRESHOLD'])).toBeNull();
  });

  it('rejects nothing for a refusal that names no reason', () => {
    expect(rejectedFor('DENY', [])).toBeNull();
  });

  it('rejects it for a rule the team set', () => {
    expect(rejectedFor('DENY', ['POLICY_MONTHLY_CAP'])).toEqual(['POLICY_MONTHLY_CAP']);
  });

  it('names only the rules that refused it, not one that only asked for an approval', () => {
    expect(rejectedFor('REQUIRE_NEW_MANDATE', ['MANDATE_MONTHLY_LIMIT', 'APPROVAL_THRESHOLD'])).toEqual([
      'MANDATE_MONTHLY_LIMIT',
    ]);
  });

  it('never rejects for the bank consent: no rule the team set, so the request waits as it was (decision 23)', () => {
    expect(rejectedFor('REQUIRE_NEW_MANDATE', ['MANDATE_ORDER_LIMIT', 'MANDATE_LIMIT_PAST_CONSENT'])).toBeNull();
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

  it('names a policy’s order cap beside another refusal: it may have refused as well', () => {
    expect(rejectedFor('DENY', ['POLICY_MONTHLY_CAP', 'POLICY_ORDER_CAP'])).toEqual([
      'POLICY_MONTHLY_CAP',
      'POLICY_ORDER_CAP',
    ]);
    expect(rejectedFor('DENY', ['POLICY_ORDER_CAP', 'AGENT_SUSPENDED'])).toBeNull();
    // Beside a REQUIRE_NEW_MANDATE it didn't refuse (it would have made a DENY): it only asked for an approval.
    expect(rejectedFor('REQUIRE_NEW_MANDATE', ['MANDATE_MONTHLY_LIMIT', 'POLICY_ORDER_CAP'])).toEqual([
      'MANDATE_MONTHLY_LIMIT',
    ]);
  });

  it.each(RULES)('rejects it for each rule the team set alone: %s', (rule) => {
    // The mandate's own limits refuse as REQUIRE_NEW_MANDATE, the rest as DENY (the engine's DECIDES).
    const decision = rule.startsWith('MANDATE_') ? 'REQUIRE_NEW_MANDATE' : 'DENY';
    expect(rejectedFor(decision, [rule])).toEqual([rule]);
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
