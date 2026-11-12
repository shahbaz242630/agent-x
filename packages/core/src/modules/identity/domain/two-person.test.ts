// The two-person rule (ADR-012 §1; SEC-PAY-04; E3-1): the same person; a
// second account of the same person (too young); a verifier whose role the
// enterer granted; demote-then-self-verify during the lock-out; a new
// organisation on the single-user path until someone is eligible.
import { describe, expect, it } from 'vitest';

import { DAY_MS } from '../../../shared-kernel/index.ts';
import type { Role } from './membership.ts';
import {
  changesVerifier,
  ESTABLISHED_DAYS,
  factsFromSummaries,
  gatherGrants,
  grantHistory,
  grantsAfter,
  historyFacts,
  mayVerify,
  NO_GRANTS,
  type RuleEvent,
  type RuleMember,
  SOLO_PATH_LOCK_DAYS,
  summaryCovers,
  summaryFromHistory,
  type TwoPersonFacts,
  twoPersonFacts,
  verifierVerdict,
} from './two-person.ts';

const NOW = new Date('2026-10-20T12:00:00.000Z');
const daysAgo = (days: number): Date => new Date(NOW.getTime() - days * DAY_MS);

const member = (id: string, role: Role, joinedDaysAgo = 30, status: RuleMember['status'] = 'ACTIVE'): RuleMember => ({
  id: `m-${id}`,
  userId: `u-${id}`,
  role,
  status,
  joinedAt: daysAgo(joinedDaysAgo),
});

const event = (
  action: string,
  subject: { type: string; id: string },
  actor: string,
  details: Record<string, unknown> = {},
  at = daysAgo(30),
  actorType = 'user',
): RuleEvent => ({ recordedAt: at, event: { actor: { type: actorType, id: actor }, action, subject, details } });

const facts = (members: readonly RuleMember[], events: readonly RuleEvent[] = []): TwoPersonFacts =>
  twoPersonFacts(members, events);

const verdict = (f: TwoPersonFacts, enteredBy: string, verifier: string, now = NOW) =>
  verifierVerdict(f, { enteredById: `m-${enteredBy}`, verifierId: `m-${verifier}` }, now);

describe('who may verify (partner, S69)', () => {
  it('is an admin or a finance approver, never a developer or a viewer', () => {
    expect(['admin', 'approver', 'developer', 'viewer'].filter(mayVerify)).toEqual(['admin', 'approver']);
  });

  it('uses ADR-012 §1’s numbers: 14 days a member, 14 days without the solo path', () => {
    expect([ESTABLISHED_DAYS, SOLO_PATH_LOCK_DAYS]).toEqual([14, 14]);
  });
});

describe('the two-person rule (SEC-PAY-04)', () => {
  const alice = member('a', 'admin');
  const bob = member('b', 'approver');

  it('lets an established second admin or approver verify', () => {
    expect(verdict(facts([alice, bob]), 'a', 'b')).toEqual({ outcome: 'two_person' });
    expect(verdict(facts([alice, member('b', 'admin')]), 'a', 'b')).toEqual({ outcome: 'two_person' });
  });

  it('refuses the person who entered the details while someone else is eligible', () => {
    expect(verdict(facts([alice, bob]), 'a', 'a')).toEqual({ outcome: 'refused', reason: 'SAME_PERSON' });
  });

  it('refuses a second membership of the same person', () => {
    const again = { ...bob, userId: alice.userId.toUpperCase() };
    expect(verdict(facts([alice, again, member('c', 'admin')]), 'a', 'b')).toEqual({
      outcome: 'refused',
      reason: 'SAME_PERSON',
    });
  });

  it('refuses a developer, a viewer or a deactivated member, on either path', () => {
    for (const other of [member('b', 'developer'), member('b', 'viewer'), member('b', 'admin', 30, 'DEACTIVATED')]) {
      expect(verdict(facts([alice, other]), 'a', 'b')).toEqual({ outcome: 'refused', reason: 'NOT_A_VERIFIER' });
      expect(verdict(facts([alice, other, member('c', 'admin')]), 'a', 'b')).toEqual({
        outcome: 'refused',
        reason: 'NOT_A_VERIFIER',
      });
    }
  });

  it('refuses a member under 14 days, until the day they are established, while someone else is eligible', () => {
    const young = member('y', 'admin', 3);
    expect(verdict(facts([alice, bob, young]), 'a', 'y')).toEqual({
      outcome: 'refused',
      reason: 'VERIFIER_TOO_NEW',
      until: new Date(young.joinedAt.getTime() + 14 * DAY_MS),
    });
  });

  it('counts a member established from exactly 14 days, not a millisecond before', () => {
    const joined = member('b', 'approver', 14);
    expect(verdict(facts([alice, joined]), 'a', 'b')).toEqual({ outcome: 'two_person' });
    const justShort = new Date(NOW.getTime() - 1);
    expect(verdict(facts([alice, joined, member('c', 'admin')]), 'a', 'b', justShort)).toMatchObject({
      reason: 'VERIFIER_TOO_NEW',
    });
  });

  it('refuses a verifier whose role the enterer granted, however long ago', () => {
    const changed = event('membership.role_changed', { type: 'membership', id: bob.id }, alice.userId, {
      roleFrom: 'viewer',
      roleTo: 'approver',
    });
    expect(verdict(facts([alice, bob, member('c', 'admin')], [changed]), 'a', 'b')).toEqual({
      outcome: 'refused',
      reason: 'VERIFIER_GRANTED_BY_ENTERER',
    });
  });

  it('names the grant before the age: a grant never ends, an age does', () => {
    const young = member('y', 'admin', 3);
    const created = event('membership.created', { type: 'membership', id: young.id }, alice.userId);
    expect(verdict(facts([alice, bob, young], [created]), 'a', 'y')).toMatchObject({
      reason: 'VERIFIER_GRANTED_BY_ENTERER',
    });
  });

  it('takes a member with no record of who granted their role as granted by the enterer', () => {
    const f = facts([alice, bob]);
    const missing: TwoPersonFacts = { ...f, grantedBy: new Map() };
    expect(verdict(missing, 'a', 'b')).toEqual({ outcome: 'single_user' });
    expect(verdict({ ...missing, members: [alice, bob, member('c', 'admin')] }, 'a', 'b')).toEqual({
      outcome: 'single_user',
    });
  });

  it('throws for a membership the facts don’t hold', () => {
    expect(() => verdict(facts([alice]), 'a', 'z')).toThrow(/no membership m-z/);
    expect(() => verdict(facts([alice]), 'z', 'a')).toThrow(/no membership m-z/);
  });

  it('finds memberships whatever the IDs’ case', () => {
    expect(verifierVerdict(facts([alice, bob]), { enteredById: 'M-A', verifierId: 'M-B' }, NOW)).toEqual({
      outcome: 'two_person',
    });
  });
});

describe('the single-user path (ADR-012 §1)', () => {
  const alice = member('a', 'admin');

  it('is open when no one else is eligible: a one-person organisation', () => {
    expect(verdict(facts([alice]), 'a', 'a')).toEqual({ outcome: 'single_user' });
  });

  it('is open in a new organisation until someone is eligible, to any of its admins and approvers', () => {
    const newOrg = [member('a', 'admin', 2), member('b', 'approver', 1)];
    expect(verdict(facts(newOrg), 'a', 'a')).toEqual({ outcome: 'single_user' });
    expect(verdict(facts(newOrg), 'a', 'b')).toEqual({ outcome: 'single_user' });
  });

  it('is open when the only other verifier’s role was granted by the enterer', () => {
    const bob = member('b', 'admin');
    const invited = event('invitation.drafted', { type: 'invitation', id: 'i-1' }, alice.userId);
    const accepted = event('invitation.acceptance_recorded', { type: 'invitation', id: 'i-1' }, bob.userId);
    expect(verdict(facts([alice, bob], [invited, accepted]), 'a', 'a')).toEqual({ outcome: 'single_user' });
  });

  /** A role change Alice made `days` ago. */
  const roleChange = (id: string, roleFrom: Role, roleTo: Role, days = 1): RuleEvent =>
    event('membership.role_changed', { type: 'membership', id }, alice.userId, { roleFrom, roleTo }, daysAgo(days));

  it('is shut for 14 days after the one other verifier is demoted: demote-then-self-verify', () => {
    const bob = member('b', 'viewer');
    const demoted = roleChange(bob.id, 'admin', 'viewer', 5);
    expect(verdict(facts([alice, bob], [demoted]), 'a', 'a')).toEqual({
      outcome: 'refused',
      reason: 'SOLO_PATH_LOCKED',
      until: new Date(daysAgo(5).getTime() + 14 * DAY_MS),
    });
    expect(verdict(facts([alice, bob], [demoted]), 'a', 'a', new Date(NOW.getTime() + 9 * DAY_MS))).toEqual({
      outcome: 'single_user',
    });
    expect(verdict(facts([alice, bob], [demoted]), 'a', 'a', new Date(NOW.getTime() + 9 * DAY_MS - 1))).toMatchObject({
      reason: 'SOLO_PATH_LOCKED',
    });
  });

  it('is shut for 14 days after the enterer moves the one other verifier sideways, which taints them (the review’s high)', () => {
    const bob = member('b', 'approver');
    const moved = roleChange(bob.id, 'admin', 'approver');
    // Bob is tainted, so no one is eligible; and the move shuts the solo path to both of them.
    for (const verifier of ['a', 'b']) {
      expect(verdict(facts([alice, bob], [moved]), 'a', verifier)).toEqual({
        outcome: 'refused',
        reason: 'SOLO_PATH_LOCKED',
        until: new Date(daysAgo(1).getTime() + 14 * DAY_MS),
      });
    }
  });

  it('is shut for 14 days after an admin or approver is deactivated, from the latest such change', () => {
    const gone = member('b', 'approver', 30, 'DEACTIVATED');
    const losses = [
      event('membership.deactivated', { type: 'membership', id: gone.id }, alice.userId, { role: 'admin' }, daysAgo(2)),
      roleChange('m-old', 'approver', 'viewer', 20),
    ];
    expect(verdict(facts([alice, gone], losses), 'a', 'a')).toMatchObject({
      reason: 'SOLO_PATH_LOCKED',
      until: new Date(daysAgo(2).getTime() + 14 * DAY_MS),
    });
    expect(verdict(facts([alice, gone], losses.toReversed()), 'a', 'a')).toMatchObject({
      until: new Date(daysAgo(2).getTime() + 14 * DAY_MS),
    });
  });

  it('isn’t shut by a change to someone who couldn’t verify', () => {
    const notChanges = [
      event('membership.deactivated', { type: 'membership', id: 'm-v' }, alice.userId, { role: 'viewer' }, daysAgo(1)),
      roleChange('m-d', 'developer', 'admin'),
      roleChange('m-e', 'developer', 'viewer'),
      event('invitation.declined', { type: 'invitation', id: 'i-9' }, alice.userId, { role: 'admin' }, daysAgo(1)),
    ];
    expect(facts([alice], notChanges).lastVerifierChange).toBeUndefined();
    expect(verdict(facts([alice], notChanges), 'a', 'a')).toEqual({ outcome: 'single_user' });
  });

  it('doesn’t matter while someone is eligible: the two-person path stays open', () => {
    const lost = event(
      'membership.deactivated',
      { type: 'membership', id: 'm-x' },
      alice.userId,
      { role: 'admin' },
      daysAgo(1),
    );
    expect(verdict(facts([alice, member('b', 'admin')], [lost]), 'a', 'b')).toEqual({ outcome: 'two_person' });
  });
});

describe('who granted a member’s role, from the log (twoPersonFacts)', () => {
  const alice = member('a', 'admin');
  const bob = member('b', 'approver');
  const carol = member('c', 'admin');

  const grantersOf = (events: readonly RuleEvent[], whose = bob): string[] =>
    [...(facts([alice, bob, carol], events).grantedBy.get(whose.id) ?? [])].sort();

  it('counts whoever asked for, opened or confirmed an invitation the member accepted', () => {
    const invitation = { type: 'invitation', id: 'I-1' };
    expect(
      grantersOf([
        event('invitation.drafted', invitation, 'U-A'),
        event('invitation.opened', invitation, alice.userId),
        event('invitation.acceptance_recorded', invitation, bob.userId),
        event('invitation.confirmed', { type: 'invitation', id: 'i-1' }, carol.userId),
      ]),
    ).toEqual(['u-a', 'u-c']);
  });

  it('counts no one for an invitation someone else accepted', () => {
    const invitation = { type: 'invitation', id: 'i-2' };
    expect(
      grantersOf([
        event('invitation.drafted', invitation, alice.userId),
        event('invitation.acceptance_recorded', invitation, carol.userId),
      ]),
    ).toEqual([]);
  });

  it('counts whoever added, brought back or changed the role of the membership', () => {
    const it_ = { type: 'membership', id: bob.id.toUpperCase() };
    expect(grantersOf([event('membership.created', it_, carol.userId)])).toEqual(['u-c']);
    expect(grantersOf([event('membership.renewed', it_, alice.userId)])).toEqual(['u-a']);
    expect(grantersOf([event('membership.reactivated', it_, alice.userId)])).toEqual(['u-a']);
    expect(grantersOf([event('membership.role_changed', it_, alice.userId)])).toEqual(['u-a']);
  });

  it('doesn’t count a removal, a decline, the app or an agent as a grant', () => {
    const invitation = { type: 'invitation', id: 'i-3' };
    expect(
      grantersOf([
        event('membership.deactivated', { type: 'membership', id: bob.id }, alice.userId, { role: 'viewer' }),
        event('invitation.declined', invitation, alice.userId),
        event('invitation.drafted', invitation, 'operator', {}, daysAgo(30), 'system'),
        event('membership.role_changed', { type: 'membership', id: bob.id }, 'agent-1', {}, daysAgo(30), 'agent'),
        event('invitation.acceptance_recorded', invitation, bob.userId),
        event('membership.created', { type: 'organisation', id: bob.id }, alice.userId),
      ]),
    ).toEqual([]);
  });

  it('never counts the member as granting their own role', () => {
    const invitation = { type: 'invitation', id: 'i-4' };
    expect(
      grantersOf([
        event('membership.created', { type: 'membership', id: bob.id }, bob.userId),
        event('invitation.opened', invitation, bob.userId),
        event('invitation.acceptance_recorded', invitation, bob.userId),
      ]),
    ).toEqual([]);
  });

  it('keeps every member, each with their own set, and the members as given', () => {
    const f = facts([alice, bob], [event('membership.created', { type: 'membership', id: alice.id }, carol.userId)]);
    expect(f.members).toEqual([alice, bob]);
    expect([...f.grantedBy.keys()]).toEqual([alice.id, bob.id]);
    expect([...(f.grantedBy.get(alice.id) ?? [])]).toEqual([carol.userId]);
    expect([...(f.grantedBy.get(bob.id) ?? [])]).toEqual([]);
  });
});

describe('a membership’s grant summary (OR1): kept from the history, moved on by each change', () => {
  const alice = member('a', 'admin');
  const bob = member('b', 'approver');
  const membershipOf = (who: RuleMember) => ({ type: 'membership', id: who.id });

  it('gathers a page at a time to the same summaries and facts as the whole history at once', () => {
    const invitation = { type: 'invitation', id: 'i-5' };
    const events = [
      event('membership.created', membershipOf(bob), alice.userId),
      event('invitation.drafted', invitation, 'u-c'),
      event('invitation.acceptance_recorded', invitation, bob.userId),
      event('membership.deactivated', membershipOf(alice), bob.userId, { role: 'admin' }, daysAgo(3)),
      event('membership.role_changed', membershipOf(alice), bob.userId, { roleFrom: 'approver' }, daysAgo(2)),
    ];
    const history = grantHistory();
    gatherGrants(history, events.slice(0, 2));
    gatherGrants(history, events.slice(2));

    expect(historyFacts([alice, bob], history).facts).toEqual(facts([alice, bob], events));
    expect(summaryFromHistory(history, bob)).toEqual({
      grantedBy: new Set(['u-a', 'u-c']),
      verifierChangedAt: undefined,
    });
    // The later of Alice's two changes as a verifier.
    expect(summaryFromHistory(history, alice).verifierChangedAt).toEqual(daysAgo(2));
  });

  it('decides from summaries alone as from the history, the latest verifier change of any member', () => {
    const summaries = new Map([
      [alice.id, { grantedBy: new Set<string>(), verifierChangedAt: daysAgo(5) }],
      [bob.id, { grantedBy: new Set([alice.userId]), verifierChangedAt: daysAgo(1) }],
    ]);
    const f = factsFromSummaries([alice, bob], summaries);

    expect(f.lastVerifierChange).toEqual(daysAgo(1));
    // Bob's role is Alice's grant, and no one else is eligible: the one-person path, shut by Bob's change a day ago.
    expect(verdict(f, 'a', 'b')).toEqual({
      outcome: 'refused',
      reason: 'SOLO_PATH_LOCKED',
      until: new Date(daysAgo(1).getTime() + SOLO_PATH_LOCK_DAYS * DAY_MS),
    });
  });

  it('decides nothing for a member with no summary: their change could shut the one-person path', () => {
    expect(() => factsFromSummaries([alice, bob], new Map([[alice.id, NO_GRANTS]]))).toThrow(/no summary/);
  });

  it('adds who granted a change, never the member, and keeps the later verifier change', () => {
    const before = { grantedBy: new Set(['u-x']), verifierChangedAt: daysAgo(4) };

    expect(
      grantsAfter(before, { memberUserId: 'U-B', granters: ['U-A', 'u-b'], verifierChangedAt: daysAgo(6) }),
    ).toEqual({ grantedBy: new Set(['u-x', 'u-a']), verifierChangedAt: daysAgo(4) });
    expect(grantsAfter(NO_GRANTS, { memberUserId: 'u-b', granters: [], verifierChangedAt: daysAgo(1) })).toEqual({
      grantedBy: new Set(),
      verifierChangedAt: daysAgo(1),
    });
  });

  it('counts a verifier deactivated or moved to any role as a change, and no one else', () => {
    expect(changesVerifier({ action: 'membership.deactivated', details: { role: 'approver' } })).toBe(true);
    expect(changesVerifier({ action: 'membership.deactivated', details: { role: 'viewer' } })).toBe(false);
    expect(changesVerifier({ action: 'membership.role_changed', details: { roleFrom: 'admin' } })).toBe(true);
    expect(changesVerifier({ action: 'membership.role_changed', details: { roleFrom: 'developer' } })).toBe(false);
  });

  it('holds a kept summary to at least what the history says: granters for an active member, and the verifier change', () => {
    const history = { grantedBy: new Set(['u-a']), verifierChangedAt: daysAgo(2) };
    const kept = (grantedBy: string[], verifierChangedAt?: Date) => ({
      grantedBy: new Set(grantedBy),
      verifierChangedAt,
    });

    expect(summaryCovers(kept(['u-a', 'u-z'], daysAgo(1)), history, true)).toBe(true);
    expect(summaryCovers(kept([], daysAgo(2)), history, true)).toBe(false);
    // Deactivated: an invitation accepted since counts once they come back, which reads them all again.
    expect(summaryCovers(kept([], daysAgo(2)), history, false)).toBe(true);
    expect(summaryCovers(kept(['u-a'], daysAgo(3)), history, true)).toBe(false);
    expect(summaryCovers(kept(['u-a']), history, true)).toBe(false);
    expect(summaryCovers(kept(['u-a']), { ...history, verifierChangedAt: undefined }, true)).toBe(true);
  });
});
