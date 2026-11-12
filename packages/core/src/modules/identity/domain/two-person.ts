// The two-person rule (ADR-012 §1, Threat-Model PAY-2; SEC-PAY-04; E3-1): who
// may verify a supplier's details that another member entered.
//
// The verifier is an admin or a finance approver (partner, S69), a different
// account from the one that entered the details, a member for 14 days (a
// second account made for the purpose is too young), and never one whose role
// the person who entered them granted or confirmed: by inviting them, opening
// or confirming their invitation, bringing them back, or changing their role.
//
// An organisation where no one is eligible (a new one, or one with a single
// user) takes the single-user path: the cooling-off and the notices alone, so
// any admin or approver may verify, the enterer too (ADR-012 §1). Removing
// people doesn't open that path: for 14 days after an admin or an approver is
// deactivated or has their role changed, it is shut. Any change counts, not
// only a demotion: an admin moved to approver by the enterer is then one whose
// role the enterer granted, so a sideways move would otherwise leave an
// insider alone as surely as a demotion (E3-1's review).
//
// Grants count directly, as ADR-012 §1 says: a member invited by someone the
// enterer invited is eligible. Following the chain would leave every
// organisation whose founder invited everyone with no second verifier;
// collusion through a planted account is the residual R-10 names, with the
// 14 days and the notices to everyone between it and a payment.
//
// Pure: what it rests on is each membership's signed grant summary, kept in
// step with every membership change, or, for a membership added before the
// summaries (0085, OR1) until its summary is built, the organisation's log
// (infrastructure/two-person-facts.ts, membership-grants.ts). A member in the 7 days without powers
// after a second factor removed (removal-restriction.ts) still counts as
// eligible here, so the organisation waits for them rather than going solo;
// whether the verifier themselves may act then is the route's access check.
import { DAY_MS } from '../../../shared-kernel/index.ts';
import type { Role } from './membership.ts';

/** How long a verifier must have been a member (ADR-012 §1). */
export const ESTABLISHED_DAYS = 14;
/** How long the single-user path stays shut after an admin or approver is removed or has their role changed (ADR-012 §1). */
export const SOLO_PATH_LOCK_DAYS = 14;

/** Whether a role may verify a supplier (partner, S69): an admin or a finance approver. */
export const mayVerify = (role: string): boolean => role === 'admin' || role === 'approver';

/** A member as the rule sees them: their verified membership. */
export interface RuleMember {
  readonly id: string;
  readonly userId: string;
  readonly role: Role;
  readonly status: 'ACTIVE' | 'DEACTIVATED';
  readonly joinedAt: Date;
}

/** An event of the organisation's log, as the rule reads it. */
export interface RuleEvent {
  readonly recordedAt: Date;
  readonly event: {
    readonly actor: { readonly type: string; readonly id: string };
    readonly action: string;
    readonly subject: { readonly type: string; readonly id: string };
    readonly details: Readonly<Record<string, unknown>>;
  };
}

/** What the rule decides on: every member, who granted each one's role, and the latest change to a verifier. */
export interface TwoPersonFacts {
  readonly members: readonly RuleMember[];
  /** By membership ID: the people (user IDs, lower case) who granted or confirmed its role, ever. */
  readonly grantedBy: ReadonlyMap<string, ReadonlySet<string>>;
  /** When an admin or approver was last deactivated or had their role changed; undefined for never. */
  readonly lastVerifierChange: Date | undefined;
}

/** The subject types the history is read from. */
export const HISTORY_SUBJECTS = ['membership', 'invitation'] as const;

/** A membership's events that grant or confirm its role, by the person who records them. */
const MEMBERSHIP_GRANTS: ReadonlySet<string> = new Set([
  'membership.created',
  'membership.renewed',
  'membership.reactivated',
  'membership.role_changed',
]);

/** An invitation's events that grant or confirm the role it carries: asked for, opened, confirmed. */
export const INVITATION_GRANTS: ReadonlySet<string> = new Set([
  'invitation.drafted',
  'invitation.opened',
  'invitation.confirmed',
]);

/** Adds `value` to the set kept under `key`. */
const addTo = (map: Map<string, Set<string>>, key: string, value: string): void => {
  const set = map.get(key) ?? new Set<string>();
  set.add(value);
  map.set(key, set);
};

/** Whether the event changes a verifier: an admin or approver deactivated, or their role changed to any other. */
export const changesVerifier = ({ action, details }: Pick<RuleEvent['event'], 'action' | 'details'>): boolean =>
  (action === 'membership.deactivated' && mayVerify(String(details.role))) ||
  (action === 'membership.role_changed' && mayVerify(String(details.roleFrom)));

/** The later of two times, either undefined for none. */
const later = (a: Date | undefined, b: Date | undefined): Date | undefined =>
  a === undefined || (b !== undefined && b > a) ? b : a;

/**
 * A membership's grant summary (OR1; 0085): who granted or confirmed its role,
 * ever, and when it last stopped being a verifier's. Kept signed with each
 * membership change, so the rule reads one a member rather than the whole log.
 */
export interface GrantSummary {
  /** The people (user IDs, lower case) who granted or confirmed its role; never the member themselves. */
  readonly grantedBy: ReadonlySet<string>;
  /** When it, an admin's or approver's, was last deactivated or had its role changed; undefined for never. */
  readonly verifierChangedAt: Date | undefined;
}

/** The log's events, gathered: who granted each membership and invitation, who accepted which, each membership's latest change as a verifier. */
export interface GrantHistory {
  readonly byMembership: Map<string, Set<string>>;
  readonly byInvitation: Map<string, Set<string>>;
  /** By person: the invitations they accepted. */
  readonly acceptedBy: Map<string, Set<string>>;
  /** By membership: when it, a verifier's, was last deactivated or had its role changed. */
  readonly verifierChanges: Map<string, Date>;
}

/** A history with nothing gathered yet. */
export const grantHistory = (): GrantHistory => ({
  byMembership: new Map(),
  byInvitation: new Map(),
  acceptedBy: new Map(),
  verifierChanges: new Map(),
});

/** Adds one event about a membership to the history: who granted its role, and its latest change as a verifier. */
function gatherMembership(history: GrantHistory, { recordedAt, event }: RuleEvent): void {
  const subject = event.subject.id.toLowerCase();
  if (event.actor.type === 'user' && MEMBERSHIP_GRANTS.has(event.action)) {
    addTo(history.byMembership, subject, event.actor.id.toLowerCase());
  }
  if (changesVerifier(event)) {
    history.verifierChanges.set(subject, later(history.verifierChanges.get(subject), recordedAt) ?? recordedAt);
  }
}

/** Adds one event about an invitation to the history: who accepted it, or who granted the role it carries. */
function gatherInvitation(history: GrantHistory, { event }: RuleEvent): void {
  const subject = event.subject.id.toLowerCase();
  const actor = event.actor.id.toLowerCase();
  if (event.action === 'invitation.acceptance_recorded') addTo(history.acceptedBy, actor, subject);
  else if (event.actor.type === 'user' && INVITATION_GRANTS.has(event.action))
    addTo(history.byInvitation, subject, actor);
}

/** Adds events about memberships and invitations (HISTORY_SUBJECTS) to the history, in any order: a page at a time. */
export function gatherGrants(history: GrantHistory, events: readonly RuleEvent[]): void {
  for (const read of events) {
    if (read.event.subject.type === 'membership') gatherMembership(history, read);
    else if (read.event.subject.type === 'invitation') gatherInvitation(history, read);
  }
}

/**
 * The member's grant summary as the history holds it. A person never counts as
 * granting their own role: accepting an invitation is theirs.
 */
export function summaryFromHistory(history: GrantHistory, member: Pick<RuleMember, 'id' | 'userId'>): GrantSummary {
  const person = member.userId.toLowerCase();
  const granted = new Set(history.byMembership.get(member.id.toLowerCase()));
  for (const invitation of history.acceptedBy.get(person) ?? []) {
    for (const granter of history.byInvitation.get(invitation) ?? []) granted.add(granter);
  }
  granted.delete(person);
  return { grantedBy: granted, verifierChangedAt: history.verifierChanges.get(member.id.toLowerCase()) };
}

/**
 * The rule's facts from every member and each one's grant summary, by
 * membership ID in lower case; the latest change to a verifier is the latest
 * of any member's. Throws for a member with none: a member left out of the
 * latest change would make the one-person path look open, so the facts are
 * read from the history until every summary is built.
 */
export function factsFromSummaries(
  members: readonly RuleMember[],
  summaries: ReadonlyMap<string, GrantSummary>,
): TwoPersonFacts {
  const grantedBy = new Map<string, ReadonlySet<string>>();
  let lastVerifierChange: Date | undefined;
  for (const member of members) {
    const summary = summaries.get(member.id.toLowerCase());
    if (summary === undefined) throw new Error(`The two-person rule's facts hold no summary for ${member.id}`);
    grantedBy.set(member.id.toLowerCase(), summary.grantedBy);
    lastVerifierChange = later(lastVerifierChange, summary.verifierChangedAt);
  }
  return { members, grantedBy, lastVerifierChange };
}

/**
 * The rule's facts from the members and the log's events about memberships
 * and invitations (HISTORY_SUBJECTS), in any order. The latest change to a
 * verifier is the latest the log holds about any membership.
 */
export function twoPersonFacts(members: readonly RuleMember[], events: readonly RuleEvent[]): TwoPersonFacts {
  const history = grantHistory();
  gatherGrants(history, events);
  return historyFacts(members, history).facts;
}

/** The rule's facts from a gathered history, with each member's summary as it holds it, by membership ID in lower case. */
export function historyFacts(
  members: readonly RuleMember[],
  history: GrantHistory,
): { readonly facts: TwoPersonFacts; readonly summaries: ReadonlyMap<string, GrantSummary> } {
  const summaries = new Map(members.map((member) => [member.id.toLowerCase(), summaryFromHistory(history, member)]));
  let lastVerifierChange: Date | undefined;
  for (const at of history.verifierChanges.values()) lastVerifierChange = later(lastVerifierChange, at);
  return { facts: { ...factsFromSummaries(members, summaries), lastVerifierChange }, summaries };
}

/** A membership change as its grant summary takes it (grantsAfter). */
export interface GrantChange {
  /** The member's own user ID: never among those who granted their role. */
  readonly memberUserId: string;
  /** Who granted or confirmed the role by this change (user IDs); none for a change that grants nothing. */
  readonly granters: Iterable<string>;
  /** The change's event's time, when it is a verifier's deactivation or role change (changesVerifier). */
  readonly verifierChangedAt?: Date | undefined;
}

/** The summary after a change of its membership: nothing taken away, so it never looks cleaner than its history. */
export function grantsAfter(
  summary: GrantSummary,
  { memberUserId, granters, verifierChangedAt }: GrantChange,
): GrantSummary {
  const grantedBy = new Set(summary.grantedBy);
  for (const granter of granters) grantedBy.add(granter.toLowerCase());
  grantedBy.delete(memberUserId.toLowerCase());
  return { grantedBy, verifierChangedAt: later(summary.verifierChangedAt, verifierChangedAt) };
}

/** A summary of a membership no one has granted anything yet. */
export const NO_GRANTS: GrantSummary = { grantedBy: new Set(), verifierChangedAt: undefined };

/**
 * Whether a kept summary holds at least what its history says, for the rule's
 * purposes: every granter of an active member's role (for one deactivated, an
 * invitation accepted since only counts once they are brought back, which
 * reads them all again), and no earlier a verifier change. More is only more
 * caution; less would open a path the history shuts.
 */
export function summaryCovers(kept: GrantSummary, history: GrantSummary, active: boolean): boolean {
  if (active && [...history.grantedBy].some((granter) => !kept.grantedBy.has(granter))) return false;
  if (history.verifierChangedAt === undefined) return true;
  return kept.verifierChangedAt !== undefined && kept.verifierChangedAt >= history.verifierChangedAt;
}

/** Why a member may not verify details another entered. */
export type VerifierRefusal =
  'NOT_A_VERIFIER' | 'SAME_PERSON' | 'VERIFIER_GRANTED_BY_ENTERER' | 'VERIFIER_TOO_NEW' | 'SOLO_PATH_LOCKED';

/**
 * The rule's answer: the verifier is an eligible second person; or no one is,
 * and the single-user path is open; or refused, with when it may change for a
 * wait that ends by itself.
 */
export type VerifierVerdict =
  | { readonly outcome: 'two_person' }
  | { readonly outcome: 'single_user' }
  | { readonly outcome: 'refused'; readonly reason: VerifierRefusal; readonly until?: Date };

/** Why `member` isn't an eligible second verifier for what `enterer` entered, at `now`; undefined when they are. */
function ineligibility(
  facts: TwoPersonFacts,
  member: RuleMember,
  enterer: RuleMember,
  now: Date,
): { readonly reason: VerifierRefusal; readonly until?: Date } | undefined {
  if (member.status !== 'ACTIVE' || !mayVerify(member.role)) return { reason: 'NOT_A_VERIFIER' };
  if (member.id === enterer.id || member.userId.toLowerCase() === enterer.userId.toLowerCase()) {
    return { reason: 'SAME_PERSON' };
  }
  // A member with no record of who granted their role is taken as granted by the enterer: never assumed clean.
  if (facts.grantedBy.get(member.id.toLowerCase())?.has(enterer.userId.toLowerCase()) !== false) {
    return { reason: 'VERIFIER_GRANTED_BY_ENTERER' };
  }
  const established = new Date(member.joinedAt.getTime() + ESTABLISHED_DAYS * DAY_MS);
  if (now.getTime() < established.getTime()) return { reason: 'VERIFIER_TOO_NEW', until: established };
  return undefined;
}

/**
 * Whether the member `verifierId` may verify details the member `enteredById`
 * entered, at `now` (memberships' IDs). Throws for either not among the
 * members: the facts were read for another organisation, or wrongly.
 */
export function verifierVerdict(
  facts: TwoPersonFacts,
  { enteredById, verifierId }: { readonly enteredById: string; readonly verifierId: string },
  now: Date,
): VerifierVerdict {
  const find = (id: string): RuleMember => {
    const found = facts.members.find((member) => member.id.toLowerCase() === id.toLowerCase());
    if (found === undefined) throw new Error(`The two-person rule's facts hold no membership ${id}`);
    return found;
  };
  const enterer = find(enteredById);
  const why = ineligibility(facts, find(verifierId), enterer, now);
  if (why === undefined) return { outcome: 'two_person' };
  // Only an admin or approver takes the single-user path, and only when no one else is eligible.
  if (
    why.reason === 'NOT_A_VERIFIER' ||
    facts.members.some((member) => ineligibility(facts, member, enterer, now) === undefined)
  ) {
    return { outcome: 'refused', ...why };
  }
  // No one eligible: the single-user path, unless a verifier was changed lately.
  if (facts.lastVerifierChange !== undefined) {
    const reopens = new Date(facts.lastVerifierChange.getTime() + SOLO_PATH_LOCK_DAYS * DAY_MS);
    if (now.getTime() < reopens.getTime()) return { outcome: 'refused', reason: 'SOLO_PATH_LOCKED', until: reopens };
  }
  return { outcome: 'single_user' };
}
