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
// deactivated or given a lesser role, it is shut, so demoting the one other
// verifier can't leave an insider alone.
//
// Pure: the history it rests on is read from the organisation's log
// (infrastructure/two-person-facts.ts). A member in the 7 days without powers
// after a second factor removed (removal-restriction.ts) still counts as
// eligible here, so the organisation waits for them rather than going solo;
// whether the verifier themselves may act then is the route's access check.
import type { Role } from './membership.ts';

/** How long a verifier must have been a member (ADR-012 §1). */
export const ESTABLISHED_DAYS = 14;
/** How long the single-user path stays shut after an admin or approver is removed or demoted (ADR-012 §1). */
export const SOLO_PATH_LOCK_DAYS = 14;

const DAY_MS = 86_400_000;

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

/** What the rule decides on: every member, who granted each one's role, and the latest loss of a verifier. */
export interface TwoPersonFacts {
  readonly members: readonly RuleMember[];
  /** By membership ID: the people (user IDs, lower case) who granted or confirmed its role, ever. */
  readonly grantedBy: ReadonlyMap<string, ReadonlySet<string>>;
  /** When an admin or approver was last deactivated or given a lesser role; undefined for never. */
  readonly lastVerifierLoss: Date | undefined;
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
const INVITATION_GRANTS: ReadonlySet<string> = new Set([
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

/** Whether the event takes a verifier away: an admin or approver deactivated, or given a role that can't verify. */
const losesVerifier = ({ action, details }: RuleEvent['event']): boolean =>
  (action === 'membership.deactivated' && mayVerify(String(details.role))) ||
  (action === 'membership.role_changed' && mayVerify(String(details.roleFrom)) && !mayVerify(String(details.roleTo)));

/** The log's events, gathered: who granted each membership and invitation, who accepted which, the latest loss. */
interface History {
  readonly byMembership: Map<string, Set<string>>;
  readonly byInvitation: Map<string, Set<string>>;
  /** By person: the invitations they accepted. */
  readonly acceptedBy: Map<string, Set<string>>;
  lastVerifierLoss: Date | undefined;
}

/** Adds one event to the history. */
function gather(history: History, { recordedAt, event }: RuleEvent): void {
  const subject = event.subject.id.toLowerCase();
  const actor = event.actor.id.toLowerCase();
  const byPerson = event.actor.type === 'user';
  if (event.subject.type === 'membership') {
    if (byPerson && MEMBERSHIP_GRANTS.has(event.action)) addTo(history.byMembership, subject, actor);
    const latest = history.lastVerifierLoss;
    if (losesVerifier(event) && (latest === undefined || recordedAt > latest)) history.lastVerifierLoss = recordedAt;
  } else if (event.subject.type === 'invitation') {
    if (event.action === 'invitation.acceptance_recorded') addTo(history.acceptedBy, actor, subject);
    else if (byPerson && INVITATION_GRANTS.has(event.action)) addTo(history.byInvitation, subject, actor);
  }
}

/**
 * The rule's facts from the members and the log's events about memberships
 * and invitations (HISTORY_SUBJECTS), in any order. A person never counts as
 * granting their own role: accepting an invitation is theirs.
 */
export function twoPersonFacts(members: readonly RuleMember[], events: readonly RuleEvent[]): TwoPersonFacts {
  const history: History = {
    byMembership: new Map(),
    byInvitation: new Map(),
    acceptedBy: new Map(),
    lastVerifierLoss: undefined,
  };
  for (const event of events) gather(history, event);
  const { byMembership, byInvitation, acceptedBy, lastVerifierLoss } = history;
  const grantedBy = new Map<string, ReadonlySet<string>>();
  for (const member of members) {
    const person = member.userId.toLowerCase();
    const granted = new Set(byMembership.get(member.id.toLowerCase()));
    for (const invitation of acceptedBy.get(person) ?? []) {
      for (const granter of byInvitation.get(invitation) ?? []) granted.add(granter);
    }
    granted.delete(person);
    grantedBy.set(member.id.toLowerCase(), granted);
  }
  return { members, grantedBy, lastVerifierLoss };
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
  const verifier = find(verifierId);
  if (verifier.status !== 'ACTIVE' || !mayVerify(verifier.role)) {
    return { outcome: 'refused', reason: 'NOT_A_VERIFIER' };
  }
  const why = ineligibility(facts, verifier, enterer, now);
  if (why === undefined) return { outcome: 'two_person' };
  if (facts.members.some((member) => ineligibility(facts, member, enterer, now) === undefined)) {
    return { outcome: 'refused', ...why };
  }
  // No one eligible: the single-user path, unless a verifier was taken away lately.
  if (facts.lastVerifierLoss !== undefined) {
    const reopens = new Date(facts.lastVerifierLoss.getTime() + SOLO_PATH_LOCK_DAYS * DAY_MS);
    if (now.getTime() < reopens.getTime()) return { outcome: 'refused', reason: 'SOLO_PATH_LOCKED', until: reopens };
  }
  return { outcome: 'single_user' };
}
