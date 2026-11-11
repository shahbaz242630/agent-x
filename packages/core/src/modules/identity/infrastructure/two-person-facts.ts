// The two-person rule's facts (domain/two-person.ts; ADR-012 §1, SEC-PAY-04;
// E3-1; OR1), read in the caller's transaction: every membership the log made,
// verified through its signed state, and each one's grant summary, verified
// through its own (membership-grants.ts). Either found tampered with raises
// the alarm and holds the organisation.
//
// The memberships are those the organisation's log made (one event each, so a
// read bounded by the members, never by the history's length), and each must
// be listed in the directory for the person its signed state names: one the
// list no longer holds would make the organisation look smaller than it is
// and open the one-person path (gate H10's review), so it is a tamper sign.
//
// Each summary must have been kept at its membership's version: one a change
// left behind, or a membership moved on past it, disagrees and is a tamper
// sign too. A membership added before the summaries (0085) has none until the
// API's job builds it: while any member's is unbuilt the rule reads the
// organisation's history as it always has (at most MOST_HISTORY_EVENTS, past
// which it throws rather than decide on part of it), and every summary kept
// must hold at least what that history says.
//
// Up to MOST_GATHERED_MEMBERS members, the memberships and their summaries are
// read on one trip (gather); more, in four statements (verifiedStates, two a
// table). So the read is three trips for most organisations and six at most,
// where it was one a member and two more.
//
// Reads only. An event deleted from the log is the anchor check's to find
// (A2b), as for any read of the log.
import { MOST_ROWS_GATHERED, type GatheredRow } from '@agentx/platform/db';

import { checkOf, type SignedStates, type StateCheck, type TamperSign } from '../../audit/index.ts';
import { listedMembers } from '../../directory/index.ts';
import {
  factsFromSummaries,
  gatherGrants,
  type GrantSummary,
  grantHistory,
  historyFacts,
  HISTORY_SUBJECTS,
  summaryCovers,
  type TwoPersonFacts,
} from '../domain/two-person.ts';
import { type GrantsCheck, grantsFrom, MEMBERSHIP_GRANTS } from './membership-grants.ts';
import {
  memberFrom,
  type MemberRecord,
  MEMBERSHIPS,
  type MembershipsTransaction,
  MOST_MEMBERS,
  TooManyMembers,
} from './memberships.ts';

/**
 * The most events about memberships and invitations one read of the history
 * takes while a summary is unbuilt: past it the read throws
 * (TooManyEventsToRead) rather than decide on part of the history. About 5 an
 * invitation, so some 2,000 invitations. The job that builds the summaries
 * reads the history a page this long at a time, whatever its length.
 */
export const MOST_HISTORY_EVENTS = 10_000;

/** The most members whose memberships and summaries one gather reads, two rows each. */
const MOST_GATHERED_MEMBERS = MOST_ROWS_GATHERED / 2;

/** The rule's facts; or tampered with, with the alarm raised. */
export type TwoPersonFactsCheck =
  ({ readonly outcome: 'read' } & TwoPersonFacts) | { readonly outcome: 'tampered'; readonly sign: TamperSign };

interface Tampered {
  readonly outcome: 'tampered';
  readonly sign: TamperSign;
}

/** The organisation's members, each verified, with the version each membership's signed state has reached. */
export interface VerifiedMembers {
  readonly outcome: 'verified';
  readonly members: readonly MemberRecord[];
  readonly versions: ReadonlyMap<string, number>;
}

/**
 * Every membership the organisation's log made, by ID in lower case and in
 * order, and the directory's entries as membership-and-person pairs. More
 * than MOST_MEMBERS throws TooManyMembers, as a list of them does.
 */
export async function membershipsMade(
  tx: MembershipsTransaction,
  states: SignedStates,
  orgId: string,
): Promise<
  { readonly outcome: 'made'; readonly ids: readonly string[]; readonly listed: ReadonlySet<string> } | Tampered
> {
  // The oldest, never past the limit unseen: one more than the most there may be is enough to know there are more.
  const made = await states.historyOf(tx, orgId, {
    subjectTypes: [MEMBERSHIPS.subject],
    actions: ['membership.created'],
    limit: MOST_MEMBERS + 1,
    oldest: true,
  });
  if (made.outcome === 'tampered') return made;
  // Lower-case UUID text sorts as Postgres sorts the uuids: the lock order's.
  const ids = [...new Set(made.events.map(({ event }) => event.subject.id.toLowerCase()))].sort();
  if (ids.length > MOST_MEMBERS) throw new TooManyMembers();
  const entries = await listedMembers(tx, orgId, MOST_MEMBERS + 1);
  const listed = new Set(entries.map(({ membershipId, userId }) => pair(membershipId, userId)));
  return { outcome: 'made', ids, listed };
}

const pair = (membershipId: string, userId: string): string => `${membershipId.toLowerCase()}:${userId.toLowerCase()}`;

/**
 * The members from their memberships' checks, each listed for its own person;
 * or the first not to be (raised as a mismatch: the alarm, and the hold), or
 * tampered with (its alarm already raised).
 */
export function membersFrom(
  states: SignedStates,
  orgId: string,
  made: { readonly ids: readonly string[]; readonly listed: ReadonlySet<string> },
  check: (id: string) => StateCheck,
): VerifiedMembers | Tampered {
  const members: MemberRecord[] = [];
  const versions = new Map<string, number>();
  for (const id of made.ids) {
    const state = check(id);
    if (state.outcome === 'tampered') return state;
    // The log made it, so it has a signed state: none at all is as gone as a row deleted.
    if (state.outcome === 'missing' || !made.listed.has(pair(id, memberFrom(id, state).userId))) {
      states.mismatch(MEMBERSHIPS.subject, { orgId, id });
      return { outcome: 'tampered', sign: 'deleted' };
    }
    members.push(memberFrom(id, state));
    versions.set(id, state.version);
  }
  return { outcome: 'verified', members, versions };
}

/**
 * The checks of the rows of `table` named `ids`, read for a decision
 * (`share`): from what `gathered` read on one trip, or, past a gather's
 * reach, in two statements (verifiedStates).
 */
async function checksOf(
  tx: MembershipsTransaction,
  states: SignedStates,
  orgId: string,
  table: GatheredRow['table'],
  ids: readonly string[],
): Promise<ReadonlyMap<string, StateCheck>> {
  if (ids.length > MOST_GATHERED_MEMBERS) return states.verifiedStates(tx, table, orgId, ids);
  // Each answers from the gather, with no trip of its own, unless it wasn't believed there (then read alone).
  const checks = new Map<string, StateCheck>();
  for (const id of ids) checks.set(id, await states.verifiedState(tx, table, { orgId, id }, 'share'));
  return checks;
}

/** A few members' memberships and summaries on one trip, every membership before any summary (ADR-006 §6, 2a). */
async function gathered(
  tx: MembershipsTransaction,
  states: SignedStates,
  orgId: string,
  ids: readonly string[],
): Promise<void> {
  if (ids.length === 0 || ids.length > MOST_GATHERED_MEMBERS) return;
  const rows = (table: GatheredRow['table']): GatheredRow[] => ids.map((id) => ({ table, id: { id }, lock: 'share' }));
  await states.gather(tx, orgId, [...rows(MEMBERSHIPS), ...rows(MEMBERSHIP_GRANTS)]);
}

/**
 * Whether each kept summary is at its membership's version and, against the
 * history's when one was read, holds at least what it says; one that isn't is
 * raised as a mismatch (the alarm, and the hold).
 */
export function summariesAgree(
  states: SignedStates,
  orgId: string,
  { members, versions }: VerifiedMembers,
  kept: ReadonlyMap<string, Extract<GrantsCheck, { readonly outcome: 'kept' }>>,
  fromHistory?: ReadonlyMap<string, GrantSummary>,
): boolean {
  for (const member of members) {
    const grants = kept.get(member.id);
    if (grants === undefined) continue;
    const history = fromHistory?.get(member.id);
    if (
      grants.membershipVersion !== versions.get(member.id) ||
      (history !== undefined && !summaryCovers(grants.summary, history, member.status === 'ACTIVE'))
    ) {
      states.mismatch(MEMBERSHIP_GRANTS.subject, { orgId, id: member.id });
      return false;
    }
  }
  return true;
}

/**
 * The two-person rule's facts for the organisation, in the caller's
 * transaction, which must be withSignedStates' for it: its memberships and
 * their grant summaries read for a decision (`share`).
 */
export async function twoPersonFactsOf(
  tx: MembershipsTransaction,
  states: SignedStates,
  orgId: string,
): Promise<TwoPersonFactsCheck> {
  const made = await membershipsMade(tx, states, orgId);
  if (made.outcome === 'tampered') return made;
  await gathered(tx, states, orgId, made.ids);
  const memberships = await checksOf(tx, states, orgId, MEMBERSHIPS, made.ids);
  const verified = membersFrom(states, orgId, made, (id) => checkOf(memberships, id));
  if (verified.outcome === 'tampered') return verified;
  const summaries = await checksOf(tx, states, orgId, MEMBERSHIP_GRANTS, made.ids);
  const kept = new Map<string, Extract<GrantsCheck, { readonly outcome: 'kept' }>>();
  let unbuilt = false;
  for (const { id } of verified.members) {
    const grants = grantsFrom(checkOf(summaries, id));
    if (grants.outcome === 'tampered') return grants;
    if (grants.outcome === 'unbuilt') unbuilt = true;
    else kept.set(id, grants);
  }
  const disagrees = { outcome: 'tampered', sign: 'holding' } as const;
  if (!unbuilt) {
    if (!summariesAgree(states, orgId, verified, kept)) return disagrees;
    const held = new Map([...kept].map(([id, { summary }]) => [id, summary]));
    return { outcome: 'read', ...factsFromSummaries(verified.members, held) };
  }
  // A summary not built yet (a membership added before 0085): the history, as before the summaries.
  const read = await states.historyOf(tx, orgId, { subjectTypes: HISTORY_SUBJECTS, limit: MOST_HISTORY_EVENTS });
  if (read.outcome === 'tampered') return read;
  const history = grantHistory();
  gatherGrants(history, read.events);
  const fromHistory = historyFacts(verified.members, history);
  if (!summariesAgree(states, orgId, verified, kept, fromHistory.summaries)) return disagrees;
  const { facts } = fromHistory;
  return { outcome: 'read', ...facts };
}
