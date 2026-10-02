// The two-person rule's facts (domain/two-person.ts; ADR-012 §1, SEC-PAY-04;
// E3-1), read in the caller's transaction: every member, verified through
// their signed state, and the organisation's history of memberships and
// invitations from its log, each event believed only whole. Either found
// tampered with raises the alarm and holds the organisation.
//
// Reads only. An event deleted from the history, to make a member look as if
// the enterer never granted their role, breaks the chain, which the anchor
// check finds (A2b), as for the removal restriction's reads.
import type { SignedStates, TamperSign } from '../../audit/index.ts';
import { HISTORY_SUBJECTS, type TwoPersonFacts, twoPersonFacts } from '../domain/two-person.ts';
import { membersOf, type MembershipsTransaction } from './memberships.ts';

/**
 * The most events about memberships and invitations one read takes: past it
 * the read throws (TooManyEventsToRead) rather than decide on part of the
 * history. About 5 an invitation, so some 2,000 invitations.
 */
export const MOST_HISTORY_EVENTS = 10_000;

/** The rule's facts; or tampered with, with the alarm raised. */
export type TwoPersonFactsCheck =
  ({ readonly outcome: 'read' } & TwoPersonFacts) | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/**
 * The two-person rule's facts for the organisation, in the caller's
 * transaction, which must be withSignedStates' for it: its members read for a
 * decision (`share`), and its history of memberships and invitations.
 */
export async function twoPersonFactsOf(
  tx: MembershipsTransaction,
  states: SignedStates,
  orgId: string,
): Promise<TwoPersonFactsCheck> {
  const members = await membersOf(tx, states, orgId);
  if (members.outcome === 'tampered') return members;
  const history = await states.historyOf(tx, orgId, { subjectTypes: HISTORY_SUBJECTS, limit: MOST_HISTORY_EVENTS });
  if (history.outcome === 'tampered') return history;
  return { outcome: 'read', ...twoPersonFacts(members.members, history.events) };
}
