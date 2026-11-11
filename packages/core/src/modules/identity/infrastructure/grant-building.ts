// The grant summaries of memberships added before 0085 built (OR1): each from
// the organisation's history, read a page at a time from its start, so no
// length of history stops it, and sealed. Signing takes the app's keys, so no
// migration can; the API's job runs this for each organisation
// (apps/api/src/grant-summaries.ts), and the rule reads the history for an
// organisation with one unbuilt meanwhile (two-person-facts.ts).
//
// In one transaction, withSignedStates' for the organisation: its memberships
// read for a decision (`share`), so no change of one comes between the
// history read and the summary built from it; then each summary for the
// change, after its membership (ADR-006 §6, 2a). A summary already kept must
// hold at least what the history says, at its membership's version, or it is
// a mismatch: the alarm, and the hold.
import { type AuditActor, checkOf, type SignedStates, type TamperSign } from '../../audit/index.ts';
import {
  gatherGrants,
  grantHistory,
  HISTORY_SUBJECTS,
  type GrantSummary,
  summaryFromHistory,
} from '../domain/two-person.ts';
import { addGrants, type GrantsCheck, grantsToChange } from './membership-grants.ts';
import { MEMBERSHIPS, type MembershipsTransaction } from './memberships.ts';
import { membersFrom, membershipsMade, MOST_HISTORY_EVENTS, summariesAgree } from './two-person-facts.ts';

/** Who builds a summary: the API's job, as the log names it. */
export const BUILDER: AuditActor = { type: 'system', id: 'api' };

/** What a build did: how many summaries it built (none: every one was there); or tampered with (the alarm raised). */
export type GrantBuilding =
  { readonly outcome: 'built'; readonly built: number } | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/**
 * Builds and seals the summary of each of the organisation's memberships that
 * has none, in the caller's transaction, which must be withSignedStates' for
 * it. `page`: how many events a read of the history takes.
 */
export async function buildGrantSummaries(
  tx: MembershipsTransaction,
  states: SignedStates,
  orgId: string,
  page = MOST_HISTORY_EVENTS,
): Promise<GrantBuilding> {
  const made = await membershipsMade(tx, states, orgId);
  if (made.outcome === 'tampered') return made;
  if (made.ids.length === 0) return { outcome: 'built', built: 0 };
  const checks = await states.verifiedStates(tx, MEMBERSHIPS, orgId, made.ids);
  const verified = membersFrom(states, orgId, made, (id) => checkOf(checks, id));
  if (verified.outcome === 'tampered') return verified;
  const kept = new Map<string, Extract<GrantsCheck, { readonly outcome: 'kept' }>>();
  const unbuilt: string[] = [];
  for (const { id } of verified.members) {
    const grants = await grantsToChange(tx, states, { orgId, id });
    if (grants.outcome === 'tampered') return grants;
    if (grants.outcome === 'unbuilt') unbuilt.push(id);
    else kept.set(id, grants);
  }
  if (unbuilt.length === 0) return { outcome: 'built', built: 0 };
  const whole = await wholeHistory(tx, states, orgId, verified.members, page);
  if (whole.outcome === 'tampered') return whole;
  const fromHistory = whole.summaries;
  if (!summariesAgree(states, orgId, verified, kept, fromHistory)) return { outcome: 'tampered', sign: 'holding' };
  for (const id of unbuilt) {
    const summary = fromHistory.get(id);
    const version = verified.versions.get(id);
    // Both read for every member just above.
    if (summary === undefined || version === undefined) throw new Error(`A member was read and not judged: ${id}`);
    await addGrants(tx, states, { orgId, id }, summary, version, { actor: BUILDER, action: 'membership_grant.built' });
  }
  return { outcome: 'built', built: unbuilt.length };
}

/** Each member's summary as the whole history holds it, read `page` events at a time from the start; or tampered with. */
async function wholeHistory(
  tx: MembershipsTransaction,
  states: SignedStates,
  orgId: string,
  members: readonly { readonly id: string; readonly userId: string }[],
  page: number,
): Promise<
  | { readonly outcome: 'read'; readonly summaries: ReadonlyMap<string, GrantSummary> }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign }
> {
  const history = grantHistory();
  let after: bigint | undefined;
  for (;;) {
    const read = await states.historyOf(tx, orgId, {
      subjectTypes: HISTORY_SUBJECTS,
      limit: page,
      oldest: true,
      ...(after === undefined ? {} : { afterSeq: after }),
    });
    if (read.outcome === 'tampered') return read;
    gatherGrants(history, read.events);
    const last = read.events.at(-1);
    if (read.events.length < page || last === undefined) break;
    after = last.seq;
  }
  return {
    outcome: 'read',
    summaries: new Map(members.map((member) => [member.id, summaryFromHistory(history, member)])),
  };
}
