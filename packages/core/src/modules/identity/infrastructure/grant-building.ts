// The grant summaries of memberships added before 0085 built (OR1): each from
// the organisation's history, read a page at a time from its start, so no
// length of history stops it, and sealed. Signing takes the app's keys, so no
// migration can; the API's job runs this for each organisation
// (apps/api/src/grant-summaries.ts), and the rule reads the history for an
// organisation with one unbuilt meanwhile (two-person-facts.ts).
//
// A summary left behind its membership is raised as the alarm first (OR1c:
// since 0089 no image in service leaves one; two-person-facts.ts), then brought
// up to date the same way: what the history says, with nothing it held taken
// away. Why: only the app's keys can sign it, so without this a hold cleared
// once someone has looked would be raised again by the very next read. Its
// hold is kept waiting (directory.holds_waiting, one row naming the first
// behind) in the same transaction as the repair, after it, so the hold is never
// lost with the evidence.
//
// In one transaction, withSignedStates' for the organisation: its memberships
// read for a decision (`share`), so no change of one comes between the
// history read and the summary built from it; then each summary for the
// change, after its membership (ADR-006 §6, 2a). A summary in step must hold
// at least what the history says, and none may be ahead of its membership, or
// it is a mismatch: the alarm, and the hold.
import {
  type AuditActor,
  checkOf,
  keepHoldWaitingHere,
  type SignedStates,
  type TamperSign,
} from '../../audit/index.ts';
import {
  gatherGrants,
  grantHistory,
  HISTORY_SUBJECTS,
  type GrantSummary,
  summaryFromHistory,
} from '../domain/two-person.ts';
import { addGrants, bringUpToDate, grantsToChange, MEMBERSHIP_GRANTS } from './membership-grants.ts';
import { MEMBERSHIPS, type MembershipsTransaction } from './memberships.ts';
import {
  behindRaised,
  type KeptGrants,
  membersFrom,
  membershipsMade,
  MOST_HISTORY_EVENTS,
  summariesCover,
  summariesInStep,
} from './two-person-facts.ts';

/** Who builds a summary: the API's job, as the log names it. */
export const BUILDER: AuditActor = { type: 'system', id: 'api' };

/** What a build did: how many summaries it built or brought up to date (none: every one was in step); or tampered with (the alarm raised). */
export type GrantBuilding =
  { readonly outcome: 'built'; readonly built: number } | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** Each member's summary read for the change, after its membership: kept, or unbuilt; or the first tampered with. */
async function grantsRead(
  tx: MembershipsTransaction,
  states: SignedStates,
  orgId: string,
  members: readonly { readonly id: string }[],
): Promise<
  | { readonly outcome: 'read'; readonly kept: ReadonlyMap<string, KeptGrants>; readonly unbuilt: readonly string[] }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign }
> {
  const kept = new Map<string, KeptGrants>();
  const unbuilt: string[] = [];
  for (const { id } of members) {
    const grants = await grantsToChange(tx, states, { orgId, id });
    if (grants.outcome === 'tampered') return grants;
    if (grants.outcome === 'unbuilt') unbuilt.push(id);
    else kept.set(id, grants);
  }
  return { outcome: 'read', kept, unbuilt };
}

/**
 * Builds and seals the summary of each of the organisation's memberships that
 * has none, and brings up to date each left behind its membership, its alarm
 * raised (the hold set as the transaction ends), in the
 * caller's transaction, which must be withSignedStates' for it. `page`: how
 * many events a read of the history takes.
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
  const read = await grantsRead(tx, states, orgId, verified.members);
  if (read.outcome === 'tampered') return read;
  const disagrees = { outcome: 'tampered', sign: 'holding' } as const;
  const inStep = summariesInStep(states, orgId, verified, read.kept);
  if (inStep === undefined) return disagrees;
  behindRaised(states, orgId, inStep.behind);
  const due = [...read.unbuilt, ...inStep.behind];
  if (due.length === 0) return { outcome: 'built', built: 0 };
  const whole = await wholeHistory(tx, states, orgId, verified.members, page);
  if (whole.outcome === 'tampered') return whole;
  if (!summariesCover(states, orgId, verified, inStep.current, whole.summaries)) return disagrees;
  const change = { actor: BUILDER, action: 'membership_grant.built' } as const;
  for (const id of due) {
    const summary = whole.summaries.get(id);
    const version = verified.versions.get(id);
    // Both read for every member just above.
    if (summary === undefined || version === undefined) throw new Error(`A member was read and not judged: ${id}`);
    const behind = read.kept.get(id);
    if (behind === undefined) await addGrants(tx, states, { orgId, id }, summary, version, change);
    else await bringUpToDate(tx, states, behind, { orgId, id }, { summary, membershipVersion: version, ...change });
  }
  const first = inStep.behind[0];
  // Why: the repair above takes the evidence away once it commits, so its hold is kept waiting in this same transaction
  // (with-signed-states.ts): if the hold then can't be recorded, the row outlives a restart and sets it. After the
  // repair, so the chain head's lock is held already, as a hold's own transaction takes it before writing this row; one
  // row, naming the first, the record this transaction's finding holds: one hold holds the organisation.
  if (first !== undefined) {
    const record = {
      orgId: orgId.toLowerCase(),
      subjectType: MEMBERSHIP_GRANTS.subject,
      objectId: first.toLowerCase(),
    };
    await keepHoldWaitingHere(tx, record, 'holding');
  }
  return { outcome: 'built', built: due.length };
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
