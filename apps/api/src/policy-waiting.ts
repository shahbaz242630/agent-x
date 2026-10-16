// The waiting requests a policy change would reject (PRD §5; BR-06, BR-09;
// Phase 3 E5d; partner decision 19, S117, their catch): a request waiting for
// approval that the new rules refuse is rejected when its approver confirms
// (decision 18, E5b), and until then its money stays held. So before saving,
// the admin sees which ones the change would reject, and why, and chooses
// (E5d-b) to reject them now or leave them for their approvers.
//
// Listed, oldest first, is each waiting request this change alone would turn
// into a rejection (partner, S118: not one the rules in force refuse already,
// which stays with its approver):
//
// - one its approver may approve today: its key not revoked, the mandate's
//   version and the supplier's details those it was decided against (one
//   moved, even carried by a pause, is its approver's to re-check, E5a), and
//   within its 72 hours (E4b, from its decision's sealed time);
// - holding its capacity under the rules in force, weighed with every older
//   one waiting counted;
// - refused under the new rules only by rules the team set (`rejectedFor`: a
//   stop is never a rejection), weighed with the older ones that stay counted
//   (as a carry's, mandate-carry.ts): when a lower cap can't hold them all,
//   the oldest stand, and once the younger ones go each approval left weighs
//   what this plan did.
//
// The organisation's change weighs every agent's; a mandate's, that mandate's
// agent's alone. At most 20 are listed, `more` saying there are others (the
// partner, S118: the change still saves; only rejecting them all at once is
// refused); past 100 waiting none is weighed, and `more` says so.
//
// Reads (partner, S116: no row-by-row reads): the waiting requests' IDs in
// one statement, then for each agent with any: the agent (3), its mandate in
// force and the policies (4), then as a carry reads one mandate's
// (`heldAuthority`, `requestsHeld`), the keys the requests' signed states
// name, and what holds capacity outside them (`outsideOf`); each request
// weighed twice in memory. All FOR SHARE, so the keys read after the requests
// wait on nothing they hold: a key's revoke locks no request.
import { agentKeyOf } from '@agentx/core/modules/agents';
import type { SignedStates } from '@agentx/core/modules/audit';
import type { DecisionMade } from '@agentx/core/modules/policies';
import { type PolicyRules } from '@agentx/core/modules/mandates';
import {
  decidedAgainst,
  holdsCapacity,
  SPEND_REQUESTS,
  type SpendRequestRecord,
  waitedOut,
} from '@agentx/core/modules/spend-requests';
import type { Money } from '@agentx/core/shared-kernel';
import type { DatabaseTransaction } from '@agentx/platform/db';

import { rejectedFor, type RuleDenial } from './approval-rejections.ts';
import {
  distinct,
  heldAuthority,
  known,
  outsideOf,
  type PendingRow,
  requestsHeld,
  weighedInOrder,
  type WeighScope,
} from './mandate-carry.ts';
import { MandateRefused } from './mandate-reads.ts';
import { proposedRules } from './policy-simulations.ts';
import { agentAlone, authorityIn, type DecisionTables, type PoliciesWeighed } from './spend-request-decisions.ts';

type WaitingTx = DatabaseTransaction<DecisionTables>;

/** The most waiting requests one change weighs: past it none is, and the plan says there are more. */
const MOST_WAITING_WEIGHED = 100;

/** The most a change lists, and rejects at once (as a brake voids, or a carry carries: 20). */
const MOST_WAITING_REJECTED = 20;

/** One waiting request the change would reject: whose, how much, and the team's rules that would refuse it. */
interface WaitingRejected {
  readonly id: string;
  readonly agentId: string;
  readonly amount: Money;
  readonly reasons: readonly RuleDenial[];
}

/** The requests the change would reject, oldest first, at most 20; `more`: others not listed. */
export interface WaitingPlan {
  readonly rejected: readonly WaitingRejected[];
  readonly more: boolean;
}

/** What a change weighs: whose, when, which policy (a mandate's by its ID, or null: the organisation's), and its new rules. */
export interface WaitingScope {
  readonly orgId: string;
  readonly now: Date;
  readonly mandateId: string | null;
  readonly rules: PolicyRules;
}

/** A waiting request as its row names it: whose, and what its authority is read by. */
interface WaitingRow extends PendingRow {
  readonly agent_id: string;
}

/**
 * The waiting requests the change would reject, as above. One whose signed
 * state, history or holdings can't be believed: INTEGRITY_FAILED.
 */
export async function waitingPlan(tx: WaitingTx, states: SignedStates, scope: WaitingScope): Promise<WaitingPlan> {
  const { orgId, mandateId } = scope;
  let waiting = tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs and facts alone, each held to its signed state (requestsHeld)
    .selectFrom(SPEND_REQUESTS.table)
    .select(['id', 'agent_id', 'supplier_id', 'funding_source_id'])
    .where('org_id', '=', orgId)
    .where('status', '=', 'APPROVAL_REQUIRED');
  if (mandateId !== null) waiting = waiting.where('mandate_id', '=', mandateId);
  const rows = await waiting
    .orderBy('created_at')
    .orderBy('id')
    .limit(MOST_WAITING_WEIGHED + 1)
    .execute();
  if (rows.length > MOST_WAITING_WEIGHED) return { rejected: [], more: true };
  const rejected: WaitingRejected[] = [];
  for (const agentId of distinct(rows.map((row) => row.agent_id))) {
    const own = rows.filter((row) => row.agent_id === agentId);
    rejected.push(...(await rejectedOf(tx, states, { ...scope, agentId, decides: false }, own)));
  }
  const age = new Map(rows.map(({ id }, at) => [id, at]));
  rejected.sort((one, other) => known(age.get(one.id)) - known(age.get(other.id)));
  return { rejected: rejected.slice(0, MOST_WAITING_REJECTED), more: rejected.length > MOST_WAITING_REJECTED };
}

/** One agent's waiting requests the change would reject: none with no mandate in force. */
async function rejectedOf(
  tx: WaitingTx,
  states: SignedStates,
  scope: WeighScope & WaitingScope,
  rows: readonly WaitingRow[],
): Promise<readonly WaitingRejected[]> {
  const { orgId, agentId, now } = scope;
  // 3: the agent.
  const agent = await agentAlone(tx, states, { orgId, agentId });
  // 4: the mandate in force, its policy and the organisation's.
  const { mandate, ...inForce } = await authorityIn(tx, states, orgId, agentId);
  if (mandate === null) return [];
  // 5–7, the requests (8), the keys they were asked with, then what holds capacity outside them.
  const authority = await heldAuthority(tx, states, scope, rows, mandate);
  const read = await requestsHeld(tx, states, scope, rows);
  const asked = read.map(({ request, state }) => ({ request, against: decidedAgainst(state) }));
  const revoked = await revokedKeys(
    tx,
    states,
    orgId,
    asked.map(({ against }) => against.agentKeyId),
  );
  const requests = read.map(({ request }) => request);
  const outside = await outsideOf(tx, scope, authority, requests);

  const approvable = new Set(
    asked
      .filter(
        ({ request, against }) =>
          request.status === 'APPROVAL_REQUIRED' &&
          !revoked.has(against.agentKeyId.toLowerCase()) &&
          against.mandateVersionId === mandate.versionId &&
          against.supplierVersionId === known(authority.suppliers.get(request.supplierId)).currentVersionId &&
          !waitedOut(known(authority.decidedAt.get(request.id)), now),
      )
      .map(({ request }) => request.id),
  );
  const weighing = { now, agent };
  const heldToday = new Set(
    weighedInOrder(weighing, authority, inForce, outside, requests, () => true)
      .filter(({ made }) => holdsCapacity(made.decision))
      .map(({ request }) => request.id),
  );
  const goes = (request: SpendRequestRecord, { decision, reasons }: DecisionMade): boolean =>
    approvable.has(request.id) &&
    heldToday.has(request.id) &&
    !holdsCapacity(decision) &&
    rejectedFor(decision, reasons) !== null;
  return weighedInOrder(
    weighing,
    authority,
    proposedPolicies(inForce, scope),
    outside,
    requests,
    (request, made) => !goes(request, made),
  )
    .filter(({ stays }) => !stays)
    .map(({ request, made }) => ({
      id: request.id,
      agentId,
      amount: request.amount,
      reasons: known(rejectedFor(made.decision, made.reasons)),
    }));
}

/**
 * The policies with the change's rules in place of those in force, as the
 * simulator weighs them: the organisation's, chosen (E2); or the mandate's.
 * A mandate's change weighs only that mandate's requests, and one decided
 * under another version than the one in force is its approver's, never listed.
 */
function proposedPolicies(inForce: PoliciesWeighed, { mandateId, rules }: WaitingScope): PoliciesWeighed {
  return mandateId === null
    ? { ...inForce, organizationPolicy: proposedRules(rules), organizationCapChosen: true }
    : { ...inForce, mandatePolicy: proposedRules(rules) };
}

/** Of the keys named, those revoked, by ID in lower case, each read once. One that can't be believed: INTEGRITY_FAILED. */
async function revokedKeys(
  tx: WaitingTx,
  states: SignedStates,
  orgId: string,
  ids: readonly string[],
): Promise<ReadonlySet<string>> {
  const revoked = new Set<string>();
  for (const id of distinct(ids.map((named) => named.toLowerCase()))) {
    const key = await agentKeyOf(tx, states, { orgId, id }, 'share');
    // Every request names its key (0039's foreign key): one not found, as one tampered with, can't be believed.
    if (key.outcome !== 'found') integrityFailed();
    if (key.key.status === 'REVOKED') revoked.add(id);
  }
  return revoked;
}

function integrityFailed(): never {
  throw new MandateRefused(503, 'INTEGRITY_FAILED');
}
