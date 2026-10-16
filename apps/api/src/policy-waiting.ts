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
// - holding its capacity under the rules in force, weighed as its approver's
//   confirm weighs it, with every other one waiting counted;
// - refused under the new rules only by rules the team set (`rejectedFor`: a
//   stop is never a rejection), weighed with every one that can't go counted
//   and the older ones that stay (as a carry's, mandate-carry.ts): when a
//   lower cap can't hold them all, the oldest stand. The youngest that stays
//   was weighed with all that stay, so once those listed go, each approval
//   left weighs no more than this plan did, but for a request decided while
//   the confirm ran unlocked (below), which only ever leaves one unlisted.
//
// The confirm holds the policy it changes for the change, so no decision or
// approval weighing it gets past it meanwhile: the organisation's always
// (E2 sets it before any agent spends), a mandate's from its second
// version. A mandate's first has no row to hold (S118 review, 82): one
// decided under the mandate meanwhile, under the rules then in force, may be
// left out of the plan; its approver weighs it again under the new rules
// (decision 18). The plan errs to rejecting fewer, never more.
//
// The organisation's change weighs every agent's; a mandate's, that mandate's
// agent's alone. At most 20 are listed, `more` saying there are others (the
// partner, S118: the change still saves; only rejecting them all at once is
// refused). Past 100 waiting the oldest 100 are weighed (their catch, S118:
// the oldest are still shown), the younger counted as holding what they hold,
// as `leave`, the only choice then, leaves them: so one listed is one each
// approver's confirm would reject with them all still waiting.
//
// Reads (partner, S116: no row-by-row reads): the waiting requests' IDs in
// one statement, then for each agent with any: the agent (3), its mandate in
// force and the policies (4), then as a carry reads one mandate's
// (`heldAuthority`, `requestsHeld`), the keys the requests' signed states
// name, and what holds capacity outside them (`outsideOf`); then weighed in
// memory, today each against all the others (at most 100 × 100 weighings),
// under the new rules once. One ended since its row was read is left out. All
// FOR SHARE, so the keys read after the requests wait on nothing they hold: a
// key's revoke locks no request.
import { agentKeyOf } from '@agentx/core/modules/agents';
import type { AuditDetails, SignedStates } from '@agentx/core/modules/audit';
import type { DecisionMade } from '@agentx/core/modules/policies';
import { type PolicyRules } from '@agentx/core/modules/mandates';
import {
  decidedAgainst,
  holdsCapacity,
  rejectRequest,
  SPEND_REQUESTS,
  type SpendRequestRecord,
  waitedOut,
} from '@agentx/core/modules/spend-requests';
import type { Money } from '@agentx/core/shared-kernel';
import type { DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { z } from 'zod';

import { rejectedFor, rejectionNote, type RuleDenial } from './approval-rejections.ts';
import {
  distinct,
  heldAuthority,
  known,
  outsideOf,
  type PendingRow,
  requestsHeld,
  weighedInOrder,
} from './mandate-carry.ts';
import { MandateRefused } from './mandate-reads.ts';
import { proposedRules } from './policy-simulations.ts';
import {
  agentAlone,
  type DecisionTables,
  mandateWeighedIn,
  type MandateWeighed,
  policiesIn,
  type PoliciesWeighed,
} from './spend-request-decisions.ts';

type WaitingTx = DatabaseTransaction<DecisionTables>;

/** The most waiting requests one change weighs, the oldest: past it the plan says there are more. */
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

/** What the admin chooses for the waiting requests the change would reject (decision 19): no default. */
const WAITING_CHOICES = ['reject', 'leave'] as const;
export type WaitingChoice = (typeof WAITING_CHOICES)[number];

/** The words each choice is confirmed with, by version: the console's confirm shows them, the policy's event keeps the version. */
const WAITING_STATEMENTS = {
  reject:
    'Once you confirm, each request listed is rejected at once and the money held for it freed, with the rules that ' +
    'refuse it kept on its record; the agent learns only that a person rejected it, and asks again. At most 20 can ' +
    'be rejected at once.',
  leave:
    'Once you confirm, the requests listed keep waiting and their money stays held. Each is rejected, with why and ' +
    'what to do, when its approver approves it under the new rules, or it expires after its 72 hours.',
} as const satisfies Record<WaitingChoice, string>;

/** The version of WAITING_STATEMENTS each change names: raised with any change to their words. */
const WAITING_STATEMENT_VERSION = 1;

/** A change's choice, as its bodies name it: only when the change would reject a waiting request. */
export const WAITING_REQUESTS = z
  .enum(WAITING_CHOICES)
  .describe(
    'What happens to the requests waiting for approval that these rules would reject (the preview lists them), ' +
      'chosen by the admin; there is no default, and a change that would reject none takes none. ' +
      `\`reject\`: ${WAITING_STATEMENTS.reject} \`leave\`: ${WAITING_STATEMENTS.leave}`,
  );

/**
 * The choice checked against the plan: one is needed when the change would
 * reject any (or more than 100 wait, the younger not weighed), and refused otherwise;
 * `reject` only when every one is listed (at most 20, partner S118: `leave`
 * saves the change whatever the count).
 */
export function waitingChosen(plan: WaitingPlan, choice: WaitingChoice | undefined): WaitingChoice | null {
  const offered = plan.rejected.length > 0 || plan.more;
  if (!offered) {
    if (choice !== undefined) throw new MandateRefused(400, 'WAITING_CHOICE_NOT_OFFERED');
    return null;
  }
  if (choice === undefined) throw new MandateRefused(409, 'WAITING_CHOICE_REQUIRED');
  if (choice === 'reject' && plan.more) throw new MandateRefused(409, 'WAITING_REQUESTS_TOO_MANY_TO_REJECT');
  return choice;
}

/** The choice and the plan as the change's step-up binds them: anything another between ask and confirm refuses it. */
export const waitingHashParts = (choice: WaitingChoice | null, plan: WaitingPlan): readonly string[] =>
  choice === null
    ? ['none']
    : [
        choice,
        String(WAITING_STATEMENT_VERSION),
        String(plan.more),
        ...plan.rejected.map(({ id, reasons }) => `${id.toLowerCase()}:${reasons.join(',')}`),
      ];

/** The choice as the policy's event keeps it, with its words' version and how many were listed. */
export const waitingDetails = (choice: WaitingChoice | null, plan: WaitingPlan) =>
  choice === null
    ? {}
    : {
        waitingRequests: choice,
        waitingStatementVersion: WAITING_STATEMENT_VERSION,
        waitingListed: plan.rejected.length,
        waitingMore: plan.more,
      };

/**
 * `reject` carried out, in the confirm's transaction after its step-up is
 * consumed, each request read for change by the plan: rejected as the
 * admin's, with the rules that refuse it kept whole as `causes` and the
 * policy version that does, its reservation and order claim released (as
 * an approver's rejection, decision 18).
 */
export async function rejectWaiting(
  tx: WaitingTx,
  states: SignedStates,
  keys: KeyProvider,
  plan: WaitingPlan,
  { orgId, userId, evidence, now }: { orgId: string; userId: string; evidence: AuditDetails; now: Date },
): Promise<void> {
  for (const { id, reasons } of plan.rejected) {
    await rejectRequest(
      tx,
      states,
      keys,
      { orgId, id },
      { userId, reason: rejectionNote(reasons, 'policy'), stepUp: { ...evidence, causes: reasons.join(',') } },
      now,
    );
  }
}

/**
 * The waiting requests the change would reject, as above, read as the ask or
 * preview reads them (FOR SHARE), or as the confirm (`decides`) does: in the
 * lock order (ADR-006 §6) for every agent at once, each level before the
 * next, so a brake or an acceptance waiting on one of them never waits on it
 * crosswise. The agents (3) and their mandates in force (4); then `locked`,
 * where the confirm takes the policy for change (4, after the mandates);
 * the policies (4, read once the one changed is held); the requests' IDs read again, any other set than
 * before, or younger ones waiting where none did (or none where some did), refused as STEP_UP_FAILED (one decided between: the plan isn't the
 * one weighed); the sources (5) and suppliers (6), FOR SHARE; every request
 * (8), locked for change in one statement in order of ID; then the keys and
 * the totals, locking nothing. One whose signed state, history or holdings
 * can't be believed: INTEGRITY_FAILED.
 */
export async function waitingPlan(
  tx: WaitingTx,
  states: SignedStates,
  scope: WaitingScope,
  { decides, locked }: { readonly decides: boolean; readonly locked?: () => Promise<void> } = { decides: false },
): Promise<WaitingPlan> {
  const { rows, beyond } = await waitingRows(tx, scope);
  const agents = distinct(rows.map((row) => row.agent_id));
  const inForce = new Map<string, Awaited<ReturnType<typeof inForceOf>>>();
  for (const agentId of agents) inForce.set(agentId, await inForceOf(tx, states, scope.orgId, agentId));
  await locked?.();
  if (decides) {
    const again = await waitingRows(tx, scope);
    const same = again.beyond === beyond && again.rows.map(({ id }) => id).join() === rows.map(({ id }) => id).join();
    if (!same) throw new MandateRefused(403, 'STEP_UP_FAILED');
  }
  const weighed: AgentWeighed[] = [];
  for (const agentId of agents) {
    const { agent, mandate } = known(inForce.get(agentId));
    if (mandate === null) continue;
    // 4, the policies: at the confirm once its own is held for the change.
    const policies = await policiesIn(tx, states, scope.orgId, mandate);
    const own = rows.filter((row) => row.agent_id === agentId);
    // 5–7 FOR SHARE, no month locked: the policy held for the change keeps decisions and approvals out (above).
    const authority = await heldAuthority(tx, states, { ...scope, agentId, decides: false }, own, mandate);
    weighed.push({ ...policies, agent, agentId, mandate, authority, rows: own });
  }
  // 8: every request, in one statement in order of ID, before any is read for its change.
  if (decides)
    await lockRequests(
      tx,
      scope.orgId,
      weighed.flatMap(({ rows: own }) => own.map(({ id }) => id)),
    );
  const rejected: WaitingRejected[] = [];
  for (const agent of weighed) rejected.push(...(await rejectedOf(tx, states, { ...scope, decides }, agent)));
  const age = new Map(rows.map(({ id }, at) => [id, at]));
  rejected.sort((one, other) => known(age.get(one.id)) - known(age.get(other.id)));
  return {
    rejected: rejected.slice(0, MOST_WAITING_REJECTED),
    more: beyond || rejected.length > MOST_WAITING_REJECTED,
  };
}

/** The oldest waiting requests' IDs and facts, at most MOST_WAITING_WEIGHED, unlocked; `beyond`: younger ones wait. */
async function waitingRows(
  tx: WaitingTx,
  { orgId, mandateId }: WaitingScope,
): Promise<{ readonly rows: readonly WaitingRow[]; readonly beyond: boolean }> {
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
  return { rows: rows.slice(0, MOST_WAITING_WEIGHED), beyond: rows.length > MOST_WAITING_WEIGHED };
}

/** Levels 3 and 4 for one agent: the agent, and its mandate in force. */
async function inForceOf(tx: WaitingTx, states: SignedStates, orgId: string, agentId: string) {
  return {
    agent: await agentAlone(tx, states, { orgId, agentId }),
    mandate: await mandateWeighedIn(tx, states, orgId, agentId),
  };
}

/** The requests locked for change, in one statement in order of ID (8). */
async function lockRequests(tx: WaitingTx, orgId: string, ids: readonly string[]): Promise<void> {
  if (ids.length === 0) return;
  await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- the lock alone; each is verified as it is read
    .selectFrom(SPEND_REQUESTS.table)
    .select('id')
    .where('org_id', '=', orgId)
    .where('id', 'in', ids)
    .orderBy('id')
    .forNoKeyUpdate()
    .execute();
}

/** One agent with its waiting requests, read to level 7: what its requests are weighed under. */
interface AgentWeighed extends PoliciesWeighed {
  readonly agentId: string;
  readonly agent: Awaited<ReturnType<typeof agentAlone>>;
  readonly mandate: MandateWeighed;
  readonly authority: Awaited<ReturnType<typeof heldAuthority>>;
  readonly rows: readonly WaitingRow[];
}

/** One agent's waiting requests the change would reject. */
async function rejectedOf(
  tx: WaitingTx,
  states: SignedStates,
  scope: WaitingScope & { readonly decides: boolean },
  { agentId, agent, mandate, authority, rows, ...inForce }: AgentWeighed,
): Promise<readonly WaitingRejected[]> {
  const { orgId, now } = scope;
  // 8, read (for change at the confirm, each locked already), then the keys they were asked with and the totals.
  const read = await requestsHeld(tx, states, { orgId, agentId, now, decides: scope.decides }, rows, 'left out');
  const asked = read.map(({ request, state }) => ({ request, against: decidedAgainst(state) }));
  const revoked = await revokedKeys(
    tx,
    states,
    orgId,
    asked.map(({ against }) => against.agentKeyId),
  );
  const requests = asked.map(({ request }) => request);
  const outside = await outsideOf(tx, { agentId, now }, authority, requests);

  /** The requests weighed in `order` (their indexes), each against those before it, as weighedInOrder does. */
  const inOrder = (
    order: readonly number[],
    policies: PoliciesWeighed,
    stays: (request: SpendRequestRecord, made: DecisionMade) => boolean,
  ) =>
    weighedInOrder(
      { now, agent },
      authority,
      policies,
      { ...outside, orders: order.map((at) => known(outside.orders[at])) },
      order.map((at) => known(requests[at])),
      stays,
    );
  const all = requests.map((_, at) => at);
  // Its approver may approve it today, and today's rules, weighed as an approver's confirm weighs them (against
  // every other one waiting: each last, so at most 100 × 100 weighings in memory), let it hold its capacity.
  const candidates = new Set(
    all.filter((at) => {
      const { request, against } = known(asked[at]);
      const today = inOrder([...all.filter((other) => other !== at), at], inForce, () => true).at(-1);
      return (
        request.status === 'APPROVAL_REQUIRED' &&
        !revoked.has(against.agentKeyId.toLowerCase()) &&
        against.mandateVersionId === mandate.versionId &&
        against.supplierVersionId === known(authority.suppliers.get(request.supplierId)).currentVersionId &&
        !waitedOut(known(authority.decidedAt.get(request.id)), now) &&
        holdsCapacity(known(today).made.decision)
      );
    }),
  );
  // Those that can't go stay whatever the rules: counted for every candidate, so weighed first.
  const order = [...all.filter((at) => !candidates.has(at)), ...all.filter((at) => candidates.has(at))];
  const goes = (request: SpendRequestRecord, { decision, reasons }: DecisionMade): boolean =>
    candidates.has(requests.indexOf(request)) && rejectedFor(decision, reasons) !== null;
  return inOrder(order, proposedPolicies(inForce, scope), (request, made) => !goes(request, made))
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
