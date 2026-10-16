// Carrying a mandate's pending spend requests over to its new version (PRD
// §4.1, §11; BR-05, BR-09; Phase 3 E4c; partner decisions 15 and 17): the
// admin accepting the version chooses, with no default, to cancel them (as
// a supersede always did, decision 4) or to carry them over, each weighed
// again under the new terms.
//
// The carry is worked out the same way at the ask and the confirm
// (`carryPlan`), so the admin sees, before signing in again, which requests
// will carry and which will be cancelled and why (17.4, the partner's catch),
// and the plan is bound into the step-up: anything changed between (a request
// decided, approved or ended, a limit moved) makes the confirm's plan
// another, and the step-up refuses it. Oldest decision first, each weighed by
// the engine under the draft and today's policies, in the month its capacity
// is held in, against what holds capacity outside the plan and the older
// requests carried before it (its own, the younger ones and those cancelled
// left out): when the new monthly limit can't hold them all, the oldest
// stand. The split total still counts them all, so it errs to asking an
// approval. What each outcome means is `carries` (decision 17). Past 20
// pending, refused: choose cancel, or act on some first (17.3).
//
// Reads (partner, S116: no row-by-row reads): what all the requests share is
// read once, each set in one statement where it can be: the draft and the
// policies; the sources and suppliers, one read each; the months' totals in
// one statement, the split totals one per supplier, the order claims in one.
// Each request is then weighed in memory by the engine, through the same
// input a decision builds (inputOf). Only its own signed state is read alone:
// at the confirm it is locked for the change it is about to make, as a
// brake's cascade reads its requests (FOR SHARE, the ask reads them in one).
//
// Lock order (ADR-006 §6), after the acceptance's own (the mandate and the
// draft's source held): the requests' IDs and facts by their rows, unlocked;
// the policies (4); their sources (5) and suppliers (6), each set in order of
// ID; the months their capacity is held in (7); the requests (8), in one
// statement; then the totals, read and locking nothing. Carrying them out
// takes the head (12): their holdings change only under their requests'
// locks, held here (as an approval's), and a cancel locks its own as a
// brake's void does. The ask reads it all FOR SHARE and locks no month.
import { type AuditActor, type AuditDetails, type SignedStates, type VerifiedState } from '@agentx/core/modules/audit';
import { type SourceCheck, sourceOf } from '@agentx/core/modules/funding-sources';
import { changeHashOf } from '@agentx/core/modules/identity';
import { lockAgentPeriod, monthsSpent, splitHeld } from '@agentx/core/modules/limit-reservations';
import { type Decision, decide, type DecisionMade } from '@agentx/core/modules/policies';
import {
  claimsOnEach,
  decisionsOf,
  type HeldSealed,
  isPending,
  type OrderClaimsSeen,
  PENDING_STATUSES,
  requestOf,
  requestsOf,
  settleCarried,
  SPEND_REQUESTS,
  type SpendRequestRecord,
  type SpendRequestStatus,
} from '@agentx/core/modules/spend-requests';
import { type SupplierRecord, supplierOf } from '@agentx/core/modules/suppliers';
import { money, type ReasonCode, windowStart } from '@agentx/core/shared-kernel';
import type { DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { z } from 'zod';

import { MandateRefused } from './mandate-reads.ts';
import {
  authorityIn,
  type DecisionTables,
  inputOf,
  type MandateWeighed,
  type PoliciesWeighed,
} from './spend-request-decisions.ts';

type CarryTx = DatabaseTransaction<DecisionTables>;

/** What the accepting admin chooses for the pending requests of the version in force (decision 15). */
const SUPERSEDE_CHOICES = ['cancel', 'carry'] as const;
export type SupersedeChoice = (typeof SUPERSEDE_CHOICES)[number];

/** The words each choice is confirmed with, by version: the console's confirm shows them, the event keeps the version. */
const SUPERSEDE_STATEMENTS = {
  cancel:
    'Once you accept the new version, every request under the version in force that is waiting for approval, ' +
    'approved or ready is cancelled and the money held for it freed. This can’t be undone: the agent asks again ' +
    'under the new terms.',
  carry:
    'Once you accept the new version, each request under the version in force that is waiting for approval, ' +
    'approved or ready is checked again under the new terms, oldest first. Those the new terms allow carry over as ' +
    'they are: one waiting still waits for its approver, and one a person approved stays approved even where the ' +
    'new terms would ask for approval. The others are cancelled and the money held for them freed: one the new ' +
    'terms refuse, one over the new limits once the older ones are counted, and one approved without a person that ' +
    'the new terms would send for approval. You see which before you confirm. At most 20 can be carried at once.',
} as const satisfies Record<SupersedeChoice, string>;

/** The version of SUPERSEDE_STATEMENTS each acceptance names: raised with any change to their words. */
const SUPERSEDE_STATEMENT_VERSION = 1;

/** The choice as an acceptance's event keeps it, with its words' version (none for a first version). */
export const supersedeChoiceDetails = (choice: SupersedeChoice | null) =>
  choice === null ? {} : { pendingRequests: choice, pendingStatementVersion: SUPERSEDE_STATEMENT_VERSION };

/** The choice as the acceptance's step-up binds it, with its words' version. */
export const supersedeHashParts = (choice: SupersedeChoice | null): readonly string[] => [
  choice ?? 'none',
  String(SUPERSEDE_STATEMENT_VERSION),
];

/** An acceptance's choice, as its bodies name it (decision 15): only when a version is in force. */
export const SUPERSEDE_PENDING_REQUESTS = z
  .enum(SUPERSEDE_CHOICES)
  .describe(
    'What happens to the pending spend requests of the version in force, chosen by the admin accepting a new ' +
      'version; there is no default, and a first version, with none, takes none. ' +
      `\`cancel\`: ${SUPERSEDE_STATEMENTS.cancel} \`carry\`: ${SUPERSEDE_STATEMENTS.carry}`,
  );

/** The most pending requests a carry weighs again in the acceptance's own transaction (17.3: as one brake voids). */
export const MOST_CARRIED = 20;

/** One pending request as the carry settles it: carried to the draft, or cancelled with the new terms' reasons. */
export interface CarryPlanned {
  readonly id: string;
  readonly outcome: 'carry' | 'cancel';
  /** The engine's reasons under the new terms: why it is cancelled, or why a carried one would need approval. */
  readonly reasons: readonly ReasonCode[];
}

/**
 * Decision 17, what the new terms do to one request:
 *
 * - Denied under them (DENY or REQUIRE_NEW_MANDATE): cancelled.
 * - Allowed: carried. One waiting still waits for its approver (17.2): nothing
 *   is approved without a person.
 * - Sent for approval: one waiting carried, still waiting; one approved or
 *   ready stays approved if a person approved it (its decision was
 *   REQUIRE_APPROVAL), and is cancelled if no person ever did (its decision
 *   ALLOW): it would need an approval it never had (17.1).
 */
export function carries(status: SpendRequestStatus, decidedAs: Decision, now: Decision): boolean {
  if (now === 'ALLOW') return true;
  if (now !== 'REQUIRE_APPROVAL') return false;
  return status === 'APPROVAL_REQUIRED' || decidedAs === 'REQUIRE_APPROVAL';
}

/** The plan as the step-up binds it: every request with its outcome and reasons, in order. */
export const planHashOf = (plan: readonly CarryPlanned[]): string =>
  changeHashOf(plan.map(({ id, outcome, reasons }) => `${id}:${outcome}:${reasons.join(',')}`)).toString('hex');

/** Whose pending requests are weighed, and how: a confirm's locks (`decides`), or an ask's reads. */
export interface WeighScope {
  readonly orgId: string;
  readonly agentId: string;
  readonly now: Date;
  readonly decides: boolean;
}

/** A carry's: the mandate whose pending requests it weighs. */
interface CarryScope extends WeighScope {
  readonly mandateId: string;
}

/**
 * The mandate's pending requests weighed again under its draft waiting, in
 * the lock order above. More than MOST_CARRIED pending:
 * PENDING_REQUESTS_TOO_MANY_TO_CARRY. One whose signed state, history or
 * holdings can't be believed, or whose row names other facts than its signed
 * state: INTEGRITY_FAILED.
 */
export async function carryPlan(
  tx: CarryTx,
  states: SignedStates,
  scope: CarryScope,
): Promise<readonly CarryPlanned[]> {
  const rows = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs and facts alone, each held to its signed state below
    .selectFrom(SPEND_REQUESTS.table)
    .select(['id', 'supplier_id', 'funding_source_id'])
    .where('org_id', '=', scope.orgId)
    .where('mandate_id', '=', scope.mandateId)
    .where('status', 'in', PENDING_STATUSES)
    .orderBy('created_at')
    .orderBy('id')
    .limit(MOST_CARRIED + 1)
    .execute();
  if (rows.length > MOST_CARRIED) throw new MandateRefused(409, 'PENDING_REQUESTS_TOO_MANY_TO_CARRY');
  if (rows.length === 0) return [];
  // 4: the draft, the mandate's policy and the organisation's, once.
  const { mandate, ...policies } = await authorityIn(tx, states, scope.orgId, scope.agentId, 'draft');
  const authority = await heldAuthority(tx, states, scope, rows, known(mandate));
  const requests = (await requestsHeld(tx, states, scope, rows)).map(({ request }) => request);
  const outside = await outsideOf(tx, scope, authority, requests);
  const agent = { id: scope.agentId, status: 'ACTIVE' };
  return weighedInOrder({ now: scope.now, agent }, authority, policies, outside, requests, (request, made) =>
    carries(request.status, request.decision, made.decision),
  ).map(({ request, made, stays }) => ({ id: request.id, outcome: stays ? 'carry' : 'cancel', reasons: made.reasons }));
}

/** A pending request as its row names it: what the authority is read by, before its signed state is. */
export interface PendingRow {
  readonly id: string;
  readonly supplier_id: string;
  readonly funding_source_id: string;
}

/** What every request is weighed under but its policies, read once: the mandate, sources, suppliers, months. */
export interface HeldAuthority {
  readonly mandate: MandateWeighed;
  readonly sources: ReadonlyMap<string, SourceCheck>;
  readonly suppliers: ReadonlyMap<string, SupplierRecord>;
  /** Each request's capacity as its decision sealed it: its month, and when it was reserved. */
  readonly held: ReadonlyMap<string, HeldSealed>;
  /** When each request's decision was sealed: a waiting one's 72 hours run from it (E4b). */
  readonly decidedAt: ReadonlyMap<string, Date>;
}

/** Levels 5–7 under the mandate read at 4, each read once for every request. */
export async function heldAuthority(
  tx: CarryTx,
  states: SignedStates,
  { orgId, agentId, decides }: WeighScope,
  rows: readonly PendingRow[],
  mandate: MandateWeighed,
): Promise<HeldAuthority> {
  const ids = rows.map(({ id }) => id);
  // 5 and 6: each set in order of ID, so no two carries lock them crosswise. A request's own exist (0039's keys).
  const sources = new Map<string, SourceCheck>();
  for (const id of distinct(rows.map((row) => row.funding_source_id))) {
    const source = await sourceOf(tx, states, { orgId, id }, 'share');
    if (source.outcome !== 'found') integrityFailed();
    sources.set(id, source);
  }
  const suppliers = new Map<string, SupplierRecord>();
  for (const id of distinct(rows.map((row) => row.supplier_id))) {
    const supplier = await supplierOf(tx, states, { orgId, id }, decides ? 'change' : 'share');
    if (supplier.outcome !== 'found') integrityFailed();
    suppliers.set(id, supplier.supplier);
  }
  // 7: the months their capacity is held in, and when, as their decisions sealed them, in one read.
  const decisions = await decisionsOf(tx, states, orgId, ids);
  const held = new Map(ids.map((id) => [id, known(decisions.get(id.toLowerCase())?.held)]));
  const decidedAt = new Map(ids.map((id) => [id, known(decisions.get(id.toLowerCase())).decidedAt]));
  if (decides) for (const month of monthsOf(held)) await lockAgentPeriod(tx, { agentId, month });
  return { mandate, sources, suppliers, held, decidedAt };
}

/**
 * The requests' signed states, in the rows' order, each held to its row: at
 * the confirm locked for the change it is about to make (8), first all in one
 * statement in order of ID, then each read for change; at the ask all in one
 * read, FOR SHARE. One not found pending, or naming other facts than its row
 * (changed past the app, its alarm raised): INTEGRITY_FAILED. Each with its
 * verified state, which names the versions it was decided against.
 */
export async function requestsHeld(
  tx: CarryTx,
  states: SignedStates,
  { orgId, agentId, decides }: WeighScope,
  rows: readonly PendingRow[],
): Promise<readonly { readonly request: SpendRequestRecord; readonly state: VerifiedState }[]> {
  const ids = rows.map(({ id }) => id);
  const read = new Map<string, { readonly request: SpendRequestRecord; readonly state: VerifiedState }>();
  if (decides) {
    await tx
      // eslint-disable-next-line agentx/authority-tables-through-signed-state -- the lock alone; each is verified below
      .selectFrom(SPEND_REQUESTS.table)
      .select('id')
      .where('org_id', '=', orgId)
      .where('id', 'in', ids)
      .orderBy('id')
      .forNoKeyUpdate()
      .execute();
    for (const id of ids) {
      const found = await requestOf(tx, states, { orgId, id }, 'change');
      if (found.outcome === 'found') read.set(id, found);
    }
  } else {
    for (const [id, found] of await requestsOf(tx, states, orgId, ids)) {
      if (found.outcome === 'found') read.set(id, found);
    }
  }
  return rows.map((row) => {
    const found = read.get(row.id);
    const asItsRow =
      found !== undefined &&
      isPending(found.request.status) &&
      found.request.agentId === agentId &&
      found.request.supplierId === row.supplier_id &&
      found.request.fundingSourceId === row.funding_source_id;
    return asItsRow ? found : integrityFailed();
  });
}

/** What holds capacity or claims an order outside the requests weighed, read once: the weighing's only reads. */
export interface HeldOutside {
  readonly spent: ReadonlyMap<string, bigint>;
  readonly split: ReadonlyMap<string, bigint>;
  readonly since: Date;
  readonly orders: readonly OrderClaimsSeen[];
}

/**
 * Outside the requests weighed: each month's total, each payee's split total
 * since the window opened (none with the split check off: the engine weighs
 * no split then), and each request's order claims, in the requests' order.
 */
export async function outsideOf(
  tx: CarryTx,
  { agentId, now }: Pick<WeighScope, 'agentId' | 'now'>,
  { mandate, suppliers, held }: HeldAuthority,
  requests: readonly SpendRequestRecord[],
): Promise<HeldOutside> {
  const currency = mandate.perOrderLimit.currency;
  const inPlan = requests.map(({ id }) => id);
  const spent = await monthsSpent(tx, { agentId, months: monthsOf(held), currency, except: inPlan });
  const since = windowStart(now, mandate.splitWindowHours);
  const split = mandate.splitCheck
    ? await splitTotalsOutside(tx, suppliers, { since, currency, except: inPlan })
    : new Map<string, bigint>();
  const orders = await claimsOnEach(
    tx,
    requests.map((request) => ({
      supplierId: request.supplierId,
      payeeKey: known(suppliers.get(request.supplierId)).payeeKey,
      reference: request.orderReference,
      except: request.id,
    })),
    inPlan,
  );
  return { spent, split, since, orders };
}

/** One request as weighed in order: the engine's answer, and whether it stays, counted against the younger ones. */
export interface WeighedInOrder {
  readonly request: SpendRequestRecord;
  readonly made: DecisionMade;
  readonly stays: boolean;
}

/**
 * Each request weighed in memory, oldest first, by the engine through the
 * input a decision builds (inputOf), against what holds capacity or claims
 * an order outside them (`outside`) and the older ones that stay (`stays`):
 * in its month (the monthly limits), to its payee in the split window (the
 * split check), and to its payee as a lookalike order (a possible
 * duplicate). The younger ones, and those that go, aren't counted, so the
 * oldest stand when the rules can't hold them all; and its own amount is the
 * engine's to add, once.
 */
export function weighedInOrder(
  { now, agent }: { readonly now: Date; readonly agent: { readonly id: string; readonly status: string } },
  { mandate, sources, suppliers, held }: HeldAuthority,
  policies: PoliciesWeighed,
  outside: HeldOutside,
  requests: readonly SpendRequestRecord[],
  stays: (request: SpendRequestRecord, made: DecisionMade) => boolean,
): readonly WeighedInOrder[] {
  const currency = mandate.perOrderLimit.currency;
  const { since } = outside;
  const carried: { readonly request: SpendRequestRecord; readonly order: OrderClaimsSeen }[] = [];
  return requests.map((request, at) => {
    const { month } = known(held.get(request.id));
    const supplier = known(suppliers.get(request.supplierId));
    const order = known(outside.orders[at]);
    const toItsPayee = carried.filter((other) => samePayee(supplier, known(suppliers.get(other.request.supplierId))));
    const made = decide(
      inputOf({
        asked: request,
        now,
        agent,
        mandate,
        policies,
        supplier,
        source: known(sources.get(request.fundingSourceId)),
        spent: money(
          known(outside.spent.get(month)) +
            sumOf(carried.filter((other) => known(held.get(other.request.id)).month === month)),
          currency,
        ),
        split: money(
          (outside.split.get(supplier.id) ?? 0n) +
            sumOf(toItsPayee.filter((other) => known(held.get(other.request.id)).reservedAt >= since)),
          currency,
        ),
        claims: {
          duplicate: order.duplicate || toItsPayee.some((other) => other.order.key === order.key),
          possible:
            order.possible ||
            toItsPayee.some(
              (other) =>
                order.bankKey !== null && other.order.bankKey === order.bankKey && other.order.key !== order.key,
            ),
        },
      }),
    );
    const staying = stays(request, made);
    if (staying) carried.push({ request, order });
    return { request, made, stays: staying };
  });
}

/** The split total of each supplier's payee outside the plan, one statement a supplier. */
async function splitTotalsOutside(
  tx: CarryTx,
  suppliers: ReadonlyMap<string, SupplierRecord>,
  { since, currency, except }: { since: Date; currency: string; except: readonly string[] },
): Promise<ReadonlyMap<string, bigint>> {
  const totals = new Map<string, bigint>();
  for (const [id, { payeeKey }] of suppliers) {
    totals.set(id, await splitHeld(tx, { supplierId: id, payeeKey, since, currency, except }));
  }
  return totals;
}

/** The same payee: the same supplier, or the same payee key where it has one (as order-claims' onTheOrdersPayee). */
export const samePayee = (supplier: SupplierRecord, other: SupplierRecord): boolean =>
  other.id === supplier.id || (supplier.payeeKey !== null && other.payeeKey === supplier.payeeKey);

/**
 * Their amounts' total, in minor units. A carried request is in the mandate's
 * currency: in another, the engine denies it (CURRENCY_NOT_ALLOWED), so it
 * never carries.
 */
const sumOf = (carried: readonly { readonly request: SpendRequestRecord }[]): bigint =>
  carried.reduce((total, { request }) => total + request.amount.minor, 0n);

/** The months their capacity is held in, each once, in order. */
const monthsOf = (held: ReadonlyMap<string, { readonly month: string }>): string[] =>
  distinct([...held.values()].map(({ month }) => month));

/**
 * A value every read above answers for what it was asked (each request's
 * decision, supplier and source, each month's total, each order's claims):
 * one missing is a history or a row changed past the app, so the carry is
 * refused.
 */
export const known = <Value>(value: Value | null | undefined): Value => value ?? integrityFailed();

/** The IDs or months, each once, in order. */
export const distinct = (values: readonly string[]): string[] => [...new Set(values)].sort();

/**
 * The plan carried out, in the confirm's transaction after its step-up is
 * consumed and before the draft is accepted: each request carried to the
 * draft (the admin's, with the acceptance's evidence) or cancelled. Holdings
 * of a carried one that don't match its decision refuse it all
 * (INTEGRITY_FAILED), nothing moved.
 */
export async function carryOut(
  tx: CarryTx,
  states: SignedStates,
  keys: KeyProvider,
  orgId: string,
  plan: readonly CarryPlanned[],
  { draftId, actor, details, now }: { draftId: string; actor: AuditActor; details: AuditDetails; now: Date },
): Promise<void> {
  for (const { id, outcome, reasons } of plan) {
    const settled = await settleCarried(
      tx,
      states,
      keys,
      { orgId, id },
      outcome === 'carry'
        ? { outcome, draftId, change: { actor, action: 'spend_request.carried', details } }
        : { outcome, causes: reasons },
      now,
    );
    if (settled === 'mismatch') integrityFailed();
  }
}

function integrityFailed(): never {
  throw new MandateRefused(503, 'INTEGRITY_FAILED');
}
