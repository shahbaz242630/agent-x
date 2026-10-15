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
import { type AuditActor, type AuditDetails, type SignedStates } from '@agentx/core/modules/audit';
import { sourceOf } from '@agentx/core/modules/funding-sources';
import { changeHashOf } from '@agentx/core/modules/identity';
import { lockAgentPeriod, monthsSpent, splitHeld } from '@agentx/core/modules/limit-reservations';
import { type Decision, decide } from '@agentx/core/modules/policies';
import {
  claimsOnEach,
  decisionsOf,
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
import { authorityIn, type DecisionTables, inputOf } from './spend-request-decisions.ts';

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
export const SUPERSEDE_STATEMENT_VERSION = 1;

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
  readonly carried: boolean;
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
  changeHashOf(
    plan.map(({ id, carried, reasons }) => `${id}:${carried ? 'carry' : 'cancel'}:${reasons.join(',')}`),
  ).toString('hex');

/**
 * The mandate's pending requests weighed again under its draft waiting, in
 * the lock order above: `decides` for the confirm's locks, or the ask's
 * reads. More than MOST_CARRIED pending: PENDING_REQUESTS_TOO_MANY_TO_CARRY.
 * One whose signed state, history or holdings can't be believed, or whose row
 * names other facts than its signed state: INTEGRITY_FAILED.
 */
export async function carryPlan(
  tx: CarryTx,
  states: SignedStates,
  carry: {
    readonly orgId: string;
    readonly agentId: string;
    readonly mandateId: string;
    readonly now: Date;
    readonly decides: boolean;
  },
): Promise<readonly CarryPlanned[]> {
  const { orgId, mandateId } = carry;
  const rows = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs and facts alone, each held to its signed state below
    .selectFrom(SPEND_REQUESTS.table)
    .select(['id', 'supplier_id', 'funding_source_id'])
    .where('org_id', '=', orgId)
    .where('mandate_id', '=', mandateId)
    .where('status', 'in', PENDING_STATUSES)
    .orderBy('created_at')
    .orderBy('id')
    .limit(MOST_CARRIED + 1)
    .execute();
  if (rows.length > MOST_CARRIED) throw new MandateRefused(409, 'PENDING_REQUESTS_TOO_MANY_TO_CARRY');
  if (rows.length === 0) return [];
  const authority = await authorityOfCarry(tx, states, carry, rows);
  const requests = await requestsHeld(tx, states, carry, rows);
  return weighedInOrder(tx, carry, authority, requests);
}

/** A pending request as its row names it: what the authority is read by, before its signed state is. */
interface CarryRow {
  readonly id: string;
  readonly supplier_id: string;
  readonly funding_source_id: string;
}

/** Levels 4–7, each read once for every request: the draft, its policies, the sources, suppliers and months. */
async function authorityOfCarry(
  tx: CarryTx,
  states: SignedStates,
  { orgId, agentId, decides }: { readonly orgId: string; readonly agentId: string; readonly decides: boolean },
  rows: readonly CarryRow[],
) {
  const ids = rows.map(({ id }) => id);
  // 4: the draft, the mandate's policy and the organisation's, once. The acceptance read the draft waiting.
  const { mandate, ...policies } = await authorityIn(tx, states, orgId, agentId, true);
  // 5 and 6: each set in order of ID, so no two carries lock them crosswise. A request's own exist (0039's keys).
  const sources = new Map<string, Awaited<ReturnType<typeof sourceOf>>>();
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
  if (decides) for (const month of monthsOf(held)) await lockAgentPeriod(tx, { agentId, month });
  return { mandate: known(mandate), policies, sources, suppliers, held };
}

/**
 * The requests' signed states, in the rows' order, each held to its row: at
 * the confirm locked for the change it is about to make (8), first all in one
 * statement in order of ID, then each read for change; at the ask all in one
 * read, FOR SHARE. One not found pending, or naming other facts than its row
 * (changed past the app, its alarm raised): INTEGRITY_FAILED.
 */
async function requestsHeld(
  tx: CarryTx,
  states: SignedStates,
  { orgId, agentId, decides }: { readonly orgId: string; readonly agentId: string; readonly decides: boolean },
  rows: readonly CarryRow[],
): Promise<readonly SpendRequestRecord[]> {
  const ids = rows.map(({ id }) => id);
  const read = new Map<string, SpendRequestRecord>();
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
      if (found.outcome === 'found') read.set(id, found.request);
    }
  } else {
    for (const [id, found] of await requestsOf(tx, states, orgId, ids)) {
      if (found.outcome === 'found') read.set(id, found.request);
    }
  }
  return rows.map((row) => {
    const request = read.get(row.id);
    const asItsRow =
      request !== undefined &&
      (PENDING_STATUSES as readonly string[]).includes(request.status) &&
      request.agentId === agentId &&
      request.supplierId === row.supplier_id &&
      request.fundingSourceId === row.funding_source_id;
    return asItsRow ? request : integrityFailed();
  });
}

/**
 * Each request weighed in memory, oldest first, by the engine through the
 * input a decision builds (inputOf), against the totals read once of what
 * holds capacity outside the plan, and the older requests carried before it:
 * in its month (the monthly limits), and to its payee in the split window
 * (the split check). The younger ones, and those cancelled, aren't counted,
 * so the oldest stand when the new limits can't hold them all; and its own
 * amount is the engine's to add, once.
 */
async function weighedInOrder(
  tx: CarryTx,
  { agentId, now }: { readonly agentId: string; readonly now: Date },
  { mandate, policies, sources, suppliers, held }: Awaited<ReturnType<typeof authorityOfCarry>>,
  requests: readonly SpendRequestRecord[],
): Promise<readonly CarryPlanned[]> {
  const currency = mandate.perOrderLimit.currency;
  const inPlan = requests.map(({ id }) => id);
  const spentOutside = await monthsSpent(tx, { agentId, months: monthsOf(held), currency, except: inPlan });
  const since = windowStart(now, mandate.splitWindowHours);
  const splitOutside = new Map<string, bigint>();
  if (mandate.splitCheck) {
    for (const [id, supplier] of suppliers) {
      const split = await splitHeld(tx, {
        supplierId: id,
        payeeKey: supplier.payeeKey,
        since,
        currency,
        except: inPlan,
      });
      splitOutside.set(id, split);
    }
  }
  const claims = await claimsOnEach(
    tx,
    requests.map((request) => ({
      supplierId: request.supplierId,
      payeeKey: known(suppliers.get(request.supplierId)).payeeKey,
      reference: request.orderReference,
      except: request.id,
    })),
  );
  const carried: SpendRequestRecord[] = [];
  return requests.map((request, at) => {
    const { month } = known(held.get(request.id));
    const supplier = known(suppliers.get(request.supplierId));
    const samePayee = (other: SpendRequestRecord) => {
      const theirs = known(suppliers.get(other.supplierId));
      return other.supplierId === supplier.id || (supplier.payeeKey !== null && theirs.payeeKey === supplier.payeeKey);
    };
    const inMonth = carried.filter((other) => known(held.get(other.id)).month === month);
    const inWindow = carried.filter((other) => samePayee(other) && known(held.get(other.id)).reservedAt >= since);
    const made = decide(
      inputOf({
        asked: request,
        now,
        agent: { id: agentId, status: 'ACTIVE' },
        mandate,
        policies,
        supplier,
        source: known(sources.get(request.fundingSourceId)),
        spent: money(known(spentOutside.get(month)) + sumOf(inMonth), currency),
        split: money((splitOutside.get(supplier.id) ?? 0n) + sumOf(inWindow), currency),
        claims: known(claims[at]),
      }),
    );
    const stands = carries(request.status, request.decision, made.decision);
    if (stands) carried.push(request);
    return { id: request.id, carried: stands, reasons: made.reasons };
  });
}

/**
 * Their amounts' total, in minor units. A carried request is in the mandate's
 * currency: in another, the engine denies it (MANDATE_CURRENCY), so it never
 * carries.
 */
const sumOf = (requests: readonly SpendRequestRecord[]): bigint =>
  requests.reduce((total, { amount }) => total + amount.minor, 0n);

/** The months their capacity is held in, each once, in order. */
const monthsOf = (held: ReadonlyMap<string, { readonly month: string }>): string[] =>
  distinct([...held.values()].map(({ month }) => month));

/**
 * A value every read above answers for what it was asked (each request's
 * decision, supplier and source, each month's total): one missing is a
 * history or a row changed past the app, so the carry is refused.
 */
const known = <Value>(value: Value | null | undefined): Value => value ?? integrityFailed();

/** The IDs or months, each once, in order. */
const distinct = (values: readonly string[]): string[] => [...new Set(values)].sort();

/**
 * The plan carried out, in the confirm's transaction after its step-up is
 * consumed and before the draft is accepted: each request carried to the
 * draft (the admin's, with the acceptance's evidence) or cancelled. Holdings that don't match a decision
 * refuse it all (INTEGRITY_FAILED), nothing moved.
 */
export async function carryOut(
  tx: CarryTx,
  states: SignedStates,
  keys: KeyProvider,
  orgId: string,
  plan: readonly CarryPlanned[],
  { draftId, actor, details, now }: { draftId: string; actor: AuditActor; details: AuditDetails; now: Date },
): Promise<void> {
  for (const { id, carried, reasons } of plan) {
    const settled = await settleCarried(
      tx,
      states,
      keys,
      { orgId, id },
      carried
        ? { outcome: 'carry', draftId, change: { actor, action: 'spend_request.carried', details } }
        : { outcome: 'cancel', causes: reasons },
      now,
    );
    if (settled === 'mismatch') integrityFailed();
  }
}

function integrityFailed(): never {
  throw new MandateRefused(503, 'INTEGRITY_FAILED');
}
