// An agent's monthly total as a signed running total (0109; GM-1a, R-15;
// ADR-006 §8; ADR-012 §2): what its month's reservations hold, one row an agent,
// month and currency, read and changed through its signed state in the same
// transactions that reserve and release, so the database's owner can't give
// capacity back by deleting or zeroing reservations. On the product's
// authority-table list (packages/core/src/authority-tables.ts), at level 11a:
// after a request (8) and its reservation (11), before the audit head (12). A
// decision locks it with its month (7) on the same trip, ahead of its own
// request and reservation, which are new rows no one else can be holding.
//
// A row's ID is named by its organisation, agent, month and currency
// (`monthTotalId`), so one deleted reads as deleted (its signed events are
// still in the log), never as a month with nothing held. A month with no row
// and nothing signed holds nothing, once the organisation is counted this way
// (`monthTotalsCutOver`): born so (its `organization.created` says so), or cut
// over by the API's job, which opens every month then held from the signed
// spend requests in the same transaction as its cutover event. Before that,
// every check of a month is refused (busy), never read from the reservations.
import type { GatheredRow, SentTogether, SignedStateTable } from '@agentx/platform/db';
import { sql, type Transaction } from 'kysely';

import type {
  AuditTables,
  ChangeToSend,
  SignedChange,
  SignedStates,
  StateCheck,
  TamperSign,
  VerifiedState,
} from '../../audit/index.ts';
import { namedId } from '../../../shared-kernel/index.ts';
import type { LimitReservationsTables } from './tables.ts';

type TotalsTransaction = Transaction<LimitReservationsTables & AuditTables>;

/** A month's total row, as the signed state reads, records and checks it. */
export const MONTH_TOTALS = {
  table: 'limit_reservations.month_totals',
  subject: 'month_total',
  fields: [
    { column: 'agent_id', type: 'uuid' },
    { column: 'month', type: 'text' },
    { column: 'currency', type: 'text' },
    { column: 'held_minor', type: 'integer' },
    { column: 'created_at', type: 'timestamptz' },
  ],
  // Fixed when the total is made: 0109's `fixed_at_creation` refuses any change after.
  fixedAtCreation: ['agent_id', 'month', 'currency', 'created_at'],
} as const satisfies SignedStateTable & { readonly fixedAtCreation: readonly string[] };

/** Whose month, which month, in which currency: a cap is in one currency (G4), so each has its own total. */
export interface MonthTotalKey {
  readonly agentId: string;
  readonly month: string;
  readonly currency: string;
}

/** The total's ID: named by what it totals, the same every time. */
export const monthTotalId = (orgId: string, { agentId, month, currency }: MonthTotalKey): string =>
  namedId(['month_total', orgId, agentId, month, currency]);

/**
 * A month's total, verified: what it holds, with the state to change it from;
 * none (no row, nothing signed); or tampered with (the alarm raised).
 */
export type MonthTotalCheck =
  | { readonly outcome: 'held'; readonly held: bigint; readonly state: VerifiedState }
  | { readonly outcome: 'none' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

const NONE = Object.freeze({ outcome: 'none' as const });
/** Minor units from 0, as 0109's check holds them, in canonical text. */
const HELD = /^(0|[1-9][0-9]{0,18})$/;

/** The total a signed read of its row holds. */
export function monthTotalFrom(check: StateCheck): MonthTotalCheck {
  if (check.outcome === 'tampered') return check;
  if (check.outcome === 'missing') return NONE;
  const held = check.fields.get('held_minor');
  // 0109's check holds it to a whole number from 0, and the seal to what was written.
  if (typeof held !== 'string' || !HELD.test(held)) throw new Error('A verified month total holds no amount');
  return Object.freeze({ outcome: 'held', held: BigInt(held), state: check });
}

/** The month's total, read through its signed state, locked as asked, in withSignedStates' transaction. */
export async function monthTotalOf(
  tx: TotalsTransaction,
  states: SignedStates,
  orgId: string,
  key: MonthTotalKey,
  lock: 'share' | 'change',
): Promise<MonthTotalCheck> {
  return monthTotalFrom(await states.verifiedState(tx, MONTH_TOTALS, { orgId, id: monthTotalId(orgId, key) }, lock));
}

/** The month's total as a row to gather, so its read rides a trip made anyway (a decision's month lock). */
export const monthTotalGathered = (orgId: string, key: MonthTotalKey, lock: 'share' | 'change'): GatheredRow => ({
  table: MONTH_TOTALS,
  id: { id: monthTotalId(orgId, key) },
  lock,
});

/** The cutover's event: about the organisation, by its ID, under a subject of its own (no row is it). */
export const CUTOVER_SUBJECT = 'month_totals';
export const CUTOVER_ACTION = 'month_totals.cutover';
/**
 * What an organisation's `organization.created` says when it is born counted this way: the organisations module's
 * own detail, which it may not import from here (ADR-004), so written there alike.
 */
const BORN_SIGNED = 'signed';

/** Whether the organisation's months are counted in signed totals: since its birth or its cutover; not yet; or its log can't be believed. */
export type CutOver = 'cut_over' | 'not_yet' | 'tampered';

/**
 * Whether the organisation is counted in signed month totals, from its own
 * log, each event believed only whole: its newest of `organization.created`
 * and the cutover's. Asked only where a month's total is missing, so a
 * decision on a month that has one makes no trip for it.
 */
export async function monthTotalsCutOver(tx: TotalsTransaction, states: SignedStates, orgId: string): Promise<CutOver> {
  const read = await states.historyOf(tx, orgId, {
    subjectTypes: ['organization', CUTOVER_SUBJECT],
    subjectId: orgId,
    actions: ['organization.created', CUTOVER_ACTION],
    limit: 1,
    newest: true,
  });
  if (read.outcome === 'tampered') return 'tampered';
  const [newest] = read.events;
  if (newest === undefined) return 'not_yet';
  return newest.event.action === CUTOVER_ACTION || newest.event.details.monthTotals === BORN_SIGNED
    ? 'cut_over'
    : 'not_yet';
}

/** The fields of a new total, as it is added and sealed. */
const newFields = (key: MonthTotalKey, held: bigint, at: Date) => ({
  agent_id: key.agentId,
  month: key.month,
  currency: key.currency,
  held_minor: held,
  created_at: at,
});

/** A new total's insert, not run: its period exists (the decision's lock target, or the job's). */
const totalInsert = (tx: TotalsTransaction, orgId: string, key: MonthTotalKey, held: bigint, at: Date) =>
  tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by the record of its first state in the same transaction
    .insertInto(MONTH_TOTALS.table)
    .values({ org_id: orgId, id: monthTotalId(orgId, key), ...newFields(key, held, at) });

/**
 * A decision's write to its month's total, on the trip that holds its
 * reservation (no trip of its own): `held`, from the total read for change
 * with its month, or a new row for a month with none (its insert first). The
 * signed state's recordNewAndMove records it with the request's events
 * (`alongside`).
 */
export function monthTotalToSend(
  tx: TotalsTransaction,
  states: SignedStates,
  orgId: string,
  key: MonthTotalKey,
  total: Exclude<MonthTotalCheck, { readonly outcome: 'tampered' }>,
  held: bigint,
  at: Date,
): { readonly statements: readonly SentTogether[]; readonly sent: ChangeToSend } {
  const id = monthTotalId(orgId, key);
  if (total.outcome === 'held') {
    const sent = states.changeToSend(tx, MONTH_TOTALS, { orgId, id }, total.state, { held_minor: held });
    return { statements: [sent.statement], sent };
  }
  const sent = states.changeToSend(tx, MONTH_TOTALS, { orgId, id }, 'new', newFields(key, held, at));
  return { statements: [totalInsert(tx, orgId, key, held, at), sent.statement], sent };
}

/** A total's new amount recorded on its own (an ending's, a payment's, the cutover's), from its read for change or new. */
export async function recordMonthTotal(
  tx: TotalsTransaction,
  states: SignedStates,
  orgId: string,
  key: MonthTotalKey,
  total: Exclude<MonthTotalCheck, { readonly outcome: 'tampered' }>,
  held: bigint,
  { at, change }: { readonly at: Date; readonly change: SignedChange },
): Promise<void> {
  const id = monthTotalId(orgId, key);
  if (total.outcome === 'held') {
    await states.record(tx, MONTH_TOTALS, { orgId, id }, total.state, { held_minor: held }, change);
    return;
  }
  await totalInsert(tx, orgId, key, held, at).execute();
  await states.record(tx, MONTH_TOTALS, { orgId, id }, 'new', newFields(key, held, at), change);
}

/**
 * `amount` given back to a month's total read for change in this transaction
 * (an ending, a payment's verified failure), recorded with `change`. A total
 * tampered with is left (its alarm raised by its read): the request still
 * ends, as a brake must. One missing is nothing to give back before the
 * organisation's cutover, and after it a mismatch (`holding`): its request
 * held capacity there. One holding less than `amount` is a mismatch too, and
 * goes to nothing, never below (0109's check).
 */
export async function givenBack(
  tx: TotalsTransaction,
  states: SignedStates,
  orgId: string,
  held: { readonly key: MonthTotalKey; readonly total: MonthTotalCheck; readonly amount: bigint } | null | undefined,
  recorded: { readonly at: Date; readonly change: SignedChange },
): Promise<void> {
  // None: a request whose decision sealed no month (before E1), or one its caller found nothing for.
  if (held === null || held === undefined) return;
  const { key, total, amount } = held;
  if (total.outcome === 'tampered') return;
  const id = monthTotalId(orgId, key);
  if (total.outcome === 'none') {
    if ((await monthTotalsCutOver(tx, states, orgId)) !== 'not_yet')
      states.mismatch(MONTH_TOTALS.subject, { orgId, id });
    return;
  }
  if (total.held < amount) states.mismatch(MONTH_TOTALS.subject, { orgId, id });
  // The amount given back goes in its event, whatever the caller's details say.
  const { at, change } = recorded;
  await recordMonthTotal(tx, states, orgId, key, total, total.held < amount ? 0n : total.held - amount, {
    at,
    change: { ...change, details: { ...change.details, amountMinor: amount.toString() } },
  });
}

/** A key's text, as reservationsHeldIn answers by it: agent, month and currency. */
export const monthTotalKeyText = ({ agentId, month, currency }: MonthTotalKey): string =>
  `${agentId.toLowerCase()}|${month}|${currency}`;

/**
 * What the reservations hold in each month asked (every state but RELEASED,
 * 0040's rule), by monthTotalKeyText, in one statement; or, with none asked,
 * in every month of the organisation's they hold anything in. Unsealed: only
 * ever compared with the signed totals (the holdings check, the cutover),
 * never weighed.
 */
export async function reservationsHeldIn(
  tx: TotalsTransaction,
  keys: readonly MonthTotalKey[] | 'all',
): Promise<ReadonlyMap<string, bigint>> {
  if (keys !== 'all' && keys.length === 0) return new Map();
  const rows = await tx
    .selectFrom('limit_reservations.reservations')
    .select(['agent_id', 'month', 'currency', sql<string>`pg_catalog.sum(amount_minor)::text`.as('held')])
    .where('state', '<>', 'RELEASED')
    .where(
      keys === 'all'
        ? sql<boolean>`true`
        : sql<boolean>`(agent_id, month, currency) in (
            select * from rows from (pg_catalog.unnest(${keys.map((key) => key.agentId)}::uuid[]),
              pg_catalog.unnest(${keys.map((key) => key.month)}::text[]),
              pg_catalog.unnest(${keys.map((key) => key.currency)}::text[])))`,
    )
    .groupBy(['agent_id', 'month', 'currency'])
    .execute();
  return new Map(
    rows.map((row) => [
      monthTotalKeyText({ agentId: row.agent_id, month: row.month, currency: row.currency }),
      BigInt(row.held),
    ]),
  );
}

/** The most month totals one page of the holdings check reads: each a verified read, locked until its page ends. */
export const MOST_TOTALS_CHECKED_A_PAGE = 200;

/** A page of the organisation's month totals checked: totals compared, mismatched and tampered with, and where to go on. */
export interface TotalsChecked {
  readonly totals: number;
  readonly mismatched: number;
  readonly tampered: number;
  readonly next: string | null;
}

/**
 * One page of the organisation's month totals (GM-1a), each verified and
 * locked FOR SHARE, so every move of its reservations (all made under the
 * total's lock for change) waits for the page or comes before it, then held
 * to what its reservations hold, in one statement: a total and its
 * reservations apart is a mismatch (`holding`, alarmed). With the requests'
 * own check (each reservation held to its signed request), a total is so held
 * to the signed requests too. Listed from the rows and the log, so one
 * deleted is read as `deleted`, alarmed. In withSignedStates' transaction.
 */
export async function checkMonthTotals(
  tx: TotalsTransaction,
  states: SignedStates,
  orgId: string,
  { after, limit }: { readonly after: string | null; readonly limit: number },
): Promise<TotalsChecked> {
  if (!Number.isInteger(limit) || limit < 1 || limit > MOST_TOTALS_CHECKED_A_PAGE) {
    throw new RangeError(`A page is 1 to ${String(MOST_TOTALS_CHECKED_A_PAGE)} month totals`);
  }
  const { ids, next } = await states.objectIds(tx, orgId, MONTH_TOTALS, after, limit);
  const checks =
    ids.length === 0 ? new Map<string, StateCheck>() : await states.verifiedStates(tx, MONTH_TOTALS, orgId, ids);
  const verified: { readonly id: string; readonly key: MonthTotalKey; readonly held: bigint }[] = [];
  let tampered = 0;
  for (const [id, check] of checks) {
    const total = monthTotalFrom(check);
    if (total.outcome !== 'held') {
      // Listed by its row or its signed events, a total not found is one tampered with (its read raised the alarm).
      tampered += 1;
      continue;
    }
    const field = (column: string): string => String(total.state.fields.get(column));
    verified.push({
      id,
      key: { agentId: field('agent_id'), month: field('month'), currency: field('currency') },
      held: total.held,
    });
  }
  const reserved = await reservationsHeldIn(
    tx,
    verified.map(({ key }) => key),
  );
  let mismatched = 0;
  for (const { id, key, held } of verified) {
    if ((reserved.get(monthTotalKeyText(key)) ?? 0n) !== held) {
      states.mismatch(MONTH_TOTALS.subject, { orgId, id });
      mismatched += 1;
    }
  }
  return { totals: ids.length, mismatched, tampered, next };
}
