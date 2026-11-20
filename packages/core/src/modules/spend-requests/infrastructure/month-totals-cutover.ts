// An organisation made before GM-1a moved to signed month totals (0110;
// R-15), once, in one transaction: every month its spend requests then held
// capacity in opened as a signed total (`month_total.opened`), counted from
// the requests' signed states and their decisions' sealed months, never from
// the reservations (the rows the owner could have cut); then its cutover event
// (`month_totals.cutover`), after which a month with no total holds nothing.
// Until it runs, every check of a month in it is refused busy (month-totals.ts).
//
// What a request holds is the holdings check's rule (domain/holdings.ts):
// waiting, approved or ready, its whole amount; handed off, as its payment
// says, nothing once a verified failure or cancellation released it (a
// payment that can't be believed is counted, the safer side). A request still
// holding whose decisions can't be read, or with no decision at all, stops the
// cutover (tampered, alarmed): nothing is opened and no cutover recorded, so
// its organisation stays busy rather than counting it as nothing. One whose
// decision is read whole yet seals no month was decided before E1 (every
// decision holding capacity since seals one, and the chain's MAC keeps an
// event as written): no total counts it, and the reservations compared leave
// it out alike (reservationsHeldIn). Where the reservations hold other than the
// requests do, the total is opened from the requests all the same, and the
// mismatch alarmed (`holding`): the organisation is held until an admin looks.
//
// Every request is read FOR SHARE, a page at a time, so an ending or a payment
// moving one waits for the cutover or comes before it: each is then counted
// as it ended, and gives back to its total only after the cutover (it reads
// the total for change, which is there by then). Decisions are refused busy
// meanwhile, so none adds a reservation. A release still running the code
// before GM-1a while this runs could reserve unseen: the holdings check
// alarms such a total.
import type { Transaction } from 'kysely';

import type { AuditEvent, AuditTables, SignedStates } from '../../audit/index.ts';
import {
  agentMonthLocking,
  type LimitReservationsTables,
  MONTH_TOTALS,
  monthTotalId,
  type MonthTotalKey,
  monthTotalKeyFrom,
  monthTotalKeyText,
  monthTotalOf,
  monthTotalsCutOver,
  CUTOVER_ACTION,
  CUTOVER_SUBJECT,
  recordMonthTotal,
  reservationsHeldIn,
} from '../../limit-reservations/index.ts';
import { holdsNow } from '../domain/holdings.ts';
import { requestsOf, type SpendRequestRecord } from './decisions.ts';
import { decisionsRead, type PaymentsOf } from './holdings-check.ts';
import { SPEND_REQUESTS } from './requests.ts';
import type { SpendRequestsTables } from './tables.ts';

type CutoverTransaction = Transaction<SpendRequestsTables & LimitReservationsTables & AuditTables>;

/** How many requests one statement of the cutover reads: verifiedStates' most. */
const REQUESTS_A_READ = 500;

const OPENER = { type: 'system', id: 'api' } as const;

/** What a cutover did: cut over, with how many totals it opened; already cut over; or not, something tampered with (alarmed). */
export type CutoverDone =
  | { readonly outcome: 'cut_over'; readonly opened: number; readonly mismatched: number }
  | { readonly outcome: 'already' }
  | { readonly outcome: 'tampered' };

/**
 * The organisation cut over to signed month totals, in the caller's
 * transaction (withSignedStates' for it), at `at`; `record` adds the cutover's
 * own event to the organisation's chain (an audit trail's record, last).
 */
export async function cutOverMonthTotals<Tx extends CutoverTransaction>(
  tx: Tx,
  states: SignedStates,
  orgId: string,
  {
    payments,
    record,
    at,
  }: { readonly payments: PaymentsOf<Tx>; readonly record: (event: AuditEvent) => Promise<unknown>; readonly at: Date },
): Promise<CutoverDone> {
  const now = await monthTotalsCutOver(tx, states, orgId);
  if (now !== 'not_yet') return now === 'cut_over' ? ALREADY : TAMPERED;
  const held = await heldBySigned(tx, states, orgId, payments);
  if (held === 'tampered') return TAMPERED;
  const reserved = await reservationsHeldIn(tx, 'all');
  // Each month either side holds, by its key's text: a month the requests hold nothing in is named as its total would be.
  const signed = new Map([...held].map(([text, { amount }]) => [text, amount]));
  const apart = [...new Set([...signed.keys(), ...reserved.keys()])].filter(
    (text) => amountIn(signed, text) !== amountIn(reserved, text),
  );
  for (const text of apart) {
    states.mismatch(MONTH_TOTALS.subject, { orgId, id: monthTotalId(orgId, monthTotalKeyFrom(text)) });
  }
  const mismatched = apart.length;
  // Each a new row, made while decisions are refused, so no order among them matters. Every request holds at least
  // 1 minor unit, so each month listed has something to open. Each read first, every one before any is opened, so a
  // total found before the cutover (planted past the app: its read raised the alarm) opens none of them.
  const opening = [...held.values()];
  const totals = [];
  for (const { key, amount } of opening) {
    // Its period added if it isn't there (the total points at it), not locked: the requests are, and decisions are
    // refused until the cutover commits. One decision that read the month empty as the cutover committed is answered
    // busy on the total's key: never over its limit.
    const [added] = agentMonthLocking(tx, { orgId, agentId: key.agentId, month: key.month, at });
    await added.execute();
    const total = await monthTotalOf(tx, states, orgId, key, 'change');
    if (total.outcome !== 'none') return TAMPERED;
    totals.push({ key, amount, total });
  }
  for (const { key, amount, total } of totals) {
    await recordMonthTotal(tx, states, orgId, key, total, amount, {
      at,
      change: { actor: OPENER, action: 'month_total.opened', details: {} },
    });
  }
  await record({
    actor: OPENER,
    action: CUTOVER_ACTION,
    subject: { type: CUTOVER_SUBJECT, id: orgId, version: 1 },
    details: { opened: opening.length, mismatched },
  });
  return { outcome: 'cut_over', opened: opening.length, mismatched };
}

/** What one month holds, by its key. */
type HeldByMonth = Map<string, { key: MonthTotalKey; amount: bigint }>;

const ALREADY = Object.freeze({ outcome: 'already' as const });
const TAMPERED = Object.freeze({ outcome: 'tampered' as const });

/** What one side holds in the month the text names: nothing where it holds none. */
const amountIn = (side: ReadonlyMap<string, bigint>, text: string): bigint => side.get(text) ?? 0n;

/**
 * What the organisation's signed spend requests hold in each month, by
 * monthTotalKeyText: every request the table or the log holds, read a page at
 * a time FOR SHARE; `tampered` if any can't be believed (its alarm raised).
 */
async function heldBySigned<Tx extends CutoverTransaction>(
  tx: Tx,
  states: SignedStates,
  orgId: string,
  payments: PaymentsOf<Tx>,
): Promise<HeldByMonth | 'tampered'> {
  const held: HeldByMonth = new Map();
  let after: string | null = null;
  do {
    const listed: { readonly ids: readonly string[]; readonly next: string | null } = await states.objectIds(
      tx,
      orgId,
      SPEND_REQUESTS,
      after,
      REQUESTS_A_READ,
    );
    const holding = await holdingOf(tx, states, orgId, listed.ids);
    if (holding === 'tampered') return 'tampered';
    if ((await addHeld(tx, states, orgId, payments, holding, held)) === 'tampered') return 'tampered';
    after = listed.next;
  } while (after !== null);
  return held;
}

/** The requests of a page that still hold capacity, each verified; `tampered` if any can't be believed. */
async function holdingOf(
  tx: CutoverTransaction,
  states: SignedStates,
  orgId: string,
  ids: readonly string[],
): Promise<SpendRequestRecord[] | 'tampered'> {
  if (ids.length === 0) return [];
  const holding: SpendRequestRecord[] = [];
  for (const check of (await requestsOf(tx, states, orgId, ids)).values()) {
    if (check.outcome !== 'found') return 'tampered';
    if (holdsNow(check.request.status)) holding.push(check.request);
  }
  return holding;
}

/**
 * Each request's amount added to its month's, by its decision's sealed month; none once its payment ended.
 * `tampered` when the decisions can't be read (their alarm raised), or a request still holding has no decision with a
 * sealed month (alarmed here, `holding`): never taken for "nothing held", which would open no total for it.
 */
async function addHeld<Tx extends CutoverTransaction>(
  tx: Tx,
  states: SignedStates,
  orgId: string,
  payments: PaymentsOf<Tx>,
  holding: readonly SpendRequestRecord[],
  held: HeldByMonth,
): Promise<'added' | 'tampered'> {
  const handedOff = holding.filter(({ status }) => status === 'HANDED_OFF').map(({ id }) => id);
  const paid = await payments(tx, states, orgId, handedOff);
  const decided = await decisionsRead(
    tx,
    states,
    orgId,
    holding.map(({ id }) => id),
  );
  if (decided === 'tampered') return 'tampered';
  for (const request of holding.filter(({ id }) => paid.get(id) !== 'ended')) {
    const decision = decided.get(request.id);
    if (decision === undefined) {
      states.mismatch(SPEND_REQUESTS.subject, { orgId, id: request.id });
      return 'tampered';
    }
    // Its decision read whole and sealing no month: written before E1, which no total counts.
    if (decision.held === null) continue;
    const key = { agentId: request.agentId, month: decision.held.month, currency: request.amount.currency };
    const text = monthTotalKeyText(key);
    held.set(text, { key, amount: (held.get(text)?.amount ?? 0n) + request.amount.minor });
  }
  return 'added';
}
