// An organisation made before TR-2 moved to signed order slots (0114; R-15),
// once, in one transaction: every slot its spend requests then held opened as a
// signed slot (`order_slot.opened`), counted from the requests' signed states
// and their decisions as sealed, never from the claims (the rows the owner
// could have cut); each request's slots named for it in an event of the
// cutover's own (`spend_request.slots_named`), which its ending, a payment's
// failure, the carry and an approval then read with its decision; then its
// cutover event (`order_slots.cutover`), after which a slot with no row is held
// by no one. Until it runs, every decision in it is refused busy
// (weighed-totals.ts). It runs only once the organisation's payee windows are
// cut over (GM-1b), so a decision reading its slots cut over knows its windows
// and month totals are too.
//
// What a request holds is the month totals' cutover's rule (eachSignedHolder):
// waiting, approved or ready, its order; handed off, as its payment says, its
// order kept for good once paid and let go after a verified failure. A request
// decided before E1 still holds its order, so it is counted too (no month
// needed). A request whose decisions can't be read, or with no decision, stops
// the cutover (tampered, alarmed): nothing is opened, and the organisation
// stays busy rather than counting it as nothing.
//
// Each request's order is named by its signed facts: its supplier; its order's
// canonical form, worked out by the database from its sealed reference (0067);
// its bank key, where its decision was made by G5's engine, which made its
// claim with one (`possibleDuplicate` sealed), as the claim was; and its payee
// key where its one claim's key holds to its decision's payee seal (E1b). A
// claim whose key doesn't hold to the seal is alarmed (`holding`) and the
// request counted on its supplier alone, as no signed fact names its key; one
// decided before E1b (no seal) is counted under its claim's key too, as that
// can only refuse an order more, never pay one. Where the claims hold other
// than the requests do, the slots are opened from the requests all the same,
// and the mismatch alarmed (`holding`): the organisation is held until an admin
// looks.
import type { KeyProvider } from '@agentx/platform/keys';
import type { Transaction } from 'kysely';

import type { AuditEvent, AuditTables, SignedStates } from '../../audit/index.ts';
import type { LimitReservationsTables } from '../../limit-reservations/index.ts';
import { payeeWindowsCutOver } from '../../limit-reservations/index.ts';
import { bankKeyOf } from '../domain/asked.ts';
import { heldBy, holdersText, type Holders, noHolders } from '../domain/order-slots.ts';
import type { SpendRequestRecord } from './decisions.ts';
import { type ClaimRow, claimsFor, type Decided, orderKeysOf, type PaymentsOf } from './holdings-check.ts';
import { eachSignedHolder } from './month-totals-cutover.ts';
import {
  ORDER_SLOTS,
  orderHashOf,
  orderSlotId,
  type OrderSlotKey,
  orderSlotKeys,
  orderSlotOf,
  orderSlotOrder,
  orderSlotsCutOver,
  type OrderToSlot,
  recordOrderSlot,
  SLOTS_CUTOVER_ACTION,
  SLOTS_CUTOVER_SUBJECT,
  SLOTS_NAMED_ACTION,
  SLOTS_NAMED_SUBJECT,
  slotsHeldByClaims,
} from './order-slots.ts';
import { payeeAsSealed } from './payee-seal.ts';
import { SPEND_REQUESTS } from './requests.ts';
import type { SpendRequestsTables } from './tables.ts';

type CutoverTransaction = Transaction<SpendRequestsTables & LimitReservationsTables & AuditTables>;

const OPENER = { type: 'system', id: 'api' } as const;

/**
 * What a slots' cutover did: cut over, with how many slots it opened; already cut over; not yet, its payee windows not
 * cut over first; or not, something tampered with (alarmed).
 */
export type SlotsCutoverDone =
  | { readonly outcome: 'cut_over'; readonly opened: number; readonly mismatched: number }
  | { readonly outcome: 'already' | 'not_yet' | 'tampered' };

const ALREADY = Object.freeze({ outcome: 'already' as const });
const NOT_YET = Object.freeze({ outcome: 'not_yet' as const });
const TAMPERED = Object.freeze({ outcome: 'tampered' as const });
/** The slots already counted, or their log not believed: nothing to cut over. */
const STOPPED_BY = { cut_over: ALREADY, tampered: TAMPERED } as const;
/** The payee windows not cut over yet, or their log not believed: the slots wait for them. */
const WAITING_ON = { not_yet: NOT_YET, tampered: TAMPERED } as const;

/** How many requests' claims and references one statement reads: verifiedStates' most, alike. */
const REQUESTS_A_READ = 500;

/** One slot as the requests fill it: which, and who holds it. */
interface Opening {
  readonly key: OrderSlotKey;
  readonly holders: Holders;
}

/**
 * The organisation cut over to signed order slots, in the caller's transaction (withSignedStates' for it), at `at`;
 * `record` adds the cutover's own events to the organisation's chain (an audit trail's record, last).
 */
export async function cutOverOrderSlots<Tx extends CutoverTransaction>(
  tx: Tx,
  states: SignedStates,
  orgId: string,
  {
    keys,
    payments,
    record,
    at,
  }: {
    /** The payee seals' key, to hold each request's claim's payee key to its decision's seal. */
    readonly keys: KeyProvider;
    readonly payments: PaymentsOf<Tx>;
    readonly record: (event: AuditEvent) => Promise<unknown>;
    readonly at: Date;
  },
): Promise<SlotsCutoverDone> {
  const now = await orderSlotsCutOver(tx, states, orgId);
  if (now !== 'not_yet') return STOPPED_BY[now];
  const windows = await payeeWindowsCutOver(tx, states, orgId);
  if (windows !== 'cut_over') return WAITING_ON[windows];
  const holding = await holdingNow(tx, states, orgId, payments);
  if (holding === 'tampered') return TAMPERED;
  const filled = slotsFilled(states, orgId, await ordersOf(tx, states, keys, orgId, holding));
  if (filled === 'tampered') return TAMPERED;
  const { opening, named } = filled;
  // Each read for change first, in order of ID, every one before any is opened: a slot found before the cutover
  // (planted past the app, its read raising the alarm) opens none of them.
  const ordered = [...opening.entries()].toSorted(([a], [b]) => orderSlotOrder(a, b));
  for (const [id] of ordered) {
    if ((await orderSlotOf(tx, states, orgId, id, 'change')).outcome !== 'none') return TAMPERED;
  }
  // Where the claims hold other than the requests do: opened from the requests all the same, the mismatch alarmed.
  const claimed = await slotsHeldByClaims(tx, orgId);
  const apart = [...new Set([...opening.keys(), ...claimed.keys()])].filter(
    (id) => !sameHolders(opening.get(id)?.holders, claimed.get(id)),
  );
  for (const id of apart) states.mismatch(ORDER_SLOTS.subject, { orgId, id });
  // Each request's slots named, so its ending lets go of them and an approval locks them: the sealed facts its slots
  // rest on from now on.
  for (const [requestId, slots] of named) {
    await record({
      actor: OPENER,
      action: SLOTS_NAMED_ACTION,
      subject: { type: SLOTS_NAMED_SUBJECT, id: requestId, version: 1 },
      details: { orderSlots: slots.join(',') },
    });
  }
  for (const [, { key, holders }] of ordered) {
    await recordOrderSlot(tx, states, orgId, key, { outcome: 'none' }, holders, {
      at,
      change: { actor: OPENER, action: 'order_slot.opened', details: {} },
    });
  }
  await record({
    actor: OPENER,
    action: SLOTS_CUTOVER_ACTION,
    subject: { type: SLOTS_CUTOVER_SUBJECT, id: orgId, version: 1 },
    details: { opened: ordered.length, mismatched: apart.length },
  });
  return { outcome: 'cut_over', opened: ordered.length, mismatched: apart.length };
}

/** A request still holding its order, with its decisions as read. */
interface Holding {
  readonly request: SpendRequestRecord;
  readonly decided: Decided;
}

/**
 * Every request still holding its order (eachSignedHolder), or `tampered`: one that can't be believed, or one whose
 * decision already seals slots (decided by TR-2's code, which refuses an organisation not cut over: past the app,
 * alarmed).
 */
async function holdingNow<Tx extends CutoverTransaction>(
  tx: Tx,
  states: SignedStates,
  orgId: string,
  payments: PaymentsOf<Tx>,
): Promise<readonly Holding[] | 'tampered'> {
  const holding: Holding[] = [];
  const sealedAhead: string[] = [];
  const read = await eachSignedHolder(tx, states, orgId, payments, (request, decided) => {
    if (decided.slots !== null) {
      states.mismatch(SPEND_REQUESTS.subject, { orgId, id: request.id });
      sealedAhead.push(request.id);
    }
    holding.push({ request, decided });
  });
  return read === 'tampered' || sealedAhead.length > 0 ? 'tampered' : holding;
}

/**
 * The slots the requests' orders fill, by ID, and each request's slots, in order; `tampered` where two requests hold
 * one order (0039's keys allow it never: something past the app, alarmed). A bank slot full lists no more, and names
 * none of those past it.
 */
function slotsFilled(
  states: SignedStates,
  orgId: string,
  orders: readonly { readonly request: SpendRequestRecord; readonly order: OrderToSlot }[],
): { readonly opening: Map<string, Opening>; readonly named: Map<string, string[]> } | 'tampered' {
  const opening = new Map<string, Opening>();
  const named = new Map<string, string[]>();
  for (const { request, order } of orders) {
    const orderHash = orderHashOf(order.orderKey);
    for (const key of orderSlotKeys(order)) {
      const id = orderSlotId(orgId, key);
      const slot = opening.get(id) ?? { key, holders: noHolders(key.kind) };
      const added = heldBy(slot.holders, { requestId: request.id, orderHash });
      if (added.outcome === 'taken') {
        states.mismatch(ORDER_SLOTS.subject, { orgId, id });
        return 'tampered';
      }
      if (added.outcome !== 'held') continue;
      opening.set(id, { key, holders: added.holders });
      named.set(request.id, [...(named.get(request.id) ?? []), id]);
    }
  }
  return { opening, named };
}

/** Whether the requests' holders of a slot are those its claims name (slotsHeldByClaims' entries). */
function sameHolders(holders: Holders | undefined, claimed: ReadonlySet<string> | undefined): boolean {
  const listed =
    holders === undefined
      ? []
      : holdersText(holders)
          .split(',')
          .filter((entry) => entry !== '');
  const others = claimed ?? new Set<string>();
  return listed.length === others.size && listed.every((entry) => others.has(entry));
}

/**
 * Each holding request's order as its signed facts name it (the header): a page of claims and canonical forms a
 * statement each. A claim whose payee key doesn't hold to its decision's seal is alarmed, and its request counted on
 * its supplier alone.
 */
async function ordersOf(
  tx: CutoverTransaction,
  states: SignedStates,
  keys: KeyProvider,
  orgId: string,
  holding: readonly Holding[],
): Promise<readonly { readonly request: SpendRequestRecord; readonly order: OrderToSlot }[]> {
  const orders = [];
  for (let start = 0; start < holding.length; start += REQUESTS_A_READ) {
    const page = holding.slice(start, start + REQUESTS_A_READ);
    const claims = await claimsFor(
      tx,
      page.map(({ request }) => request.id),
    );
    const canonical = await orderKeysOf(tx, [...new Set(page.map(({ request }) => request.orderReference))]);
    for (const { request, decided } of page) {
      const own = claims.filter(({ requestId }) => requestId.toLowerCase() === request.id);
      const payeeKey = sealedPayeeKey(states, keys, orgId, { request, decided }, own);
      const orderKey = canonical.get(request.orderReference);
      if (orderKey === undefined) throw new Error(`An order's canonical form was not read: ${request.id}`);
      const bankKey = decided.held?.bankKeyed === true ? bankKeyOf(request.orderReference) : null;
      orders.push({ request, order: { supplierId: request.supplierId, payeeKey, orderKey, bankKey } });
    }
  }
  return orders;
}

/**
 * The payee key a request's order is counted under: its one claim's, where that holds to its decision's payee seal or
 * no seal was made (before E1b: a key that can only refuse an order more); none for no one claim, or a key that
 * doesn't hold to the seal (alarmed, `holding`).
 */
function sealedPayeeKey(
  states: SignedStates,
  keys: KeyProvider,
  orgId: string,
  { request, decided }: Holding,
  own: readonly ClaimRow[],
): string | null {
  const [claim] = own;
  const payeeKey = own.length === 1 ? (claim?.payeeKey ?? null) : null;
  if (payeeKey === null) return null;
  if (payeeAsSealed(keys, decided.held?.payee ?? 'none', { orgId, requestId: request.id, payeeKey })) return payeeKey;
  states.mismatch(SPEND_REQUESTS.subject, { orgId, id: request.id });
  return null;
}
