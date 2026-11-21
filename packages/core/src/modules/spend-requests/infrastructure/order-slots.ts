// An order's claim as signed slots (0114; TR-2, R-15; ADR-006 §6 and §11;
// ADR-014 §3; decision 11a; ADR-012 §2): who holds each place an order can be
// claimed, read and changed through its signed state in the same transactions
// that claim and release, so the database's owner can't have an invoice paid
// twice by releasing or deleting its claim. On the product's authority-table
// list (packages/core/src/authority-tables.ts), at level 11c: after a request
// (8), its reservation and claim (11), its agent's month total (11a) and its
// payee's windows (11b), before the audit head (12). A holder of several takes
// them in order of ID, in one statement.
//
// An order is claimed in up to four slots, as the claims are looked at
// (order-claims.ts): its supplier's and, with a key, its payee key's, each by
// the order's canonical form (0067), and, where its reference would reach the
// bank as something (bankKeyOf), its supplier's and its key's by that bank key
// (0043, decision 11a). A decision reads its order's slots for change with its
// month's lock, on the same trip, and its claim adds to them on the claim's
// trip; its decision seals the slots' IDs (`orderSlots`), so an ending lets go
// of the slots it joined, whatever the unsealed claim now says.
//
// A slot's ID is named by its organisation, kind, supplier or key, and the
// SHA-256 of its order or bank key (`orderSlotId`), so one deleted reads as
// deleted (its signed events are still in the log), never as an order no one
// claims; and the read holds the ID to the sealed fields, so a row moved under
// another's ID is refused even before the seal's own check. A slot with no row
// and nothing signed is held by no one once the organisation is counted this
// way (`orderSlotsCutOver`): born so, or cut over by the API's job, which opens
// every slot then held from the signed spend requests. Before that, every
// decision is refused busy, never weighed from the claims.
import { createHash } from 'node:crypto';

import {
  type GatheredRow,
  MOST_ROWS_GATHERED,
  MOST_SIGNED_ROWS_READ,
  type SentTogether,
  type SignedStateTable,
} from '@agentx/platform/db';
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
import { countedFind, countedSince, type CutOver, monthTotalOrder, namedId } from '../../limit-reservations/index.ts';
import {
  type Holders,
  holdersFrom,
  holdersText,
  holderIds,
  isOrderKind,
  letGo,
  MOST_BANK_ENTRIES,
  SLOT_KINDS,
  type SlotKind,
} from '../domain/order-slots.ts';
import type { SpendRequestsTables } from './tables.ts';

type SlotsTransaction = Transaction<SpendRequestsTables & AuditTables>;

/** A slot's row, as the signed state reads, records and checks it. */
export const ORDER_SLOTS = {
  table: 'spend_requests.order_slots',
  subject: 'order_slot',
  fields: [
    { column: 'kind', type: 'text' },
    { column: 'supplier_id', type: 'uuid' },
    { column: 'payee_key', type: 'text' },
    { column: 'key_hash', type: 'text' },
    { column: 'holders', type: 'text' },
    { column: 'created_at', type: 'timestamptz' },
  ],
  // Fixed when the slot is made: 0114's `fixed_at_creation` refuses any change after.
  fixedAtCreation: ['kind', 'supplier_id', 'payee_key', 'key_hash', 'created_at'],
} as const satisfies SignedStateTable & { readonly fixedAtCreation: readonly string[] };

/** Which slot: its kind, its supplier (a supplier kind) or payee key (a payee kind), and its order's or bank key's hash. */
export interface OrderSlotKey {
  readonly kind: SlotKind;
  readonly supplierId: string | null;
  readonly payeeKey: string | null;
  readonly keyHash: string;
}

/** An order as its slots are found: its supplier and that supplier's payee key, its canonical form and its bank key. */
export interface OrderToSlot {
  readonly supplierId: string;
  /** The supplier's payee key as it is (ADR-014 §3); null when it has none. */
  readonly payeeKey: string | null;
  /** Its canonical form, as the database works it out (0067's `order_key_of`): never worked out here. */
  readonly orderKey: string;
  /** Its reference as the bank would carry it (bankKeyOf); null for one never a lookalike. */
  readonly bankKey: string | null;
}

/** The SHA-256 of an order's canonical form or bank key, lower-case hex: what a slot seals in its place. */
export const keyHashOf = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');

/** An order's hash as a bank slot lists it beside its request: the first 16 hex, enough to tell two orders apart. */
export const orderHashOf = (orderKey: string): string => keyHashOf(orderKey).slice(0, 16);

/**
 * The slot's ID: named by which slot it is, the same every time. A payee key goes in as hex, as namedId lower-cases
 * each part and two keys may differ only in case.
 */
export const orderSlotId = (orgId: string, { kind, supplierId, payeeKey, keyHash }: OrderSlotKey): string =>
  namedId(['order_slot', orgId, kind, supplierId ?? Buffer.from(payeeKey ?? '', 'utf8').toString('hex'), keyHash]);

/**
 * The slots an order is claimed in, in this order: its supplier's and (with a key) its key's by its canonical form,
 * then, where it has a bank key, its supplier's and its key's by that.
 */
export function orderSlotKeys({ supplierId, payeeKey, orderKey, bankKey }: OrderToSlot): readonly OrderSlotKey[] {
  const supplier = supplierId.toLowerCase();
  const byOrder = keyHashOf(orderKey);
  const keys: OrderSlotKey[] = [{ kind: 'supplier_order', supplierId: supplier, payeeKey: null, keyHash: byOrder }];
  if (payeeKey !== null) keys.push({ kind: 'payee_order', supplierId: null, payeeKey, keyHash: byOrder });
  if (bankKey !== null) {
    const byBank = keyHashOf(bankKey);
    keys.push({ kind: 'supplier_bank', supplierId: supplier, payeeKey: null, keyHash: byBank });
    if (payeeKey !== null) keys.push({ kind: 'payee_bank', supplierId: null, payeeKey, keyHash: byBank });
  }
  return keys;
}

/** Several slots' IDs in the order every holder of several locks them (11c): the month totals' order alike. */
export const orderSlotOrder = monthTotalOrder;

/** A slot, verified: who holds it, which it is, with the state to change it from; none; or tampered with (alarmed). */
export type OrderSlotCheck =
  | { readonly outcome: 'held'; readonly holders: Holders; readonly key: OrderSlotKey; readonly state: VerifiedState }
  | { readonly outcome: 'none' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

const NONE = Object.freeze({ outcome: 'none' as const });

const isSlotKind = (kind: unknown): kind is SlotKind => SLOT_KINDS.includes(kind as SlotKind);

/**
 * The slot a signed read of its row `id` holds. Its sealed fields must name its own ID (orderSlotId): a row whose seal
 * names another slot is refused and alarmed (`holding`), never read as this one. Its holders are in the form the app
 * writes, as 0114's check and the seal hold them.
 */
export function orderSlotFrom(states: SignedStates, orgId: string, id: string, check: StateCheck): OrderSlotCheck {
  if (check.outcome === 'tampered') return check;
  if (check.outcome === 'missing') return NONE;
  const kind = check.fields.get('kind');
  const keyHash = check.fields.get('key_hash');
  if (!isSlotKind(kind) || typeof keyHash !== 'string') throw new Error('A verified order slot names no slot');
  const key = {
    kind,
    supplierId: check.fields.get('supplier_id') ?? null,
    payeeKey: check.fields.get('payee_key') ?? null,
    keyHash,
  };
  const holders = holdersFrom(kind, String(check.fields.get('holders')));
  if (holders === undefined) throw new Error('A verified order slot holds no holders');
  if (orderSlotId(orgId, key) !== id.toLowerCase()) {
    states.mismatch(ORDER_SLOTS.subject, { orgId, id });
    return Object.freeze({ outcome: 'tampered', sign: 'row' });
  }
  return Object.freeze({ outcome: 'held', holders, key, state: check });
}

/** A slot as a row to gather, so its read rides a trip made anyway (a decision's month lock). */
export const orderSlotGathered = (id: string, lock: 'share' | 'change'): GatheredRow => ({
  table: ORDER_SLOTS,
  id: { id },
  lock,
});

/** One slot by its ID, read through its signed state, locked as asked, in withSignedStates' transaction. */
export async function orderSlotOf(
  tx: SlotsTransaction,
  states: SignedStates,
  orgId: string,
  id: string,
  lock: 'share' | 'change',
): Promise<OrderSlotCheck> {
  return orderSlotFrom(states, orgId, id, await states.verifiedState(tx, ORDER_SLOTS, { orgId, id }, lock));
}

/**
 * The slots named, each once, locked as asked in order of ID (11c), a gather a statement for at most MOST_ROWS_GATHERED
 * of them, then each verified from it (no trip): by ID in lower case. None asked, no trip.
 */
export async function orderSlotsOf(
  tx: SlotsTransaction,
  states: SignedStates,
  orgId: string,
  ids: readonly string[],
  lock: 'share' | 'change',
): Promise<ReadonlyMap<string, OrderSlotCheck>> {
  const ordered = [...new Set(ids.map((id) => id.toLowerCase()))].toSorted(orderSlotOrder);
  for (let start = 0; start < ordered.length; start += MOST_ROWS_GATHERED) {
    await states.gather(
      tx,
      orgId,
      ordered.slice(start, start + MOST_ROWS_GATHERED).map((id) => orderSlotGathered(id, lock)),
    );
  }
  const read = new Map<string, OrderSlotCheck>();
  for (const id of ordered) read.set(id, await orderSlotOf(tx, states, orgId, id, lock));
  return read;
}

/**
 * The order slots' cutover naming the slots a request decided before TR-2 holds (those the cutover opened it in):
 * about the request, by its ID, under a subject of its own (its own signed state's events are its state changes alone).
 */
export const SLOTS_NAMED_SUBJECT = 'spend_request_slots';
export const SLOTS_NAMED_ACTION = 'spend_request.slots_named';

/** The order slots' cutover event: about the organisation, by its ID, under a subject of its own. */
export const SLOTS_CUTOVER_SUBJECT = 'order_slots';
export const SLOTS_CUTOVER_ACTION = 'order_slots.cutover';

const SLOTS_COUNTED = { subject: SLOTS_CUTOVER_SUBJECT, action: SLOTS_CUTOVER_ACTION } as const;

/**
 * Whether the organisation's orders are claimed in signed slots: since its birth (its `organization.created` says
 * `orderSlots: signed`) or its cutover; not yet; or its log can't be believed. The job cuts an organisation's slots over
 * only once its payee windows are (GM-1b), but no read takes this for theirs: a missing total or window is asked of its
 * own cutover, so a slots' cutover alone never makes a month or a payee read as holding nothing.
 */
export const orderSlotsCutOver = (tx: SlotsTransaction, states: SignedStates, orgId: string): Promise<CutOver> =>
  countedSince(tx, states, orgId, { ...SLOTS_COUNTED, born: 'orderSlots' });

/** orderSlotsCutOver's history, for a decision to gather ahead on a trip it makes anyway: then answered with no trip. */
export const orderSlotsCutOverFind = (orgId: string) => countedFind(orgId, SLOTS_COUNTED);

/** The fields of a new slot, as it is added and sealed. */
const newFields = (key: OrderSlotKey, holders: Holders, at: Date) => ({
  kind: key.kind,
  supplier_id: key.supplierId,
  payee_key: key.payeeKey,
  key_hash: key.keyHash,
  holders: holdersText(holders),
  created_at: at,
});

/** A new slot's insert, not run. */
const slotInsert = (tx: SlotsTransaction, orgId: string, key: OrderSlotKey, holders: Holders, at: Date) =>
  tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by the record of its first state in the same transaction
    .insertInto(ORDER_SLOTS.table)
    .values({ org_id: orgId, id: orderSlotId(orgId, key), ...newFields(key, holders, at) });

/** A slot as read for change, or none: one tampered with is refused before anything is written to it. */
export type SlotToWrite = Exclude<OrderSlotCheck, { readonly outcome: 'tampered' }>;

/**
 * A decision's write to one of its order's slots, on the trip that holds its claim (no trip of its own): `held`, from
 * the slot read for change with its month, or a new row for a slot with none (its insert first). The signed state's
 * recordNewAndMove records it with the request's events (`alongside`).
 */
export function orderSlotToSend(
  tx: SlotsTransaction,
  states: SignedStates,
  orgId: string,
  key: OrderSlotKey,
  read: SlotToWrite,
  holders: Holders,
  at: Date,
): { readonly statements: readonly SentTogether[]; readonly sent: ChangeToSend } {
  const id = orderSlotId(orgId, key);
  if (read.outcome === 'held') {
    const sent = states.changeToSend(tx, ORDER_SLOTS, { orgId, id }, read.state, { holders: holdersText(holders) });
    return { statements: [sent.statement], sent };
  }
  const sent = states.changeToSend(tx, ORDER_SLOTS, { orgId, id }, 'new', newFields(key, holders, at));
  return { statements: [slotInsert(tx, orgId, key, holders, at), sent.statement], sent };
}

/** A slot's new holders recorded on its own (an ending's, a payment's, the cutover's), from its read for change or new. */
export async function recordOrderSlot(
  tx: SlotsTransaction,
  states: SignedStates,
  orgId: string,
  key: OrderSlotKey,
  read: SlotToWrite,
  holders: Holders,
  { at, change }: { readonly at: Date; readonly change: SignedChange },
): Promise<void> {
  const id = orderSlotId(orgId, key);
  if (read.outcome === 'held') {
    await states.record(tx, ORDER_SLOTS, { orgId, id }, read.state, { holders: holdersText(holders) }, change);
    return;
  }
  await slotInsert(tx, orgId, key, holders, at).execute();
  await states.record(tx, ORDER_SLOTS, { orgId, id }, 'new', newFields(key, holders, at), change);
}

/** A request's hold on one slot, to let go: the slot, and the request. */
export interface SlotTake {
  readonly id: string;
  readonly requestId: string;
}

/** The slots a request's sealed decision names (or its cutover named), each as one to let go. */
export const slotTakesOf = (requestId: string, slots: readonly string[] | null): readonly SlotTake[] =>
  (slots ?? []).map((id) => ({ id: id.toLowerCase(), requestId: requestId.toLowerCase() }));

/**
 * Each take let go of its slot, read for change in this transaction (`read`, by ID in lower case: an ending, a brake's
 * batch, a payment's verified failure), one record a slot for all its takes, the requests in its event. A slot tampered
 * with is left (its alarm raised by its read): the request still ends, as a brake must. One missing is nothing to let go
 * before the organisation's cutover, and after it a mismatch (`holding`): its request held it. A slot not held by a
 * request it lets go of is a mismatch too, and the rest let go all the same.
 */
export async function slotsLetGo(
  tx: SlotsTransaction,
  states: SignedStates,
  orgId: string,
  read: ReadonlyMap<string, OrderSlotCheck>,
  takes: readonly SlotTake[],
  recorded: { readonly at: Date; readonly change: SignedChange },
): Promise<void> {
  const bySlot = new Map<string, string[]>();
  for (const { id, requestId } of takes) {
    const slot = id.toLowerCase();
    bySlot.set(slot, [...new Set([...(bySlot.get(slot) ?? []), requestId.toLowerCase()])]);
  }
  for (const [id, requestIds] of [...bySlot].toSorted(([a], [b]) => orderSlotOrder(a, b))) {
    const slot = read.get(id);
    if (slot === undefined) throw new Error(`An order slot let go of was not read for change: ${id}`);
    if (slot.outcome === 'tampered') continue;
    if (slot.outcome === 'none') {
      if ((await orderSlotsCutOver(tx, states, orgId)) !== 'not_yet')
        states.mismatch(ORDER_SLOTS.subject, { orgId, id });
      continue;
    }
    const { holders, short } = letGo(slot.holders, requestIds);
    if (short) states.mismatch(ORDER_SLOTS.subject, { orgId, id });
    if (holdersText(holders) === holdersText(slot.holders)) continue;
    const { at, change } = recorded;
    await recordOrderSlot(tx, states, orgId, slot.key, slot, holders, {
      at,
      change: { ...change, details: { ...change.details, requestIds: requestIds.join(',') } },
    });
  }
}

/**
 * slotsLetGo for one request's slots as its caller locked them (a payment's verified failure): none read (its caller
 * never locked them) lets go of nothing, which the holdings check then finds as a slot held with its claim released:
 * the order stays refused, never paid twice.
 */
export async function heldSlotsLetGo(
  tx: SlotsTransaction,
  states: SignedStates,
  orgId: string,
  held: { readonly slotsRead: ReadonlyMap<string, OrderSlotCheck>; readonly slots: readonly SlotTake[] } | undefined,
  recorded: { readonly at: Date; readonly change: SignedChange },
): Promise<void> {
  if (held === undefined) return;
  await slotsLetGo(tx, states, orgId, held.slotsRead, held.slots, recorded);
}

/** An open claim, as its table holds it: its request, supplier, payee key, canonical form and bank key. */
interface OpenClaim extends OrderToSlot {
  readonly requestId: string;
}

/** Who each slot should hold by the open claims named: an order kind's request, a bank kind's entries, by slot ID. */
type HeldByClaims = Map<string, Set<string>>;

/**
 * Each open claim's slots (orderSlotKeys, with its own payee key and bank key, none before G5) and who each holds by
 * them: an order slot its request, a bank slot `hash16:request`.
 */
function slotsOfClaims(orgId: string, claims: readonly OpenClaim[]): HeldByClaims {
  const held: HeldByClaims = new Map();
  for (const claim of claims) {
    const requestId = claim.requestId.toLowerCase();
    const orderHash = orderHashOf(claim.orderKey);
    for (const key of orderSlotKeys(claim)) {
      const id = orderSlotId(orgId, key);
      const entry = isOrderKind(key.kind) ? requestId : `${orderHash}:${requestId}`;
      held.set(id, new Set([...(held.get(id) ?? []), entry]));
    }
  }
  return held;
}

/**
 * The open claims on the suppliers or payee keys named, or made since `since`, in one statement. Unsealed: only ever
 * compared with the signed slots (the holdings check), never weighed.
 */
async function openClaims(
  tx: SlotsTransaction,
  which: { readonly supplierIds: readonly string[]; readonly payeeKeys: readonly string[] } | { readonly since: Date },
): Promise<OpenClaim[]> {
  const { rows } = await sql<{
    request_id: string;
    supplier_id: string;
    payee_key: string | null;
    order_reference: string;
    bank_key: string | null;
  }>`
    select request_id, supplier_id, payee_key, order_reference, bank_key from spend_requests.order_claims
    where released_at is null and ${
      'since' in which
        ? sql<boolean>`claimed_at >= ${which.since}`
        : sql<boolean>`(supplier_id = any(${[...which.supplierIds]}::uuid[]) or payee_key = any(${[...which.payeeKeys]}::text[]))`
    }`.execute(tx);
  return rows.map((row) => ({
    requestId: row.request_id,
    supplierId: row.supplier_id,
    payeeKey: row.payee_key,
    orderKey: row.order_reference,
    bankKey: row.bank_key,
  }));
}

/**
 * Who each slot should hold by every open claim of the organisation, in one statement: by slot ID, an order slot's
 * request, a bank slot's `hash16:request` entries (the slots' cutover's comparison, TR-2).
 */
export async function slotsHeldByClaims(
  tx: SlotsTransaction,
  orgId: string,
): Promise<ReadonlyMap<string, ReadonlySet<string>>> {
  return slotsOfClaims(orgId, await openClaims(tx, { since: new Date(0) }));
}

/** Whether a slot's holders are those the claims say: the same, or, for a bank slot full, all listed among them. */
export function slotAsClaimed(holders: Holders, claimed: ReadonlySet<string>): boolean {
  const listed =
    holders.kind === 'order'
      ? holderIds(holders)
      : holders.entries.map(({ orderHash, requestId }) => `${orderHash}:${requestId}`);
  if (!listed.every((entry) => claimed.has(entry))) return false;
  return listed.length === claimed.size || (holders.kind === 'bank' && listed.length >= MOST_BANK_ENTRIES);
}

/** The most slots one page of the holdings check reads: each a verified read, locked until its page ends. */
export const MOST_SLOTS_CHECKED_A_PAGE = 200;

/** A page of the organisation's slots checked: slots compared, mismatched and tampered with, and where to go on. */
export interface SlotsChecked {
  readonly slots: number;
  readonly mismatched: number;
  readonly tampered: number;
  readonly next: string | null;
}

/**
 * One page of the organisation's order slots (TR-2), each verified and locked FOR SHARE, so every claim and release
 * (each made under the slot's lock for change) waits for the page or comes before it, then held to the open claims on
 * its supplier or payee key, in one statement: a slot and its claims apart is a mismatch (`holding`, alarmed). With the
 * requests' own check (each claim held to its signed request, its order and payee key to its sealed decision), a slot
 * is so held to the signed requests too. Listed from the rows and the log, so one deleted is read as `deleted`,
 * alarmed. In withSignedStates' transaction.
 */
export async function checkOrderSlots(
  tx: SlotsTransaction,
  states: SignedStates,
  orgId: string,
  { after, limit }: { readonly after: string | null; readonly limit: number },
): Promise<SlotsChecked> {
  if (!Number.isInteger(limit) || limit < 1 || limit > MOST_SLOTS_CHECKED_A_PAGE) {
    throw new RangeError(`A page is 1 to ${String(MOST_SLOTS_CHECKED_A_PAGE)} order slots`);
  }
  const { ids, next } = await states.objectIds(tx, orgId, ORDER_SLOTS, after, limit);
  const checks =
    ids.length === 0 ? new Map<string, StateCheck>() : await states.verifiedStates(tx, ORDER_SLOTS, orgId, ids);
  const verified: { readonly id: string; readonly key: OrderSlotKey; readonly holders: Holders }[] = [];
  let tampered = 0;
  for (const [id, check] of checks) {
    const slot = orderSlotFrom(states, orgId, id, check);
    // Listed by its row or its signed events, a slot not found is one tampered with (its read raised the alarm).
    if (slot.outcome === 'held') verified.push({ id, key: slot.key, holders: slot.holders });
    else tampered += 1;
  }
  const named = (pick: (key: OrderSlotKey) => string | null) => [
    ...new Set(verified.flatMap(({ key }) => pick(key) ?? [])),
  ];
  const claimed =
    verified.length === 0
      ? new Map<string, Set<string>>()
      : slotsOfClaims(
          orgId,
          await openClaims(tx, {
            supplierIds: named(({ supplierId }) => supplierId),
            payeeKeys: named(({ payeeKey }) => payeeKey),
          }),
        );
  let mismatched = 0;
  for (const { id, holders } of verified) {
    if (!slotAsClaimed(holders, claimed.get(id) ?? new Set())) {
      states.mismatch(ORDER_SLOTS.subject, { orgId, id });
      mismatched += 1;
    }
  }
  return { slots: ids.length, mismatched, tampered, next };
}

/**
 * How far back the holdings check looks for a slot never made beside its claim: a slot made once is in the log for good
 * (read `deleted` if its row goes), so only a claim made without its slot is looked for, and the check passes every
 * organisation at least hourly; a month leaves room for any pause.
 */
export const SLOTS_MISSING_LOOK_BACK_MS = 31 * 24 * 3_600_000;

/**
 * Every slot an open claim made since SLOTS_MISSING_LOOK_BACK_MS before `at` should be held in, yet that has no row and
 * nothing signed, once the organisation is cut over: each alarmed (`holding`), with how many. The claims in one
 * statement, the slots a few hundred at a time (verifiedStates, FOR SHARE). Before the cutover there is none to look for.
 */
export async function slotsMissing(
  tx: SlotsTransaction,
  states: SignedStates,
  orgId: string,
  at: Date,
): Promise<number> {
  if ((await orderSlotsCutOver(tx, states, orgId)) !== 'cut_over') return 0;
  const since = new Date(at.getTime() - SLOTS_MISSING_LOOK_BACK_MS);
  const ids = [...slotsOfClaims(orgId, await openClaims(tx, { since })).keys()];
  let missing = 0;
  for (let start = 0; start < ids.length; start += MOST_SIGNED_ROWS_READ) {
    const checks = await states.verifiedStates(tx, ORDER_SLOTS, orgId, ids.slice(start, start + MOST_SIGNED_ROWS_READ));
    for (const [id, check] of checks) {
      if (check.outcome !== 'missing') continue;
      states.mismatch(ORDER_SLOTS.subject, { orgId, id });
      missing += 1;
    }
  }
  return missing;
}
