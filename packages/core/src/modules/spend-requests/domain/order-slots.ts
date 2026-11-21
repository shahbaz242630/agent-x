// Who holds an order's slot (0114; TR-2, R-15; ADR-006 §11; ADR-014 §3;
// decision 11a): the rules the slots keep, apart from how they are stored.
//
// An order kind (`supplier_order`, `payee_order`) is held by one request at
// most: another request asking for the same order, in canonical form, on the
// same supplier or payee key, is a duplicate (D3: refused). A bank kind
// (`supplier_bank`, `payee_bank`) lists every request whose order the bank
// would carry alike, each with the first 16 hex of its order's hash: one in
// another form there makes a new request a possible duplicate (a person
// approves it). A paid request keeps its slots for good; only an ending
// without a payment, or a payment's verified failure, lets them go.

/**
 * The order slots' cutover naming the slots a request decided before TR-2 holds (those the cutover opened it in):
 * about the request, by its ID, under a subject of its own (its own signed state's events are its state changes alone).
 * Here, with the rules, so the holdings check's decisions read can name it without reading the slots.
 */
export const SLOTS_NAMED_SUBJECT = 'spend_request_slots';
export const SLOTS_NAMED_ACTION = 'spend_request.slots_named';

/** The four kinds of slot, as 0114's check names them. */
export const SLOT_KINDS = ['supplier_order', 'payee_order', 'supplier_bank', 'payee_bank'] as const;
export type SlotKind = (typeof SLOT_KINDS)[number];

/** Whether the kind is held by one request (an order) or listed by many (a bank key). */
export const isOrderKind = (kind: SlotKind): boolean => kind === 'supplier_order' || kind === 'payee_order';

/** A request on a bank slot: its order's hash, first 16 hex, and its ID. */
export interface BankEntry {
  readonly orderHash: string;
  readonly requestId: string;
}

/** Who holds a slot: an order kind's request (null: none), or a bank kind's entries, in order. */
export type Holders =
  | { readonly kind: 'order'; readonly holder: string | null }
  | { readonly kind: 'bank'; readonly entries: readonly BankEntry[] };

/**
 * How many requests a bank slot lists (0114's 4,096 characters hold 75): past it a new request is a possible duplicate
 * by the slot alone, never listed, so no slot grows without end.
 */
export const MOST_BANK_ENTRIES = 64;

const REQUEST_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ORDER_HASH = /^[0-9a-f]{16}$/;

/** An entry's place in a bank slot's list: by order hash, then request, so one list has one text. */
const entryOrder = (a: BankEntry, b: BankEntry): number =>
  a.orderHash === b.orderHash
    ? Number(a.requestId > b.requestId) - Number(a.requestId < b.requestId)
    : a.orderHash < b.orderHash
      ? -1
      : 1;

/**
 * The holders a slot's sealed text says, or undefined for text the app never writes (0114's check and the seal hold
 * every row to it, so undefined is something past both).
 */
export function holdersFrom(kind: SlotKind, text: string): Holders | undefined {
  if (isOrderKind(kind)) {
    if (text === '') return { kind: 'order', holder: null };
    return REQUEST_ID.test(text) ? { kind: 'order', holder: text } : undefined;
  }
  if (text === '') return { kind: 'bank', entries: [] };
  const entries: BankEntry[] = [];
  for (const part of text.split(',')) {
    const [orderHash = '', requestId = '', ...more] = part.split(':');
    if (more.length > 0 || !ORDER_HASH.test(orderHash) || !REQUEST_ID.test(requestId)) return undefined;
    entries.push({ orderHash, requestId });
  }
  return entries.length > MOST_BANK_ENTRIES ? undefined : { kind: 'bank', entries };
}

/** The holders as their slot's text: the one request or '', or the entries in order, comma between. */
export function holdersText(holders: Holders): string {
  if (holders.kind === 'order') return holders.holder ?? '';
  return holders.entries.map(({ orderHash, requestId }) => `${orderHash}:${requestId}`).join(',');
}

/** Holders for a slot no request holds yet. */
export const noHolders = (kind: SlotKind): Holders =>
  isOrderKind(kind) ? { kind: 'order', holder: null } : { kind: 'bank', entries: [] };

/**
 * The request added as a holder: an order kind's, where none holds it (`taken` where another does: a duplicate the
 * caller refused before); a bank kind's listed in order, once (`full` past MOST_BANK_ENTRIES: left off the list).
 */
export function heldBy(
  holders: Holders,
  { requestId, orderHash }: BankEntry,
): { readonly outcome: 'held'; readonly holders: Holders } | { readonly outcome: 'taken' | 'full' } {
  const id = requestId.toLowerCase();
  if (holders.kind === 'order') {
    if (holders.holder !== null && holders.holder !== id) return { outcome: 'taken' };
    return { outcome: 'held', holders: { kind: 'order', holder: id } };
  }
  if (holders.entries.some((entry) => entry.requestId === id)) return { outcome: 'held', holders };
  if (holders.entries.length >= MOST_BANK_ENTRIES) return { outcome: 'full' };
  return {
    outcome: 'held',
    holders: { kind: 'bank', entries: [...holders.entries, { orderHash, requestId: id }].toSorted(entryOrder) },
  };
}

/** The requests let go of: the holders without them, and whether every one let go held it (a slot short: a mismatch). */
export function letGo(
  holders: Holders,
  requestIds: readonly string[],
): { readonly holders: Holders; readonly short: boolean } {
  const ids = new Set(requestIds.map((id) => id.toLowerCase()));
  if (holders.kind === 'order') {
    const held = holders.holder !== null && ids.has(holders.holder);
    return { holders: { kind: 'order', holder: held ? null : holders.holder }, short: !held || ids.size > 1 };
  }
  const kept = holders.entries.filter(({ requestId }) => !ids.has(requestId));
  return { holders: { kind: 'bank', entries: kept }, short: holders.entries.length - kept.length !== ids.size };
}

/** Every request a slot's holders name. */
export const holderIds = (holders: Holders): readonly string[] =>
  holders.kind === 'order'
    ? holders.holder === null
      ? []
      : [holders.holder]
    : holders.entries.map(({ requestId }) => requestId);

/**
 * What a request's slots say of its order (claimLooks' two looks, from signed slots): `duplicate`, an order slot held by
 * a request not left out; `possible`, a bank slot listing a request not left out whose order is in another form (its
 * hash apart), or a bank slot full (a lookalike may be past its list). `except`: the requests weighed again (an
 * approval's own, a carry's plan), never their own duplicates.
 */
export function slotsLook(
  slots: readonly Holders[],
  { orderHash, except }: { readonly orderHash: string; readonly except: readonly string[] },
): { readonly duplicate: boolean; readonly possible: boolean } {
  const leftOut = new Set(except.map((id) => id.toLowerCase()));
  let duplicate = false;
  let possible = false;
  for (const holders of slots) {
    if (holders.kind === 'order') {
      if (holders.holder !== null && !leftOut.has(holders.holder)) duplicate = true;
      continue;
    }
    if (holders.entries.length >= MOST_BANK_ENTRIES) possible = true;
    if (holders.entries.some((entry) => entry.orderHash !== orderHash && !leftOut.has(entry.requestId)))
      possible = true;
  }
  return { duplicate, possible };
}
