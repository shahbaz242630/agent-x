// The holdings check (ADR-012 §2; SEC-DB-09; Phase 2 E1): a page of the
// organisation's spend requests, each verified through its signed state and
// locked FOR SHARE (so a move that changes what it holds waits for the page,
// or the page for it), with their reservations and order claims read in one
// statement each and compared by `holdingsMatch`, with the month and instant
// each decision sealed (`heldMonth`, `heldAt`) read from its signed event. A
// request whose holdings don't match raises the integrity alarm (`holding`),
// and the organisation is put on hold once the page's transaction ends
// (withSignedStates).
//
// A page lists the requests the log holds as well as the table's rows
// (`objectIds`), so a request whose row was deleted (with its claim, the
// only way 0039's key lets it go) is read as `deleted`, alarmed, and not
// passed over. A request tampered with is counted and passed over, its
// alarm raised by its read, so it can't hide the ones after it.
//
// A reservation or claim whose request was never made isn't looked for: the
// requests table is read only through signed states, request by request.
// One planted past the app only takes capacity away or blocks an order, never
// pays one (0040's `held_for_its_request` and 0039's `for_its_request` guard
// what the app makes).
import { sql, type Transaction } from 'kysely';

import { type AuditTables, type PageAsked, type SignedStates } from '../../audit/index.ts';
import { type LimitReservationsTables, reservationsFor } from '../../limit-reservations/index.ts';
import { type ClaimHolding, heldOf, holdingsMatch, holdsNow } from '../domain/holdings.ts';
import { type HeldAs, requestOf, type SpendRequestRecord } from './decisions.ts';
import { orderKeyOf } from './order-claims.ts';
import { SPEND_REQUESTS } from './requests.ts';
import type { SpendRequestsTables } from './tables.ts';

type HoldingsTransaction = Transaction<SpendRequestsTables & LimitReservationsTables & AuditTables>;

/** The most requests one page checks: each is a verified read, locked until the page's transaction ends. */
export const MOST_CHECKED_A_PAGE = 200;

/** A request's decided event names one decision: a few more read are already tampering. */
const MOST_DECIDED_EVENTS = 4;

/** A page checked: requests compared, those that didn't match and those tampered with (each alarmed), and where to go on. */
export interface HoldingsChecked {
  readonly requests: number;
  readonly mismatched: number;
  readonly tampered: number;
  /** The ID to start the next page after, or null at the end. */
  readonly next: string | null;
}

/** A claim of a request, as its table holds it. */
interface ClaimRow {
  readonly requestId: string;
  readonly supplierId: string;
  readonly orderKey: string;
  readonly released: boolean;
}

/** The claims of the requests named, in one statement. */
async function claimsFor(tx: HoldingsTransaction, requestIds: readonly string[]): Promise<ClaimRow[]> {
  if (requestIds.length === 0) return [];
  const rows = await tx
    .selectFrom('spend_requests.order_claims')
    .select(['request_id', 'supplier_id', 'order_reference', 'released_at'])
    .where('request_id', 'in', requestIds)
    .execute();
  return rows.map((row) => ({
    requestId: row.request_id,
    supplierId: row.supplier_id,
    orderKey: row.order_reference,
    released: row.released_at !== null,
  }));
}

/** Each reference's canonical form, as 0039 makes a request's `order_key` (`orderKeyOf`), in one statement. */
async function orderKeysOf(tx: HoldingsTransaction, references: readonly string[]): Promise<Map<string, string>> {
  if (references.length === 0) return new Map();
  const { rows } = await sql<{ reference: string; key: string }>`
    select reference, ${orderKeyOf(sql.ref('reference'))} as key
    from pg_catalog.unnest(${[...references]}::text[]) as reference`.execute(tx);
  return new Map(rows.map(({ reference, key }) => [reference, key]));
}

/**
 * The reservation's month and instant the request's decision sealed; null
 * where it sealed none. A history that can't be believed has raised the alarm
 * and holds the organisation already: nothing sealed is then compared.
 */
async function heldAsDecided(
  tx: HoldingsTransaction,
  states: SignedStates,
  orgId: string,
  id: string,
): Promise<HeldAs | null> {
  const history = await states.historyOf(tx, orgId, {
    subjectTypes: [SPEND_REQUESTS.subject],
    subjectId: id,
    actions: ['spend_request.decided'],
    limit: MOST_DECIDED_EVENTS,
  });
  return history.outcome === 'read' ? heldOf(history.events.at(-1)?.event.details) : null;
}

/** Groups rows by their request's ID. */
function byRequest<Row extends { readonly requestId: string }>(rows: readonly Row[]): Map<string, Row[]> {
  const grouped = new Map<string, Row[]>();
  for (const row of rows) grouped.set(row.requestId, [...(grouped.get(row.requestId) ?? []), row]);
  return grouped;
}

/**
 * One page of the organisation's spend requests checked against what they
 * hold, in the caller's transaction, which must be withSignedStates' for it.
 * A limit outside 1 to MOST_CHECKED_A_PAGE is refused before any SQL runs.
 */
export async function checkHoldings(
  tx: HoldingsTransaction,
  states: SignedStates,
  orgId: string,
  { after, limit }: PageAsked,
): Promise<HoldingsChecked> {
  if (!Number.isInteger(limit) || limit < 1 || limit > MOST_CHECKED_A_PAGE) {
    throw new RangeError(`A page is 1 to ${String(MOST_CHECKED_A_PAGE)} spend requests`);
  }
  const { ids, next } = await states.objectIds(tx, orgId, SPEND_REQUESTS, after, limit);
  const requests: SpendRequestRecord[] = [];
  let tampered = 0;
  for (const id of ids) {
    const read = await requestOf(tx, states, { orgId, id });
    // Listed by its row or its signed events, a request not found is one tampered with (its read raised the alarm).
    if (read.outcome === 'found') requests.push(read.request);
    else tampered += 1;
  }
  const found = requests.map(({ id }) => id);
  const reservations = byRequest(await reservationsFor(tx, found));
  const claimed = byRequest(await claimsFor(tx, found));
  const keys = await orderKeysOf(tx, [...new Set(requests.map(({ orderReference }) => orderReference))]);
  let mismatched = 0;
  for (const request of requests) {
    // Only what still holds anything was sealed with what it holds.
    const held = holdsNow(request.status) ? await heldAsDecided(tx, states, orgId, request.id) : null;
    // A claim is its request's own when it is on the request's supplier and order, in canonical form.
    const claims: ClaimHolding[] = (claimed.get(request.id) ?? []).map((claim) => ({
      released: claim.released,
      itsOwn: claim.supplierId === request.supplierId && claim.orderKey === keys.get(request.orderReference),
    }));
    if (!holdingsMatch({ ...request, held }, reservations.get(request.id) ?? [], claims)) {
      states.mismatch(SPEND_REQUESTS.subject, { orgId, id: request.id });
      mismatched += 1;
    }
  }
  return { requests: requests.length, mismatched, tampered, next };
}
