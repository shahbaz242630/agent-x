// The holdings check (ADR-012 §2; SEC-DB-09; Phase 2 E1): a page of the
// organisation's spend requests, each verified through its signed state and
// locked FOR SHARE (so a move that changes what it holds waits for the page,
// or the page for it), with their reservations and order claims read in one
// statement each and compared by `holdingsMatch`. A request whose holdings
// don't match raises the integrity alarm (`holding`), and the organisation is
// put on hold once the page's transaction ends (withSignedStates). A request
// tampered with refuses the page, its own alarm raised by its read.
//
// A reservation or claim whose request isn't there at all isn't looked for:
// the requests table is read only through signed states, request by request.
// One planted past the app only takes capacity away or blocks an order, never
// pays one (0040's `held_for_its_request` and 0039's `for_its_request` guard
// what the app makes).
import { sql, type Transaction } from 'kysely';

import {
  type AuditTables,
  type PageAsked,
  type SignedStates,
  type TamperSign,
  verifiedPage,
} from '../../audit/index.ts';
import { type LimitReservationsTables, reservationsFor } from '../../limit-reservations/index.ts';
import { type ClaimHolding, holdingsMatch } from '../domain/holdings.ts';
import { requestOf, type SpendRequestRecord } from './decisions.ts';
import { orderKeyOf } from './order-claims.ts';
import { SPEND_REQUESTS } from './requests.ts';
import type { SpendRequestsTables } from './tables.ts';

type HoldingsTransaction = Transaction<SpendRequestsTables & LimitReservationsTables & AuditTables>;

/** The most requests one page checks: each is a verified read, locked until the page's transaction ends. */
export const MOST_CHECKED_A_PAGE = 200;

export type HoldingsChecked =
  | {
      readonly outcome: 'checked';
      readonly requests: number;
      readonly mismatched: number;
      readonly next: string | null;
    }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

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

/** Groups rows by their request's ID. */
function byRequest<Row extends { readonly requestId: string }>(rows: readonly Row[]): Map<string, Row[]> {
  const grouped = new Map<string, Row[]>();
  for (const row of rows) grouped.set(row.requestId, [...(grouped.get(row.requestId) ?? []), row]);
  return grouped;
}

/**
 * One page of the organisation's spend requests checked against what they
 * hold, in the caller's transaction, which must be withSignedStates' for it:
 * how many were checked and how many didn't match (each alarmed), with the ID
 * to start the next page after, or null at the end.
 */
export async function checkHoldings(
  tx: HoldingsTransaction,
  states: SignedStates,
  orgId: string,
  page: PageAsked,
): Promise<HoldingsChecked> {
  const listed = await verifiedPage<SpendRequestsTables, SpendRequestRecord>(
    tx,
    SPEND_REQUESTS,
    orgId,
    page,
    { most: MOST_CHECKED_A_PAGE, rows: 'spend requests' },
    async (id) => {
      const read = await requestOf(tx, states, { orgId, id });
      return read.outcome === 'found' ? { outcome: 'found', item: read.request } : read;
    },
  );
  if (listed.outcome === 'tampered') return listed;
  const ids = listed.items.map(({ id }) => id);
  const reservations = byRequest(await reservationsFor(tx, ids));
  const claimed = byRequest(await claimsFor(tx, ids));
  const keys = await orderKeysOf(tx, [...new Set(listed.items.map(({ orderReference }) => orderReference))]);
  let mismatched = 0;
  for (const request of listed.items) {
    // A claim is its request's own when it is on the request's supplier and order, in canonical form.
    const claims: ClaimHolding[] = (claimed.get(request.id) ?? []).map((claim) => ({
      released: claim.released,
      itsOwn: claim.supplierId === request.supplierId && claim.orderKey === keys.get(request.orderReference),
    }));
    if (!holdingsMatch(request, reservations.get(request.id) ?? [], claims)) {
      states.mismatch(SPEND_REQUESTS.subject, { orgId, id: request.id });
      mismatched += 1;
    }
  }
  return { outcome: 'checked', requests: ids.length, mismatched, next: listed.next };
}
