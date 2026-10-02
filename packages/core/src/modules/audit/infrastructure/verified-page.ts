// A page of an organisation's authority rows, each believed only once its
// signed state is (ADR-012 §2): the one paging every list of them shares
// (agents, funding sources, suppliers), so where a page starts, where it
// stops and what a tampered row does to it are written once.
import { type SignedStateTable, signedRowIds } from '@agentx/platform/db';
import type { Transaction } from 'kysely';

import type { TamperSign } from './signed-states.ts';

/** One row as its module reads it through its signed state (agentOf, sourceOf, supplierOf). */
export type PageRead<Item> =
  | { readonly outcome: 'found'; readonly item: Item }
  | { readonly outcome: 'missing' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** A page, with the ID to ask the next page after, or null at the end; or tampered with, and then no page at all. */
export type VerifiedPage<Item> =
  | { readonly outcome: 'listed'; readonly items: readonly Item[]; readonly next: string | null }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** What a page asks for: after the row `after` (null from the start), at most `limit`, which is 1 to `most`. */
export interface PageAsked {
  readonly after: string | null;
  readonly limit: number;
}

/**
 * A page of the organisation's rows of `table`, in order of ID, in the
 * caller's transaction, which must be withSignedStates' for it: each row read
 * by `read`, so a page holds nothing that can't be believed. A row gone since
 * its ID was listed is left out. Tampered with, at the first row that is, the
 * page is refused (`read` raised the alarm). Besides each row's own read, two
 * statements a page: the tenant check and its IDs. A limit outside 1 to `most` is refused before
 * any SQL runs, naming the page's `rows`.
 */
export async function verifiedPage<Schema, Item>(
  tx: Transaction<Schema>,
  table: SignedStateTable,
  orgId: string,
  { after, limit }: PageAsked,
  { most, rows }: { readonly most: number; readonly rows: string },
  read: (id: string) => Promise<PageRead<Item>>,
): Promise<VerifiedPage<Item>> {
  if (!Number.isInteger(limit) || limit < 1 || limit > most) {
    throw new RangeError(`A page is 1 to ${String(most)} ${rows}`);
  }
  const ids = await signedRowIds(tx, table, orgId, limit, after);
  const items: Item[] = [];
  let last: string | null = null;
  for (const id of ids.slice(0, limit)) {
    const found = await read(id);
    if (found.outcome === 'tampered') return found;
    if (found.outcome === 'found') items.push(found.item);
    last = id;
  }
  // One more than the page was there: the next page starts after this one's last.
  return { outcome: 'listed', items, next: ids.length > limit ? last : null };
}
