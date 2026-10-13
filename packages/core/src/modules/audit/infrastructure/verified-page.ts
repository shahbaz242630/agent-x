// A page of an organisation's authority rows, each believed only once its
// signed state is (ADR-012 §2): the one paging every list of them shares
// (agents, funding sources, suppliers, mandates), so where a page starts,
// where it stops and what a tampered row does to it are written once. The
// page's rows are verified together (SignedStates.verifiedStates), so a page
// is a few statements however many rows it holds, never one read a row.
import { type SignedStateTable, signedRowIds } from '@agentx/platform/db';

import type { AuditTransaction } from './audit-trail.ts';
import { checkOf, type SignedStates, type TamperSign, type VerifiedState } from './signed-states.ts';

/**
 * A page, with the ID to ask the next page after, or null at the end, and the
 * IDs of its rows that can't be checked now (a backlog of events, Phase 3
 * A1b), left out; or tampered with, and then no page at all.
 */
export type VerifiedPage<Item> =
  | {
      readonly outcome: 'listed';
      readonly items: readonly Item[];
      readonly next: string | null;
      readonly unchecked: readonly string[];
    }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/** What a page asks for: after the row `after` (null from the start), at most `limit`, which is 1 to `most`. */
export interface PageAsked {
  readonly after: string | null;
  readonly limit: number;
}

/** A row of the page, verified: its ID, in lower case, and its signed state. */
export interface PageRow {
  readonly id: string;
  readonly state: VerifiedState;
}

/** The items a page's rows show, in the rows' order; or tampered with, at the first that is (its alarm raised). */
export type PageShown<Item> =
  | { readonly outcome: 'shown'; readonly items: readonly Item[] }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/**
 * A page of the organisation's rows of `table`, in order of ID, in the
 * caller's transaction, which must be withSignedStates' for it: the page's
 * rows verified together, locked `share`, then shown by `show`, which may
 * read what they point to (a supplier's version) the same way, so a page
 * holds nothing that can't be believed. A row gone since its ID was listed
 * is left out, and one that can't be checked now (a backlog of events) is
 * left out and named in `unchecked`. Tampered with, at the first row that is in ID order, the page
 * is refused (every tampered row's alarm raised). Besides `show`'s, six
 * statements a page that holds rows: its IDs, then the rows, then their
 * signed states, each with its tenant check (a row not found whole is read
 * again on its own). A limit outside 1 to `most` is refused before any
 * SQL runs, naming the page's `rows`.
 */
export async function verifiedPage<Item>(
  tx: AuditTransaction,
  states: SignedStates,
  table: SignedStateTable,
  orgId: string,
  { after, limit }: PageAsked,
  { most, rows }: { readonly most: number; readonly rows: string },
  show: (verified: readonly PageRow[]) => PageShown<Item> | Promise<PageShown<Item>>,
): Promise<VerifiedPage<Item>> {
  if (!Number.isInteger(limit) || limit < 1 || limit > most) {
    throw new RangeError(`A page is 1 to ${String(most)} ${rows}`);
  }
  const ids = await signedRowIds(tx, table, orgId, limit, after);
  const page = ids.slice(0, limit);
  const checks = await states.pageStates(tx, table, orgId, page);
  const verified: PageRow[] = [];
  const unchecked: string[] = [];
  for (const id of page) {
    const check = checkOf(checks, id);
    if (check.outcome === 'tampered') return check;
    if (check.outcome === 'backlog') unchecked.push(id.toLowerCase());
    if (check.outcome === 'verified') verified.push({ id: id.toLowerCase(), state: check });
  }
  const shown = await show(verified);
  if (shown.outcome === 'tampered') return shown;
  // One more than the page was there: the next page starts after this one's last.
  return {
    outcome: 'listed',
    items: shown.items,
    next: ids.length > limit ? (page.at(-1) ?? null) : null,
    unchecked,
  };
}
