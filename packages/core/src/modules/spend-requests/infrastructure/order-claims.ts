// Order claims (0039; ADR-006 §5, §11; ADR-014 §3, §5; Phase 2 D3): the
// database's safety net against paying one order twice, and the duplicate
// check the decision rests on (`duplicateOrder`, SEC-AG-14), built first in
// Phase 2 and never held up by the split check.
//
// An order is compared by its canonical form (NFKC, case-folded, trimmed,
// spaces collapsed), which the database works out: a request's `order_key`
// is generated from its reference, and the duplicate check, asked before the
// request exists, applies the very same expression to the reference the agent
// sent (`orderKeyOf`; a test holds the two equal). A claim is made from the
// reference as its request was made with, by the same expression, and 0039's
// `for_its_request` key holds it to its request's own supplier and `order_key`.
//
// The caller (D4) holds the supplier FOR NO KEY UPDATE first (ADR-006 §6: 6),
// which serialises the check and the claim for one supplier. Two suppliers
// sharing a payee key aren't serialised by it, so the claim itself may still
// find the order taken: `claimOrder` answers `taken` without failing the
// transaction (the second waits on the first's unique entry, then does
// nothing), and the caller starts again, its check then seeing the claim.
import { type Expression, sql, type Transaction } from 'kysely';

import type { SpendRequestsTables } from './tables.ts';

type ClaimsTransaction = Transaction<SpendRequestsTables>;

/** The canonical form of an order reference, exactly as 0039 generates `order_key`. */
export const orderKeyOf = (reference: Expression<string> | string) =>
  sql<string>`pg_catalog.regexp_replace(pg_catalog.btrim(pg_catalog.lower(pg_catalog.normalize(${reference}::text, 'NFKC'))), ' +', ' ', 'g')`;

/** The order a request asks to pay: to its supplier, under the supplier's payee key when it has one. */
export interface OrderOf {
  readonly orgId: string;
  readonly supplierId: string;
  /** The supplier's payee key as it is (ADR-014 §3); null when it has none. */
  readonly payeeKey: string | null;
}

/**
 * Whether the order is already claimed and not released: by the same
 * supplier, or by the same payee key where there is one, in canonical form.
 */
export async function hasOpenClaim(
  tx: ClaimsTransaction,
  order: OrderOf & { readonly reference: string },
): Promise<boolean> {
  const found = await tx
    .selectFrom('spend_requests.order_claims')
    .select('id')
    .where('org_id', '=', order.orgId)
    .where('released_at', 'is', null)
    .where('order_reference', '=', orderKeyOf(order.reference))
    .where((where) =>
      order.payeeKey === null
        ? where('supplier_id', '=', order.supplierId)
        : where.or([where('supplier_id', '=', order.supplierId), where('payee_key', '=', order.payeeKey)]),
    )
    .limit(1)
    .executeTakeFirst();
  return found !== undefined;
}

/**
 * Claims a request's order, on its own supplier and order: `claimed`,
 * or `taken` when an open claim already holds it (left to the caller to start
 * again, the transaction still usable). A supplier or order not the
 * request's, a payee key not the supplier's, or a request not holding
 * capacity fails (0039's `for_its_request` and `claim_guard`).
 */
export async function claimOrder(
  tx: ClaimsTransaction,
  claim: OrderOf & {
    readonly id: string;
    readonly requestId: string;
    /** The order reference as the request was made with it. */
    readonly reference: string;
    readonly claimedAt: Date;
  },
): Promise<'claimed' | 'taken'> {
  const made = await tx
    .insertInto('spend_requests.order_claims')
    .values({
      org_id: claim.orgId,
      id: claim.id,
      request_id: claim.requestId,
      supplier_id: claim.supplierId,
      payee_key: claim.payeeKey,
      order_reference: orderKeyOf(claim.reference),
      claimed_at: claim.claimedAt,
    })
    // Any open claim on the order (or the request's own) leaves it unmade, the transaction still usable.
    .onConflict((conflict) => conflict.doNothing())
    .returning('id')
    .executeTakeFirst();
  return made === undefined ? 'taken' : 'claimed';
}

/**
 * Releases a request's claim once its request (or its payment) has ended, so
 * the order may be asked for again: whether there was an open one to release.
 */
export async function releaseClaim(
  tx: ClaimsTransaction,
  release: { readonly orgId: string; readonly requestId: string; readonly releasedAt: Date },
): Promise<boolean> {
  const released = await tx
    .updateTable('spend_requests.order_claims')
    .set({ released_at: release.releasedAt })
    .where('org_id', '=', release.orgId)
    .where('request_id', '=', release.requestId)
    .where('released_at', 'is', null)
    .executeTakeFirst();
  return released.numUpdatedRows > 0n;
}
