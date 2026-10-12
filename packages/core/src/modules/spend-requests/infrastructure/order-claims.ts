// Order claims (0039; ADR-006 §5, §11; ADR-014 §3, §5; Phase 2 D3): the
// database's safety net against paying one order twice, and the duplicate
// check the decision rests on (`duplicateOrder`, SEC-AG-14).
//
// An order is compared by its canonical form (NFKC, case-folded, trimmed,
// spaces collapsed), which the database works out: a request's `order_key`
// is generated from its reference, and the duplicate check, asked before the
// request exists, applies the very same expression to the reference the agent
// sent (`orderKeyOf`; a test holds the two equal). A claim is made from the
// reference as its request was made with, by the same expression, and 0039's
// `for_its_request` key holds it to its request's own supplier and `order_key`.
//
// A claim also keeps its `bank_key` (0043; partner decision 11a): its bank
// reference in lower case, the app's (`bankKeyOf`). An open claim with the
// same bank key and another canonical form, on the supplier or its payee key,
// makes the request a possible duplicate, for a person to approve
// (`claimsOn`); the holdings check compares each claim's with its request's.
//
// The caller (D4) holds the supplier FOR NO KEY UPDATE first (ADR-006 §6: 6),
// which serialises the check and the claim for one supplier, and its payee
// key with it: no two suppliers hold one key at once (0033's
// `one_supplier_a_payee`), and a key moves only by a change of the supplier
// holding it, which that lock waits for. So D4 never meets `taken` (it fails
// the request if it does); the answer stays for any caller without the lock.
import { type Expression, type ExpressionBuilder, sql, type Transaction } from 'kysely';

import { bankKeyOf } from '../domain/asked.ts';
import type { SpendRequestsTables } from './tables.ts';

type ClaimsTransaction = Transaction<SpendRequestsTables>;

/** The canonical form of an order reference, exactly as 0039 generates `order_key`. */
export const orderKeyOf = (reference: Expression<string> | string) =>
  sql<string>`pg_catalog.regexp_replace(pg_catalog.btrim(pg_catalog.lower(pg_catalog.normalize(${reference}::text, 'NFKC'))), ' +', ' ', 'g')`;

/** The order a request asks to pay: to its supplier, under the supplier's payee key when it has one. */
export interface OrderOf {
  readonly supplierId: string;
  /** The supplier's payee key as it is (ADR-014 §3); null when it has none. */
  readonly payeeKey: string | null;
  /** The order reference as the agent wrote it. */
  readonly reference: string;
}

type Claims = ExpressionBuilder<SpendRequestsTables, 'spend_requests.order_claims'>;

/** By the same supplier, or by the same payee key where there is one. */
const onTheOrdersPayee = (order: OrderOf) => (where: Claims) =>
  order.payeeKey === null
    ? where('supplier_id', '=', order.supplierId)
    : where.or([where('supplier_id', '=', order.supplierId), where('payee_key', '=', order.payeeKey)]);

/**
 * The open claims on the order, in canonical form, on its supplier or payee;
 * the organisation's alone, by its tenant wall (withTenant).
 */
const openClaimsOn = (tx: ClaimsTransaction, order: OrderOf) =>
  tx
    .selectFrom('spend_requests.order_claims')
    .select('id')
    .where('released_at', 'is', null)
    .where('order_reference', '=', orderKeyOf(order.reference))
    .where(onTheOrdersPayee(order))
    .limit(1);

/** Whether the order is already claimed and not released, in canonical form. */
export async function hasOpenClaim(tx: ClaimsTransaction, order: OrderOf): Promise<boolean> {
  return (await openClaimsOn(tx, order).executeTakeFirst()) !== undefined;
}

/**
 * What the open claims on the order's supplier or payee say of it, in one
 * statement: `duplicate`, one claims it in canonical form (D3: refused);
 * `possible`, one in another form the rail would carry alike (decision 11a:
 * a person approves it). An order whose bank reference would be its
 * request's own ID is never a possible duplicate.
 */
export async function claimsOn(
  tx: ClaimsTransaction,
  order: OrderOf,
): Promise<{ readonly duplicate: boolean; readonly possible: boolean }> {
  const bankKey = bankKeyOf(order.reference);
  const lookalikes = (bank: string) =>
    tx
      .selectFrom('spend_requests.order_claims')
      .select('id')
      .where('released_at', 'is', null)
      .where('bank_key', '=', bank)
      .where('order_reference', '<>', orderKeyOf(order.reference))
      .where(onTheOrdersPayee(order));
  const found = await tx
    .selectNoFrom((select) => [
      select.exists(openClaimsOn(tx, order)).as('duplicate'),
      bankKey === null ? sql<boolean>`false`.as('possible') : select.exists(lookalikes(bankKey)).as('possible'),
    ])
    .executeTakeFirstOrThrow();
  // Postgres answers booleans; Kysely types EXISTS as any dialect's.
  return { duplicate: found.duplicate === true, possible: found.possible === true };
}

/**
 * Claims a request's order, on its own supplier and order: `claimed`, or
 * `taken` when another request's open claim already holds it (left to the
 * caller to start again, the transaction still usable). A supplier or order
 * not the request's, a payee key not the supplier's, or a request not holding
 * capacity fails (0039's `for_its_request` and `claim_guard`).
 */
export async function claimOrder(
  tx: ClaimsTransaction,
  claim: OrderOf & {
    readonly orgId: string;
    readonly id: string;
    readonly requestId: string;
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
      bank_key: bankKeyOf(claim.reference),
      claimed_at: claim.claimedAt,
    })
    // Postgres takes one conflict target and the order has two partial keys, so any key's conflict lands here:
    // checked below.
    .onConflict((conflict) => conflict.doNothing())
    .returning('id')
    .executeTakeFirst();
  if (made !== undefined) return 'claimed';
  // Taken only by another request's open claim: the request's own claim or a reused ID is a caller's bug,
  // which a restart would only meet again.
  const other = await openClaimsOn(tx, claim).where('request_id', '<>', claim.requestId).executeTakeFirst();
  if (other === undefined) throw new Error('an order claim conflicted with no other request’s open claim on its order');
  return 'taken';
}

/** Locks the request's claims FOR NO KEY UPDATE (level 11), before its move takes the audit head (D7, D8). */
export async function lockClaimsOf(tx: ClaimsTransaction, requestId: string): Promise<void> {
  await tx
    .selectFrom('spend_requests.order_claims')
    .select('id')
    .where('request_id', '=', requestId)
    .orderBy('id')
    .forNoKeyUpdate()
    .execute();
}

/**
 * Releases a request's claim once its request (or its payment) has ended, so
 * the order may be asked for again: whether there was an open one to release.
 */
export async function releaseClaim(
  tx: ClaimsTransaction,
  release: { readonly requestId: string; readonly releasedAt: Date },
): Promise<boolean> {
  const released = await tx
    .updateTable('spend_requests.order_claims')
    .set({ released_at: release.releasedAt })
    .where('request_id', '=', release.requestId)
    .where('released_at', 'is', null)
    .executeTakeFirst();
  return released.numUpdatedRows > 0n;
}
