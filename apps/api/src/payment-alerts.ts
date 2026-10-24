// A payment that needs our team's check, told to its organisation (Phase 4
// gate; partner decision 37b, S143): the bank went back on its word about a
// settled payment, or refused one after its word was read (`contradicted`);
// rejected one with no proof the money stayed (`rejected_unproven`); or left
// one unresolved past a day (`still_unknown`). Each is kept in the
// organisation's audit log and every admin is emailed (0065), in the caller's
// transaction: the one that read the bank's word, so the alert commits with
// it. About the payment's transaction by a subject of its own, never its
// signed state. A payment unresolved past a day is told once; the others are
// told as the bank first says them, by their callers.
import { type AuditTables, createAuditTrail } from '@agentx/core/modules/audit';
import type { NoticeKind, NotificationsTables, Outbox } from '@agentx/core/modules/notifications';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';

export type PaymentAlertTables = AuditTables & NotificationsTables;

/** What about the payment needs our team's check. */
export type PaymentAlert = 'contradicted' | 'rejected_unproven' | 'still_unknown';

/** The email each alert sends its admins. */
const KIND_OF = {
  contradicted: 'payment_contradicted',
  rejected_unproven: 'payment_unproven',
  still_unknown: 'payment_still_unknown',
} as const satisfies Record<PaymentAlert, NoticeKind>;

/** The alert's own subject: the payment's transaction, never its signed state. */
const SUBJECT_TYPE = 'payment_alert';

/** The API, as the actor of the alert's event. */
const ACTOR = { type: 'system', id: 'api' } as const;

/**
 * Keeps the alert in the organisation's audit log and queues its email to
 * every admin, in `tx`; `still_unknown` once a payment (false if told before).
 */
export async function alertAdmins(
  tx: DatabaseTransaction<PaymentAlertTables>,
  { keys, ids, outbox }: { readonly keys: KeyProvider; readonly ids: IdGenerator; readonly outbox: Outbox },
  {
    orgId,
    transactionId,
    alert,
    details = {},
  }: {
    readonly orgId: string;
    readonly transactionId: string;
    readonly alert: PaymentAlert;
    readonly details?: Record<string, string>;
  },
): Promise<boolean> {
  const action = `payment.${alert}`;
  if (alert === 'still_unknown') {
    const told = await tx
      .selectFrom('audit.events')
      .select('seq')
      .where('org_id', '=', orgId)
      .where('subject_type', '=', SUBJECT_TYPE)
      .where('subject_id', '=', transactionId)
      .where('action', '=', action)
      .limit(1)
      .executeTakeFirst();
    if (told !== undefined) return false;
  }
  await createAuditTrail({ keys, ids }).record(tx, orgId, {
    actor: ACTOR,
    action,
    subject: { type: SUBJECT_TYPE, id: transactionId, version: 1 },
    details,
  });
  await outbox.add(tx, [
    {
      orgId,
      recipientUserId: null,
      kind: KIND_OF[alert],
      membershipId: null,
      role: null,
      aboutId: transactionId,
    },
  ]);
  return true;
}
