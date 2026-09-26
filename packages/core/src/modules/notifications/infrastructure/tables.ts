/** The notifications schema's table (db/migrations/0021_notifications_outbox.sql), as Kysely sees it. */
export interface NotificationsTables {
  'notifications.outbox': OutboxTable;
}

interface OutboxTable {
  id: string;
  org_id: string;
  recipient_user_id: string | null;
  kind: string;
  membership_id: string;
  role: string;
  created_at: Date;
  attempts: number;
  next_attempt_at: Date;
  sent_at: Date | null;
  given_up_at: Date | null;
  last_failure: string | null;
}
