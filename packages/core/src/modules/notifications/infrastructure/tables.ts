import type { Generated } from 'kysely';

/** The notifications schema's table (db/migrations/0021_notifications_outbox.sql, 0023_outbox_contacts.sql), as Kysely sees it. */
export interface NotificationsTables {
  'notifications.outbox': OutboxTable;
}

interface OutboxTable {
  id: string;
  org_id: string;
  recipient_user_id: string | null;
  kind: string;
  membership_id: string | null;
  role: string | null;
  created_at: Date;
  attempts: number;
  next_attempt_at: Date;
  sent_at: Date | null;
  given_up_at: Date | null;
  last_failure: string | null;
  recipient_contact_id: string | null;
  to_contacts: Generated<boolean>;
  about_id: string | null;
}
