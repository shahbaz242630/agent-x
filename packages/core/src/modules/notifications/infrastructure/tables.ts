import type { Generated } from 'kysely';

/** The notifications schema's table (db/migrations/0021_notifications_outbox.sql, 0023_outbox_contacts.sql, 0105_outbox_seals.sql), as Kysely sees it. */
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
  /** The notice's seal as queued, and as it ended (0105); none on a notice queued before. */
  mac: Buffer | null;
  mac_key_version: number | null;
  end_mac: Buffer | null;
  end_key_version: number | null;
}
