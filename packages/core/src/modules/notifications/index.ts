// The notifications module (ADR-004, ADR-003 §10; Phase 1 B5): notices to
// people, written to the outbox in the change's own transaction (0021), then
// sent by the API's sender. B5-1a holds the table and the outbox store.
export {
  type ClaimedNotice,
  isNoticeRole,
  type Notice,
  NOTICE_KINDS,
  type NoticeKind,
  type NoticeRole,
} from './domain/notice.ts';
export {
  CLAIM_LEASE_MS,
  createOutbox,
  MOST_ATTEMPTS,
  MOST_NOTICES_A_BATCH,
  type Outbox,
  OUTBOX_RETENTION_DAYS,
} from './infrastructure/outbox.ts';
export type { NotificationsTables } from './infrastructure/tables.ts';
