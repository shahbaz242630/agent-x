// The notifications module (ADR-004, ADR-003 §10; Phase 1 B5): notices to
// people, written to the outbox in the change's own transaction (0021), then
// sent by the API's sender through a notifier, to the address the login
// service gives at send time. It depends on no other module: a module whose
// change tells people (identity) calls it.
export { messageFor, type NoticeMessage, type ResetLink } from './domain/messages.ts';
export { type AcsSettings, createAcsNotifier, EMAIL_API_VERSION } from './infrastructure/acs-notifier.ts';
export {
  type ClaimedNotice,
  isNoticeKind,
  MANDATE_NOTICE_KINDS,
  isNoticeRole,
  type Notice,
  NOTICE_KINDS,
  type NoticeKind,
  type NoticeRole,
  SIGN_IN_NOTICE_KINDS,
  type SignInNoticeKind,
} from './domain/notice.ts';
export {
  CLAIM_LEASE_MS,
  createOutbox,
  LEASE_EXPIRED,
  MOST_ATTEMPTS,
  MOST_NOTICES_A_BATCH,
  MOST_RECIPIENTS,
  type Outbox,
  OUTBOX_RETENTION_DAYS,
} from './infrastructure/outbox.ts';
export {
  type AddressBook,
  type Admin,
  type Audience,
  type ContactAddresses,
  createNoticeSender,
  type Notifier,
  type NoticeSender,
  NOTICES_A_RUN,
  type ResetLinks,
  type SendOutcome,
} from './infrastructure/sender.ts';
export type { NotificationsTables } from './infrastructure/tables.ts';
