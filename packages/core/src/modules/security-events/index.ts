// The security-events module (ADR-004, ADR-005 §6, ADR-011 §7): failed
// sign-ins and rate-limit hits with the client's IP address, in a global
// table (0012), kept in-country for the retention period the config names.
// B2-5b gathers them from the API; B2-5a holds the table, the writes and the
// retention sweep. 6E1b (CO7b) keeps those tied to an organisation in its own
// walled table (0091), and reads them for its admins. S206 V6: each row
// carries a MAC, and each day of rows is sealed on an audit chain (0105); the
// partner's refused messages kept as evidence use its MACs too.
export {
  createSecurityEvents,
  LEAST_RETENTION_DAYS,
  MOST_EVENTS_A_BATCH,
  ORG_EVENT_KINDS,
  SECURITY_EVENT_KINDS,
  type SecurityEvent,
  type SecurityEventKind,
  type SecurityEvents,
} from './infrastructure/security-events.ts';
export {
  type OrgEventCursor,
  type OrgEventsChecked,
  type OrgEventsToRead,
  orgSecurityEventsPage,
  type OrgSecurityEvent,
} from './infrastructure/org-events.ts';
export {
  anythingToSeal,
  brokenSecuritySeal,
  firstCheckableDay,
  evidenceMessage,
  legacyExcused,
  type LegacyRows,
  nextDayWithRows,
  outOfRange,
  rowMac,
  rowMacHolds,
  rowsBetween,
  SECURITY_EVENTS_SEALED,
  SECURITY_LOG_SUBJECT,
  SECURITY_SEAL_FORM,
  securityCountOfDay,
  securityDigestOfDay,
  type SecurityLog,
  securityLogAlarm,
  tallyFrom,
} from './infrastructure/event-seals.ts';
export {
  ALL_SEALED,
  legacyRowsAt,
  type LegacySealing,
  SEALING_STARTED,
  sealLegacyRows,
} from './infrastructure/legacy-seal.ts';
export type { SecurityEventsTables } from './infrastructure/tables.ts';
