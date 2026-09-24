// The security-events module (ADR-004, ADR-005 §6, ADR-011 §7): failed
// sign-ins and rate-limit hits with the client's IP address, in a global
// table (0012), kept in-country for the retention period the config names.
// B2-5b gathers them from the API; B2-5a holds the table, the writes and the
// retention sweep.
export {
  createSecurityEvents,
  LEAST_RETENTION_DAYS,
  MOST_EVENTS_A_BATCH,
  SECURITY_EVENT_KINDS,
  type SecurityEvent,
  type SecurityEventKind,
  type SecurityEvents,
} from './infrastructure/security-events.ts';
export type { SecurityEventsTables } from './infrastructure/tables.ts';
