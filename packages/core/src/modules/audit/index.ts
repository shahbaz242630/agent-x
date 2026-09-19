// The audit module (ADR-004, ADR-011 §3): every organisation's append-only,
// hash-chained audit trail, the only store for organisation audit events
// (ADR-014 §8). Any module may record to it; evidence reads it.
export {
  type ActorType,
  type AuditActor,
  type AuditDetails,
  type AuditDetailValue,
  type AuditEvent,
  AuditEventRefused,
  type AuditSubject,
} from './domain/event.ts';
export {
  AuditChainBroken,
  type AuditTrail,
  type AuditTransaction,
  createAuditTrail,
  type RecordedAuditEvent,
} from './infrastructure/audit-trail.ts';
export type { AuditTables } from './infrastructure/tables.ts';
