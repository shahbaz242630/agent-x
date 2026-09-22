// The audit module (ADR-004, ADR-011 §3): every organisation's append-only,
// hash-chained audit trail, the only store for organisation audit events
// (ADR-014 §8). Any module may record to it; evidence reads it. Its signed
// states are how every authority row is checked against the log (ADR-012 §2),
// and they come only through withSignedStates, which puts an organisation on
// its integrity hold for anything they find tampered with.
export {
  type ActorType,
  type AuditActor,
  type AuditDetails,
  type AuditDetailValue,
  type AuditEvent,
  AuditEventRefused,
  type AuditSubject,
  type AuditSubjectKey,
} from './domain/event.ts';
export {
  type AuditTrail,
  type AuditTransaction,
  createAuditTrail,
  type LatestSignedState,
  type RecordedAuditEvent,
  TooManyEventsAboutObject,
} from './infrastructure/audit-trail.ts';
export {
  type RecordedState,
  type SignedChange,
  SignedStateFailed,
  type SignedStates,
  type SignedStatusChange,
  type StateCheck,
  type TamperSign,
  type VerifiedState,
} from './infrastructure/signed-states.ts';
export type { AuditTables } from './infrastructure/tables.ts';
export { type SignedStatesServices, withSignedStates } from './infrastructure/with-signed-states.ts';
