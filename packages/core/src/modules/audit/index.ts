// The audit module (ADR-004, ADR-011 §3): every organisation's append-only,
// hash-chained audit trail, the only store for organisation audit events
// (ADR-014 §8). Any module may record to it; evidence reads it. Its signed
// states are how every authority row is checked against the log (ADR-012 §2),
// and they come only through withSignedStates, which puts an organisation on
// its integrity hold for anything they find tampered with; holdOrganisation
// does the same for a chain the anchor check finds failing (B1d-3).
export {
  actorAsKept,
  actorProblems,
  type ActorType,
  type AuditActor,
  type AuditDetails,
  type AuditDetailValue,
  type AuditEvent,
  AuditEventRefused,
  type AuditSubject,
  type AuditSubjectKey,
} from './domain/event.ts';
export { actorEventsSince } from './infrastructure/actor-counts.ts';
export {
  lockChainHead,
  REPAIR_ROLE,
  repairRoleProblems,
  type RepairRow,
  writeOriginalRows,
} from './infrastructure/chain-repair.ts';
export {
  columnsOf,
  firePendingChecks,
  guardsOff,
  guardsOn,
  readRowsAlike,
  rowsAsStored,
  type StateAsRead,
  stateObjectIds,
  type StateRepairRow,
  STATES_READ_AT_ONCE,
  statesAsRead,
  StateWriteMissed,
  triggersOf,
  writeStateRow,
} from './infrastructure/state-repair.ts';
export {
  chainRowsAlone,
  chainRowsIn,
  type ChainRowsPage,
  holdsOperatorSignatures,
  operatorSigningStart,
  operatorSigningStartIn,
  type StoredColumns,
  type StoredRow,
  type StoredValues,
} from './infrastructure/chain-rows.ts';
export {
  type AuditTrail,
  type AuditTransaction,
  createAuditTrail,
  type HistoryToRead,
  type LatestSignedState,
  type LogEvent,
  type LogPageToRead,
  type ReadEvent,
  type RecordedAuditEvent,
  TooManyEventsAboutObject,
  TooManyEventsToRead,
} from './infrastructure/audit-trail.ts';
export {
  type CheckedTable,
  type ClearingStepUp,
  type HistoryBatch,
  type EventRead,
  type HistoryCheck,
  type HistoryCheckRecord,
  type HoldClearing,
  type OrganisationCheck,
  type HoldInvestigation,
  type HoldRecord,
  type InvestigationCheck,
  type InvestigationRecording,
  type LogPage,
  type RecordedState,
  type SignedChange,
  SignedStateFailed,
  type SignedStates,
  type SignedStatusChange,
  checkOf,
  judgeSignedRow,
  type StateCheck,
  type TamperSign,
  type VerifiedState,
} from './infrastructure/signed-states.ts';
export {
  INVESTIGATION_CONCLUSIONS,
  INVESTIGATION_REFERENCE_MAX,
  type InvestigationConclusion,
  isIncidentReference,
} from './domain/integrity-hold.ts';
export { holdHistoryDue } from './infrastructure/hold-history-due.ts';
export { eventsInRange, type LogRange } from './infrastructure/log-range.ts';
export {
  cancelledSince,
  movedOtherwiseSince,
  namedInDetails,
  newestDetail,
  withDetail,
} from './infrastructure/newest-detail.ts';
export type { AuditTables } from './infrastructure/tables.ts';
export { type PageAsked, type PageShown, type VerifiedPage, verifiedPage } from './infrastructure/verified-page.ts';
export {
  holdOrganisation,
  HOLDS_WAITING_EVERY_MS,
  markHoldsWith,
  pollHoldsWaiting,
  type SignedStatesServices,
  withSignedStates,
} from './infrastructure/with-signed-states.ts';
