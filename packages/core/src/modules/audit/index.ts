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
  subjectKeyProblems,
} from './domain/event.ts';
export { actorEventsSince } from './infrastructure/actor-counts.ts';
// What a chain that fails its check throws, for a module refusing a change on the trail's word (step-up, S206).
export { CHAIN_START, ChainBroken, type CheckedPoint, type StateDigest } from '@agentx/platform/audit-chain';
// How far past a horizon the digest forgets a fact (AT13d): an ending keeps a request's capacity past it (endings.ts).
export { FORGET_MARGIN_MS as DIGEST_FORGET_MARGIN_MS } from '@agentx/platform/audit-chain';
// The digest itself, for another module's tamper tests to hold its reads to one (sessions-tamper.db.test, AT13g).
export { createDigestLog } from '@agentx/platform/audit-chain';
// The witness log's refusal and maker (TR-1), for another module answering a `now` write unconfirmed (identity's
// sessions-all-ended) and its tests.
export { createWitnessLog, WitnessUnconfirmed } from '@agentx/platform/audit-chain';
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
  lockNotAvailable,
  readRowsAlike,
  rowsAsStored,
  shortLockWait,
  type StateAsRead,
  stateObjectIds,
  type StateRepairRow,
  STATES_READ_AT_ONCE,
  statesAsRead,
  StateWriteMissed,
  triggersOf,
  withRepairStates,
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
  readBelowWalk,
  type AuditTransaction,
  type CheckedEventFacts,
  createAuditTrail,
  eventsSinceChecked,
  type EventsSinceCheck,
  type HistoryToRead,
  type LatestSignedState,
  type LogEvent,
  type LogPageToRead,
  MOST_HISTORIES_READ,
  type ReadEvent,
  type RecordedAuditEvent,
  TooManyEventsAboutObject,
  TooManyEventsToRead,
  type WalkedEvent,
  type WalkedStep,
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
  type AlongsideChange,
  type ChangeToSend,
  type SignedChange,
  SignedStateFailed,
  type SignedStates,
  type SignedStatusChange,
  type AnchorKeptWithin,
  type AnchorWithin,
  checkOf,
  judgeSignedRow,
  type StateCheck,
  type TamperSign,
  type VerifiedState,
} from './infrastructure/signed-states.ts';
export { type SealedRowAsRead, sealedRowJudged, sealedRowRead } from './infrastructure/seal-at-the-door.ts';
export {
  INVESTIGATION_CONCLUSIONS,
  INVESTIGATION_REFERENCE_MAX,
  type InvestigationConclusion,
  isIncidentReference,
} from './domain/integrity-hold.ts';
export { holdHistoryDue } from './infrastructure/hold-history-due.ts';
export { keepHoldWaitingHere } from './infrastructure/holds-waiting.ts';
export { eventsInRange, type LogRange } from './infrastructure/log-range.ts';
export { type SignedRowRead, signedMoment } from './infrastructure/signed-moment.ts';
export {
  cancelledSince,
  movedOtherwiseSince,
  namedInDetails,
  newestDetail,
  withDetail,
} from './infrastructure/newest-detail.ts';
export type { AuditTables } from './infrastructure/tables.ts';
export { type PageAsked, type PageShown, type VerifiedPage, verifiedPage } from './infrastructure/verified-page.ts';
export { WITNESSED_SOON, witnessClassOf } from './infrastructure/witness-class.ts';
export {
  type ChainFrontier,
  createChainFrontier,
  type FrontierAnchors,
  type FrontierStart,
  judgeWitnessed,
  MOST_WALKED_WITHIN,
  type ReadAhead,
  type WalkedWithin,
  walkWithin,
  type WithinWalk,
  type WitnessJudgement,
} from './infrastructure/chain-frontier.ts';
export {
  chainWitness,
  headWrittenIn,
  noteCommitted,
  nowChainsOf,
  waitWitnessed,
  witnessedWrite,
  witnessWith,
  WriteCutBack,
  wroteTo,
} from './infrastructure/witnessing.ts';
export {
  checkStatesWith,
  holdOrganisation,
  HOLDS_WAITING_EVERY_MS,
  markHoldsWith,
  pollHoldsWaiting,
  type SignedStatesServices,
  statesDigest,
  withSignedStates,
} from './infrastructure/with-signed-states.ts';
