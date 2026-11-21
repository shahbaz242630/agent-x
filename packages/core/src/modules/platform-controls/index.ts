// The platform-controls module (ADR-004): the platform's own audit chain,
// apart from every organisation's (ADR-014 §8), with the operator's actions
// on it; and the platform hand-off pause (Phase 4 B1, SEC-OPS-03), one switch
// for every organisation's hand-offs to the bank, each move a signed event on
// that chain, its row believed only as its newest event says.
export { type PlatformActor, type PlatformEvent, PlatformEventRefused } from './domain/event.ts';
export {
  changeHandoffPause,
  HANDOFF_PAUSED,
  HANDOFF_RESUMED,
  type HandoffPause,
  type HandoffPauseChange,
  type HandoffPauseChanged,
  type HandoffPauseLock,
  handoffPauseOf,
  PAUSE_ACTOR,
  pauseSubjectOf,
} from './infrastructure/handoff-pause.ts';
export { jobsBeating, releaseJobLease, takeJobLease } from './infrastructure/job-lease.ts';
export { nextMachineId } from './infrastructure/machine-ids.ts';
export {
  checkPlatformStretch,
  type CheckedPlatformEvent,
  createPlatformChain,
  HEAD_WAIT_SECONDS,
  type PlatformChain,
  platformCutBack,
  platformEventSealed,
  type PlatformHeadOfRow,
  platformHeadRead,
  type PlatformSubjectOf,
  platformEventsSigned,
  type PlatformTransaction,
  type PlatformPoint,
  type RecordedPlatformEvent,
  type StretchCheck,
  type StretchStart,
} from './infrastructure/platform-chain.ts';
export {
  latestPlatformTime,
  latestPlatformTimeOf,
  latestPlatformTimeOfRead,
  latestPlatformSeqRead,
  platformEventWith,
  platformEventWithRead,
  type PlatformEventsMatching,
} from './infrastructure/platform-events.ts';
export type { PlatformControlsTables } from './infrastructure/tables.ts';
