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
} from './infrastructure/handoff-pause.ts';
export {
  createPlatformChain,
  HEAD_WAIT_SECONDS,
  type PlatformChain,
  type PlatformTransaction,
  type RecordedPlatformEvent,
} from './infrastructure/platform-chain.ts';
export {
  latestPlatformTime,
  latestPlatformTimeOf,
  platformEventWith,
  type PlatformEventsMatching,
} from './infrastructure/platform-events.ts';
export type { PlatformControlsTables } from './infrastructure/tables.ts';
