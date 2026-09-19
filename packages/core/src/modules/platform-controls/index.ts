// The platform-controls module (ADR-004): the platform's own audit chain,
// apart from every organisation's (ADR-014 §8). The platform hand-off pause
// and operator actions join it in later phases.
export { type PlatformActor, type PlatformEvent, PlatformEventRefused } from './domain/event.ts';
export {
  createPlatformChain,
  type PlatformChain,
  type PlatformTransaction,
  type RecordedPlatformEvent,
} from './infrastructure/platform-chain.ts';
export type { PlatformControlsTables } from './infrastructure/tables.ts';
