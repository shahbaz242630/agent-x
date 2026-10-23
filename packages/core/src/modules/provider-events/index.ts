// The provider-events module (ADR-004, ADR-007 §12–13; Phase 4 E1b): the
// partner's messages as Agent X keeps them, in the inbox (one row a message,
// routed to its organisation) and, refused, as security evidence. The
// adapter (providers) checks a message's signature; this keeps what it named.
export {
  createProviderEvents,
  MOST_KEPT_AN_HOUR,
  MOST_KEPT_AN_HOUR_IN_ALL,
  MOST_TRIES,
  MOST_KEPT_BYTES,
  type Nudge,
  type ProviderEvents,
} from './infrastructure/provider-events.ts';
export type { ProviderEventsTables } from './infrastructure/tables.ts';
