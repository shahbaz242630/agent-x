// The partner's messages, as the adapter hands them on (Phase 4 E1b; ADR-007
// §12–13; rail map §1.8; SEC-PTR-01, -03, -06): its signature checked over
// the raw body before anything is read from it, then normalised to what the
// message names. A message is a nudge, never the payment's state: the bank's
// status query decides that (E1a, SEC-PTR-02), so nothing here carries a status.
//
// The rail's messages carry no event ID and name the consent, the payment
// only sometimes (rail map §1.8); the real partner's shape waits for its
// answers to EVT-1 and EVT-2 (Phase 5). Each adapter maps its own onto these.

/** What a verified message names: one payment, by our instruction ID; or a consent alone, every payment under it. */
export type EventReference =
  | { readonly kind: 'instruction'; readonly instructionId: string }
  | { readonly kind: 'consent'; readonly consentId: string };

/** A message whose signature held, normalised. */
export interface PartnerEvent {
  /** The partner it came from, as the inbox keys it (`fake` for the fake). */
  readonly partner: string;
  /** Its event ID where it has one; otherwise the SHA-256 of its verified body, in hex: a replay has the same (SEC-PTR-03). */
  readonly dedupeKey: string;
  /** What happened, in the partner's own words (the rail's `EventType`). */
  readonly eventType: string;
  readonly reference: EventReference;
}

/**
 * Why a message is refused: its signature didn't hold (`signature`), the
 * time it signed is outside the window (`stale`, SEC-PTR-03: only where it
 * signs one), or its body, signed, isn't a message we can read (`malformed`).
 */
export type EventRefusal = 'signature' | 'stale' | 'malformed';

export type EventCheck =
  | { readonly kind: 'verified'; readonly event: PartnerEvent }
  | { readonly kind: 'refused'; readonly reason: EventRefusal };

/** A message's headers, by their lower-case names, as Node gives them. */
export type EventHeaders = Readonly<Record<string, string | readonly string[] | undefined>>;

/** The most a message's body may be: anything longer is refused before it is read (SEC-PTR-06). */
export const MOST_EVENT_BYTES = 64 * 1024;
