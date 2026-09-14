/**
 * The one registry of reason codes (ADR-011 §8, SEC-EVD-06). A reason code
 * says why a request was refused, held or sent for approval. It is recorded
 * with each decision and state change, and returned to API clients.
 *
 * - Code that records a reason types it as `ReasonCode`, so an unregistered
 *   code fails the type check, and lint refuses `as ReasonCode`.
 * - Each code has a description, which is its public documentation.
 * - Codes are stable: never rename or reuse one, because clients and past
 *   evidence depend on it. Add new codes in alphabetical order.
 */
export const REASON_CODES = {
  AGGREGATE_THRESHOLD:
    "Together with the same supplier's other open or paid requests in the aggregation window, this request crosses the approval threshold, so a person must approve it.",
  DUPLICATE_ORDER_REFERENCE:
    'An earlier request for the same supplier and order reference is still open, has an unknown outcome or was paid, so this one is refused.',
  ORG_FROZEN:
    'The organisation is frozen, so no new request is accepted. This refusal is temporary: the same idempotency key can be used again once the freeze is lifted.',
  SUPPLIER_CHANGED:
    "The supplier's payment details changed after the request was decided, so it is refused before hand-off.",
} as const satisfies Readonly<Record<string, string>>;

export type ReasonCode = keyof typeof REASON_CODES;

/**
 * True only for a registered code. Use it on a code read back from the
 * database or another outside source, where the compiler can't vouch for it
 * and `as ReasonCode` is refused by lint. Inherited names such as `toString`
 * are not codes.
 */
export function isReasonCode(value: string): value is ReasonCode {
  return Object.hasOwn(REASON_CODES, value);
}
